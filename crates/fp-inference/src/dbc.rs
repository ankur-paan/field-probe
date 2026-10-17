//! Vector CANdb++ (.dbc) Signal Importer and Database
//!
//! Parses standard Vector .dbc database files, extracting message definitions (BO_),
//! signal layouts (SG_), bit lengths, endianness, sign extensions, and linear scaling
//! factors for automated decoding of raw CAN frames into engineering units.

use crate::signals::{SignalByteOrder, SignalDefinition};
use fp_core::CanFrame;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Parsed message from a Vector DBC database
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DbcMessage {
    /// Raw message identifier from the DBC (bit 31 may be set for extended frames)
    pub raw_id: u32,
    /// Physical CAN arbitration identifier (standard 11-bit or extended 29-bit)
    pub can_id: u32,
    /// Indicates whether the message uses extended 29-bit CAN identifiers
    pub is_extended: bool,
    /// Symbolic message name (e.g., "EngineStatus", "EEC1")
    pub name: String,
    /// Expected data length code
    pub dlc: u8,
    /// Sending ECU node name
    pub transmitter: String,
    /// Extracted signal definitions mapped to this frame
    pub signals: Vec<SignalDefinition>,
}

/// Parsed Vector CANdb++ database
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DbcDatabase {
    /// Optional version string from DBC header
    pub version: String,
    /// Messages indexed by CAN arbitration ID
    pub messages: HashMap<u32, DbcMessage>,
}

impl DbcDatabase {
    /// Create a new empty DBC database
    pub fn new() -> Self {
        Self {
            version: String::new(),
            messages: HashMap::new(),
        }
    }

    /// Parse a Vector DBC text file content into a structured `DbcDatabase`
    pub fn parse(content: &str) -> Result<Self, String> {
        let mut db = DbcDatabase::new();
        let mut current_msg: Option<DbcMessage> = None;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("VERSION") {
                let ver = rest.trim().trim_matches('"').to_string();
                db.version = ver;
            } else if trimmed.starts_with("BO_ ") {
                // Save previously parsed message
                if let Some(msg) = current_msg.take() {
                    db.messages.insert(msg.can_id, msg);
                }

                // Format: BO_ <ID> <Name>: <DLC> <Transmitter>
                // Example: BO_ 217056256 EEC1: 8 Vector__XXX
                // Example: BO_ 256 EngineData : 8 ECU1
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() < 5 {
                    return Err(format!("Malformed BO_ line: '{}'", trimmed));
                }

                let raw_id = parts[1]
                    .parse::<u32>()
                    .map_err(|e| format!("Invalid CAN ID in BO_: {} ({})", parts[1], e))?;

                // Extended CAN IDs in DBC format have bit 31 set: (1 << 31) | can_id
                let is_extended = (raw_id & 0x8000_0000) != 0 || raw_id > 0x7FF;
                let can_id = if (raw_id & 0x8000_0000) != 0 {
                    raw_id & 0x1FFFFFFF
                } else {
                    raw_id
                };

                let name = parts[2].trim_end_matches(':').to_string();
                let dlc_idx = if parts[2].ends_with(':') { 3 } else { 4 };
                if dlc_idx >= parts.len() {
                    return Err(format!("Missing DLC in BO_ line: '{}'", trimmed));
                }

                let dlc = parts[dlc_idx]
                    .parse::<u8>()
                    .map_err(|e| format!("Invalid DLC in BO_: {} ({})", parts[dlc_idx], e))?;

                let transmitter = parts.get(dlc_idx + 1).unwrap_or(&"Vector__XXX").to_string();

                current_msg = Some(DbcMessage {
                    raw_id,
                    can_id,
                    is_extended,
                    name,
                    dlc,
                    transmitter,
                    signals: Vec::new(),
                });
            } else if trimmed.starts_with("SG_ ") {
                // Format: SG_ <Name> [m|M<val>] : <StartBit>|<Length>@<ByteOrder><Sign> (<Factor>,<Offset>) [<Min>|<Max>] "<Unit>" <Receivers>
                // Example: SG_ EngineSpeed : 0|16@1+ (0.125,0) [0|8031.875] "rpm" ECU
                let msg = current_msg
                    .as_mut()
                    .ok_or_else(|| format!("SG_ line without preceding BO_: '{}'", trimmed))?;

                if let Some(signal) = parse_dbc_signal_line(trimmed) {
                    msg.signals.push(signal);
                }
            }
        }

        // Insert last pending message
        if let Some(msg) = current_msg {
            db.messages.insert(msg.can_id, msg);
        }

        Ok(db)
    }

    /// Lookup a message by CAN arbitration identifier
    pub fn find_message(&self, can_id: u32) -> Option<&DbcMessage> {
        self.messages.get(&can_id)
    }

    /// Decode all signals for an incoming `CanFrame` according to database definitions
    pub fn extract_signals(&self, frame: &CanFrame) -> Vec<(String, f64)> {
        let mut results = Vec::new();
        let frame_id = frame.id.as_raw();

        if let Some(msg) = self.find_message(frame_id) {
            for sig in &msg.signals {
                if let Some(val) = sig.unpack(&frame.data) {
                    results.push((sig.name.clone(), val));
                }
            }
        }

        results
    }
}

/// Helper function to parse a single `SG_` line from a DBC file
fn parse_dbc_signal_line(line: &str) -> Option<SignalDefinition> {
    // Strip leading "SG_ "
    let line = line.strip_prefix("SG_ ")?.trim();

    // Find colon separating signal name (and optional multiplexer) from definition
    let colon_pos = line.find(':')?;
    let header_part = line[..colon_pos].trim();
    let body_part = line[colon_pos + 1..].trim();

    // Header part has: <SignalName> [m<val>|M]
    let sig_name = header_part.split_whitespace().next()?.to_string();

    // Body part: <StartBit>|<Length>@<ByteOrder><Sign> (<Factor>,<Offset>) [<Min>|<Max>] "<Unit>" <Receivers>
    // 1. Bit spec: <StartBit>|<Length>@<ByteOrder><Sign>
    let at_pos = body_part.find('@')?;
    let bit_spec = body_part[..at_pos].trim();
    let pipe_pos = bit_spec.find('|')?;
    let start_bit: usize = bit_spec[..pipe_pos].trim().parse().ok()?;
    let bit_length: usize = bit_spec[pipe_pos + 1..].trim().parse().ok()?;

    // Byte order and sign: e.g. "1+" or "0-"
    let rest_after_at = &body_part[at_pos + 1..].trim_start();
    let byte_order_char = rest_after_at.chars().next()?;
    let byte_order = match byte_order_char {
        '1' => SignalByteOrder::LittleEndian,
        '0' => SignalByteOrder::BigEndian,
        _ => return None,
    };

    let sign_char = rest_after_at.chars().nth(1)?;
    let is_signed = match sign_char {
        '-' => true,
        '+' => false,
        _ => false,
    };

    // 2. Factor and offset: (<Factor>,<Offset>)
    let open_paren = body_part.find('(')?;
    let close_paren = body_part.find(')')?;
    if close_paren <= open_paren {
        return None;
    }
    let factor_offset_str = &body_part[open_paren + 1..close_paren];
    let comma_pos = factor_offset_str.find(',')?;
    let scale: f64 = factor_offset_str[..comma_pos].trim().parse().ok()?;
    let offset: f64 = factor_offset_str[comma_pos + 1..].trim().parse().ok()?;

    // 3. Unit string: "<Unit>"
    let unit = if let (Some(first_quote), Some(second_quote)) =
        (body_part.find('"'), body_part.rfind('"'))
    {
        if second_quote > first_quote {
            body_part[first_quote + 1..second_quote].to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    Some(SignalDefinition::new(
        sig_name, start_bit, bit_length, byte_order, is_signed, scale, offset, unit,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::export_dbc;
    use fp_core::CanFrame;

    #[test]
    fn test_parse_standard_and_extended_dbc() {
        let dbc_content = r#"
VERSION ""

NS_ :

BS_:

BU_: ECU_Engine ECU_Gateway

BO_ 256 EngineData: 8 ECU_Engine
 SG_ EngineRPM : 0|16@1+ (0.125,0) [0|8000] "rpm" ECU_Gateway
 SG_ CoolantTemp : 16|8@1- (1,-40) [-40|150] "degC" ECU_Gateway

BO_ 217056256 EEC1: 8 ECU_Engine
 SG_ DriverDemandTorque : 0|8@1- (1,-125) [-125|125] "%" ECU_Gateway
 SG_ ActualEngineTorque : 8|8@1- (1,-125) [-125|125] "%" ECU_Gateway
 SG_ EngineSpeed : 24|16@1+ (0.125,0) [0|8031.875] "rpm" ECU_Gateway
"#;

        let db = DbcDatabase::parse(dbc_content).expect("Valid DBC parse");
        assert_eq!(db.messages.len(), 2);

        // Standard message 0x100 = 256
        let engine_msg = db.find_message(256).expect("Found 256");
        assert_eq!(engine_msg.name, "EngineData");
        assert_eq!(engine_msg.dlc, 8);
        assert!(!engine_msg.is_extended);
        assert_eq!(engine_msg.signals.len(), 2);
        assert_eq!(engine_msg.signals[0].name, "EngineRPM");
        assert_eq!(engine_msg.signals[0].scale, 0.125);
        assert_eq!(engine_msg.signals[1].name, "CoolantTemp");
        assert_eq!(engine_msg.signals[1].offset, -40.0);

        // Extended message: 217056256 = 0xCF00400 | 0x80000000
        let eec1_msg = db.find_message(0xCF00400).expect("Found EEC1");
        assert_eq!(eec1_msg.name, "EEC1");
        assert!(eec1_msg.is_extended);
        assert_eq!(eec1_msg.signals.len(), 3);
        assert_eq!(eec1_msg.signals[2].name, "EngineSpeed");
    }

    #[test]
    fn test_extract_signals_from_can_frame() {
        let dbc_content = r#"
BO_ 256 EngineData: 8 ECU
 SG_ Speed : 0|16@1+ (0.01,0) [0|300] "km/h" Gateway
 SG_ Status : 16|8@1+ (1,0) [0|255] "" Gateway
"#;

        let db = DbcDatabase::parse(dbc_content).expect("DBC parse");

        // Payload: Speed = 10000 (0x2710) => 100.0 km/h, Status = 0x05
        let frame = CanFrame::new_standard(256, &[0x10, 0x27, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00]);

        let signals = db.extract_signals(&frame);
        assert_eq!(signals.len(), 2);
        assert_eq!(signals[0].0, "Speed");
        assert!((signals[0].1 - 100.0).abs() < 0.001);
        assert_eq!(signals[1].0, "Status");
        assert_eq!(signals[1].1, 5.0);
    }

    #[test]
    fn test_export_and_reimport_roundtrip() {
        let signals = vec![
            SignalDefinition::new(
                "Torque",
                0,
                16,
                SignalByteOrder::LittleEndian,
                true,
                0.5,
                -500.0,
                "Nm",
            ),
            SignalDefinition::new(
                "RPM",
                16,
                16,
                SignalByteOrder::LittleEndian,
                false,
                0.25,
                0.0,
                "rpm",
            ),
        ];

        let exported = export_dbc(&[(0x200, "MotorTelemetry", 8, signals)]);
        let parsed_db = DbcDatabase::parse(&exported).expect("Parse exported DBC");

        let msg = parsed_db.find_message(0x200).expect("Found 0x200 message");
        assert_eq!(msg.name, "MotorTelemetry");
        assert_eq!(msg.signals.len(), 2);
        assert_eq!(msg.signals[0].name, "Torque");
        assert_eq!(msg.signals[0].scale, 0.5);
        assert_eq!(msg.signals[0].offset, -500.0);
        assert_eq!(msg.signals[0].unit, "Nm");
        assert_eq!(msg.signals[1].name, "RPM");
        assert_eq!(msg.signals[1].scale, 0.25);
    }
}
