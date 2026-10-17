use serde::{Deserialize, Serialize};

/// SAE J1708 Message Identification Characters (MIDs)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum J1708Mid {
    Engine1,                 // 128
    Transmission,            // 130
    BrakesAbs,               // 136
    InstrumentCluster,       // 140
    VehicleManagementSystem, // 142
    Engine2,                 // 175
    VehicleSecurity,         // 187
    CabClimateControl,       // 188
    Other(u8),
}

impl From<u8> for J1708Mid {
    fn from(val: u8) -> Self {
        match val {
            128 => J1708Mid::Engine1,
            130 => J1708Mid::Transmission,
            136 => J1708Mid::BrakesAbs,
            140 => J1708Mid::InstrumentCluster,
            142 => J1708Mid::VehicleManagementSystem,
            175 => J1708Mid::Engine2,
            187 => J1708Mid::VehicleSecurity,
            188 => J1708Mid::CabClimateControl,
            other => J1708Mid::Other(other),
        }
    }
}

pub fn j1708_mid_name(mid: u8) -> &'static str {
    match mid {
        128 => "Engine #1",
        130 => "Transmission",
        136 => "Brakes / ABS",
        140 => "Instrument Cluster",
        142 => "Vehicle Management System",
        175 => "Engine #2",
        187 => "Vehicle Security",
        188 => "Cab Climate Control",
        _ => "Specialized Heavy-Duty Controller",
    }
}

/// Decoded SAE J1587 Parameter Identification (PID) signals
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum J1587Parameter {
    /// PID 84: Road Speed (0.5 mph/bit -> converted to km/h)
    RoadSpeedKmh(f32),
    /// PID 91: Percent Accelerator Pedal Position (0.4 %/bit)
    AcceleratorPedalPercent(f32),
    /// PID 92: Percent Engine Load (0.5 %/bit)
    PercentEngineLoad(f32),
    /// PID 100: Engine Oil Pressure (0.5 psi/bit -> converted to kPa)
    EngineOilPressureKpa(f32),
    /// PID 102: Boost Pressure (0.125 psi/bit -> converted to kPa)
    BoostPressureKpa(f32),
    /// PID 110: Engine Coolant Temperature (1 deg F/bit -> converted to deg C)
    CoolantTemperatureDegC(f32),
    /// PID 158: Battery Potential Switched (0.05 V/bit)
    BatteryVoltageSwitched(f32),
    /// PID 168: Battery Potential Unswitched (0.05 V/bit)
    BatteryVoltageUnswitched(f32),
    /// PID 190: Engine Speed (0.25 rpm/bit)
    EngineSpeedRpm(f32),
    /// PID 245: Total Vehicle Distance (0.1 miles/bit -> converted to km)
    TotalDistanceKm(f64),
    /// PID 247: Total Engine Hours (0.05 hours/bit)
    TotalEngineHours(f64),
    /// Generic/Raw parameter
    RawParameter { pid: u8, data: Vec<u8> },
}

/// Decoded SAE J1708/J1587 Message
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct J1708Message {
    pub mid: u8,
    pub mid_name: String,
    pub parameters: Vec<J1587Parameter>,
    pub checksum_valid: bool,
}

/// Calculate standard SAE J1708 checksum (two's complement sum mod 256)
pub fn calculate_j1708_checksum(data: &[u8]) -> u8 {
    let sum: u32 = data.iter().map(|&b| b as u32).sum();
    ((!sum).wrapping_add(1) & 0xFF) as u8
}

/// Verify if the entire frame (including trailing checksum) satisfies the J1708 zero-sum rule
pub fn verify_j1708_checksum(frame: &[u8]) -> bool {
    if frame.is_empty() {
        return false;
    }
    let sum: u32 = frame.iter().map(|&b| b as u32).sum();
    sum.is_multiple_of(256)
}

/// Dissect a raw SAE J1708 serial frame (MID + J1587 PIDs + Checksum)
pub fn dissect_j1708(frame: &[u8]) -> Option<J1708Message> {
    if frame.len() < 2 {
        return None;
    }

    let checksum_valid = verify_j1708_checksum(frame);
    let mid = frame[0];
    let mid_name = j1708_mid_name(mid).to_string();

    // Payload is between MID (index 0) and Checksum (last index)
    let payload = &frame[1..frame.len() - 1];
    let mut parameters = Vec::new();
    let mut i = 0;

    while i < payload.len() {
        let pid = payload[i];
        i += 1;

        match pid {
            // PID 0..=127: Single-byte parameter
            84 if i < payload.len() => {
                let raw = payload[i];
                i += 1;
                // 0.5 mph per bit -> 0.804672 km/h per bit
                parameters.push(J1587Parameter::RoadSpeedKmh((raw as f32) * 0.804672));
            }
            91 if i < payload.len() => {
                let raw = payload[i];
                i += 1;
                parameters.push(J1587Parameter::AcceleratorPedalPercent((raw as f32) * 0.4));
            }
            92 if i < payload.len() => {
                let raw = payload[i];
                i += 1;
                parameters.push(J1587Parameter::PercentEngineLoad((raw as f32) * 0.5));
            }
            100 if i < payload.len() => {
                let raw = payload[i];
                i += 1;
                // 0.5 psi per bit -> 3.44738 kPa per bit
                parameters.push(J1587Parameter::EngineOilPressureKpa((raw as f32) * 3.44738));
            }
            102 if i < payload.len() => {
                let raw = payload[i];
                i += 1;
                // 0.125 psi per bit -> 0.861845 kPa per bit
                parameters.push(J1587Parameter::BoostPressureKpa((raw as f32) * 0.861845));
            }
            110 if i < payload.len() => {
                let raw = payload[i];
                i += 1;
                // 1 deg F per bit -> converted to deg C: (F - 32) * 5/9
                let deg_f = raw as f32;
                parameters.push(J1587Parameter::CoolantTemperatureDegC(
                    (deg_f - 32.0) * 5.0 / 9.0,
                ));
            }
            0..=127 if i < payload.len() => {
                let data = vec![payload[i]];
                i += 1;
                parameters.push(J1587Parameter::RawParameter { pid, data });
            }

            // PID 128..=191: Two-byte parameter
            158 if i + 1 < payload.len() => {
                let raw = u16::from_le_bytes([payload[i], payload[i + 1]]);
                i += 2;
                parameters.push(J1587Parameter::BatteryVoltageSwitched((raw as f32) * 0.05));
            }
            168 if i + 1 < payload.len() => {
                let raw = u16::from_le_bytes([payload[i], payload[i + 1]]);
                i += 2;
                parameters.push(J1587Parameter::BatteryVoltageUnswitched(
                    (raw as f32) * 0.05,
                ));
            }
            190 if i + 1 < payload.len() => {
                let raw = u16::from_le_bytes([payload[i], payload[i + 1]]);
                i += 2;
                parameters.push(J1587Parameter::EngineSpeedRpm((raw as f32) * 0.25));
            }
            128..=191 if i + 1 < payload.len() => {
                let data = vec![payload[i], payload[i + 1]];
                i += 2;
                parameters.push(J1587Parameter::RawParameter { pid, data });
            }

            // PID 192..=253: Multi-byte or variable parameter
            245 if i + 3 < payload.len() => {
                let raw = u32::from_le_bytes([
                    payload[i],
                    payload[i + 1],
                    payload[i + 2],
                    payload[i + 3],
                ]);
                i += 4;
                // 0.1 miles per bit -> 0.160934 km per bit
                parameters.push(J1587Parameter::TotalDistanceKm((raw as f64) * 0.160934));
            }
            247 if i + 3 < payload.len() => {
                let raw = u32::from_le_bytes([
                    payload[i],
                    payload[i + 1],
                    payload[i + 2],
                    payload[i + 3],
                ]);
                i += 4;
                parameters.push(J1587Parameter::TotalEngineHours((raw as f64) * 0.05));
            }
            _ => {
                // Unknown PID or truncated: collect remaining bytes and finish
                let remaining = payload[i..].to_vec();
                i = payload.len();
                parameters.push(J1587Parameter::RawParameter {
                    pid,
                    data: remaining,
                });
            }
        }
    }

    Some(J1708Message {
        mid,
        mid_name,
        parameters,
        checksum_valid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_j1708_checksum_calculation_and_verification() {
        // Sample frame: MID 128 (Engine), PID 190 (Engine Speed = 1600 rpm -> 6400 raw = 0x1900)
        // Payload: [128, 190, 0x00, 0x19]
        // Sum = 128 + 190 + 0 + 25 = 343. 343 % 256 = 87. Checksum = 256 - 87 = 169 (0xA9).
        let payload = [128, 190, 0x00, 0x19];
        let cs = calculate_j1708_checksum(&payload);
        assert_eq!(cs, 169);

        let mut complete_frame = payload.to_vec();
        complete_frame.push(cs);
        assert!(verify_j1708_checksum(&complete_frame));
    }

    #[test]
    fn test_j1708_dissection_engine_parameters() {
        // Frame: MID 128 (Engine),
        // PID 190 (Engine Speed = 1200 rpm -> 4800 raw = 0x12C0 -> [0xC0, 0x12]),
        // PID 100 (Oil Pressure = 50 psi -> raw 100 = 0x64),
        // PID 110 (Coolant Temp = 180 deg F -> raw 180 = 0xB4 -> (180-32)*5/9 = 82.22 deg C)
        let mut frame = vec![128, 190, 0xC0, 0x12, 100, 0x64, 110, 0xB4];
        let cs = calculate_j1708_checksum(&frame);
        frame.push(cs);

        let msg = dissect_j1708(&frame).expect("Dissect valid J1708 frame");
        assert_eq!(msg.mid, 128);
        assert_eq!(msg.mid_name, "Engine #1");
        assert!(msg.checksum_valid);
        assert_eq!(msg.parameters.len(), 3);

        assert_eq!(msg.parameters[0], J1587Parameter::EngineSpeedRpm(1200.0));
        match msg.parameters[1] {
            J1587Parameter::EngineOilPressureKpa(press) => {
                assert!((press - 344.738).abs() < 0.1);
            }
            _ => panic!("Expected Oil Pressure"),
        }
        match msg.parameters[2] {
            J1587Parameter::CoolantTemperatureDegC(temp) => {
                assert!((temp - 82.22).abs() < 0.1);
            }
            _ => panic!("Expected Coolant Temp"),
        }
    }

    proptest::proptest! {
        #[test]
        fn fuzz_j1708_dissector_never_panics(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = dissect_j1708(&data);
            let _ = verify_j1708_checksum(&data);
            let _ = calculate_j1708_checksum(&data);
        }
    }
}
