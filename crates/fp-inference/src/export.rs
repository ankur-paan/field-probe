//! Multi-format SCADA, Network, and Telemetry Exporters
//!
//! Generates Vector DBC (.dbc), Wireshark PCAP-NG (.pcapng), Telegraf Influx Line Protocol,
//! and Node-RED SCADA gateway configuration flows.

use crate::catalog::RegisterCatalog;
use crate::signals::{SignalByteOrder, SignalDefinition};
use fp_core::{CanId, RawBusEvent, RawFrame};
use serde_json::json;

/// Export CAN signals and message definitions to standard Vector DBC format
pub fn export_dbc(
    messages: &[(u32, &str, usize, Vec<SignalDefinition>)],
) -> String {
    let mut out = String::new();
    out.push_str("VERSION \"\"\n\n");
    out.push_str("NS_ :\n\n");
    out.push_str("BS_:\n\n");
    out.push_str("BU_: FieldProbe_Master ECU_Node\n\n");

    for (can_id, msg_name, dlc, signals) in messages {
        out.push_str(&format!(
            "BO_ {} {}: {} FieldProbe_Master\n",
            can_id, msg_name, dlc
        ));

        for sig in signals {
            let byte_order_char = match sig.byte_order {
                SignalByteOrder::LittleEndian => '1',
                SignalByteOrder::BigEndian => '0',
            };
            let sign_char = if sig.is_signed { '-' } else { '+' };

            // Calculate theoretical min/max
            let max_raw = (1u64.checked_shl(sig.bit_length as u32).unwrap_or(u64::MAX)).saturating_sub(1);
            let min_val = sig.offset;
            let max_val = (max_raw as f64) * sig.scale + sig.offset;

            out.push_str(&format!(
                " SG_ {} : {}|{}@{}{} ({},{}) [{}|{}] \"{}\" ECU_Node\n",
                sig.name,
                sig.start_bit,
                sig.bit_length,
                byte_order_char,
                sign_char,
                sig.scale,
                sig.offset,
                min_val,
                max_val,
                sig.unit
            ));
        }
        out.push('\n');
    }

    out
}

/// Export captured bus events into standard Wireshark PCAP-NG binary format
pub fn export_pcapng(events: &[RawBusEvent]) -> Vec<u8> {
    let mut buf = Vec::new();

    // 1. Section Header Block (SHB)
    // Type = 0x0A0D0D0A, Length = 28, Magic = 0x1A2B3C4D, Major = 1, Minor = 0, Section Len = -1
    let shb_len: u32 = 28;
    buf.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
    buf.extend_from_slice(&shb_len.to_le_bytes());
    buf.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes()); // Major
    buf.extend_from_slice(&0u16.to_le_bytes()); // Minor
    buf.extend_from_slice(&0xFFFFFFFFFFFFFFFFu64.to_le_bytes()); // Section length undefined
    buf.extend_from_slice(&shb_len.to_le_bytes());

    // 2. Interface Description Block 0 (SocketCAN)
    // Type = 0x00000001, Length = 20, LinkType = 227 (LINKTYPE_CAN_SOCKETCAN), SnapLen = 65535
    let idb_len: u32 = 20;
    buf.extend_from_slice(&0x00000001u32.to_le_bytes());
    buf.extend_from_slice(&idb_len.to_le_bytes());
    buf.extend_from_slice(&227u16.to_le_bytes()); // LINKTYPE_CAN_SOCKETCAN
    buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    buf.extend_from_slice(&65535u32.to_le_bytes()); // SnapLen
    buf.extend_from_slice(&idb_len.to_le_bytes());

    // Interface Description Block 1 (Serial / RTAC / User0)
    // Type = 0x00000001, Length = 20, LinkType = 250 (LINKTYPE_RTAC_SERIAL), SnapLen = 65535
    buf.extend_from_slice(&0x00000001u32.to_le_bytes());
    buf.extend_from_slice(&idb_len.to_le_bytes());
    buf.extend_from_slice(&250u16.to_le_bytes()); // LINKTYPE_RTAC_SERIAL
    buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    buf.extend_from_slice(&65535u32.to_le_bytes()); // SnapLen
    buf.extend_from_slice(&idb_len.to_le_bytes());

    // 3. Enhanced Packet Blocks (EPB)
    for ev in events {
        let (raw_bytes, interface_id) = match &ev.payload {
            RawFrame::Can(c) => {
                let mut id_val = match c.id {
                    CanId::Standard(s) => s as u32,
                    CanId::Extended(e) => (e & 0x1FFFFFFF) | 0x80000000,
                };
                if c.is_rtr {
                    id_val |= 0x40000000;
                }
                if c.is_error {
                    id_val |= 0x20000000;
                }
                let mut packet = Vec::with_capacity(16);
                packet.extend_from_slice(&id_val.to_be_bytes());
                packet.push(c.dlc);
                packet.push(0); // padding
                packet.push(0); // reserved
                packet.push(0); // reserved
                packet.extend_from_slice(&c.data);
                (packet, 0u32)
            }
            RawFrame::Serial(s) => (s.data.to_vec(), 1u32),
        };

        let cap_len = raw_bytes.len() as u32;
        let pad_len = (4 - (cap_len % 4)) % 4;
        let epb_len: u32 = 32 + cap_len + pad_len;

        buf.extend_from_slice(&0x00000006u32.to_le_bytes()); // Block Type EPB
        buf.extend_from_slice(&epb_len.to_le_bytes());
        buf.extend_from_slice(&interface_id.to_le_bytes()); // Interface ID: 0 for CAN, 1 for Serial

        // Timestamp in microseconds
        let ts_high = (ev.timestamp_us >> 32) as u32;
        let ts_low = (ev.timestamp_us & 0xFFFFFFFF) as u32;
        buf.extend_from_slice(&ts_high.to_le_bytes());
        buf.extend_from_slice(&ts_low.to_le_bytes());

        buf.extend_from_slice(&cap_len.to_le_bytes());
        buf.extend_from_slice(&cap_len.to_le_bytes());
        buf.extend_from_slice(&raw_bytes);

        buf.resize(buf.len() + pad_len as usize, 0);

        buf.extend_from_slice(&epb_len.to_le_bytes());
    }

    buf
}

/// Export RegisterCatalog to Telegraf / InfluxDB line protocol format
pub fn export_telegraf(catalog: &RegisterCatalog) -> String {
    let mut out = String::new();
    let mut sorted_entries = catalog.entries.values().collect::<Vec<_>>();
    sorted_entries.sort_by(|a, b| {
        a.node_or_slave
            .cmp(&b.node_or_slave)
            .then_with(|| a.address.cmp(&b.address))
    });

    for entry in sorted_entries {
        let clean_node = entry.node_or_slave.replace(' ', "_");
        let clean_type = entry.plausible_type.replace(' ', "_");

        out.push_str(&format!(
            "industrial_register,node={},type={} address={}i,raw_hex=\"{}\",frequency_hz={:.2},jitter_ms={:.2},confidence={:.2}\n",
            clean_node, clean_type, entry.address, entry.raw_hex, entry.polling_frequency_hz, entry.jitter_ms, entry.confidence
        ));
    }

    out
}

/// Export RegisterCatalog to pretty-printed JSON
pub fn export_json(catalog: &RegisterCatalog) -> String {
    serde_json::to_string_pretty(catalog).unwrap_or_else(|_| "{}".to_string())
}

/// Export RegisterCatalog to a ready-to-import Node-RED SCADA gateway flow
pub fn export_nodered_flow(catalog: &RegisterCatalog) -> String {
    let mut nodes = Vec::new();

    // Tab node
    nodes.push(json!({
        "id": "tab_field_probe",
        "type": "tab",
        "label": "FieldProbe Industrial Telemetry",
        "disabled": false,
        "info": "Generated automatically by field-probe AI engine"
    }));

    let mut y = 100;
    for (key, entry) in &catalog.entries {
        let read_id = format!("modbus_read_{}", key.replace(':', "_"));
        let mqtt_id = format!("mqtt_out_{}", key.replace(':', "_"));

        nodes.push(json!({
            "id": read_id,
            "type": "modbus-read",
            "z": "tab_field_probe",
            "name": format!("Read {} [{}]", key, entry.plausible_type),
            "topic": format!("fieldprobe/registers/{}", key),
            "unitid": entry.node_or_slave,
            "dataType": "HoldingRegister",
            "adr": entry.address,
            "quantity": if entry.plausible_type.contains("32") { 2 } else { 1 },
            "rate": format!("{:.0}", (1.0 / entry.polling_frequency_hz.max(0.1)) * 1000.0),
            "rateUnit": "ms",
            "wires": [[mqtt_id]],
            "x": 200,
            "y": y
        }));

        nodes.push(json!({
            "id": mqtt_id,
            "type": "mqtt out",
            "z": "tab_field_probe",
            "name": format!("Publish {}", key),
            "topic": format!("scada/fieldprobe/{}", key),
            "qos": "1",
            "retain": "true",
            "x": 500,
            "y": y
        }));

        y += 60;
    }

    serde_json::to_string_pretty(&nodes).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::InferredRegisterEntry;
    use fp_core::{CanFrame, Direction, LinkParams, SerialParams};

    #[test]
    fn test_export_dbc_generation() {
        let signals = vec![
            SignalDefinition::new("EngineSpeed", 0, 16, SignalByteOrder::LittleEndian, false, 0.125, 0.0, "rpm"),
            SignalDefinition::new("EngineTorque", 16, 8, SignalByteOrder::LittleEndian, true, 1.0, -125.0, "%"),
        ];

        let messages = vec![(0xCF00400, "EEC1", 8, signals)];
        let dbc = export_dbc(&messages);

        assert!(dbc.contains("BO_ 217056256 EEC1: 8 FieldProbe_Master"));
        assert!(dbc.contains("SG_ EngineSpeed : 0|16@1+ (0.125,0)"));
        assert!(dbc.contains("SG_ EngineTorque : 16|8@1- (1,-125)"));
    }

    #[test]
    fn test_export_pcapng_binary() {
        let ev_can = RawBusEvent {
            interface_id: "can0".into(),
            timestamp_us: 100_000,
            link_params: LinkParams::Serial(SerialParams::default()),
            payload: RawFrame::Can(CanFrame::new_standard(0x123, &[1, 2, 3, 4])),
            direction: Direction::Rx,
            error_flags: Default::default(),
        };

        let ev_serial = RawBusEvent {
            interface_id: "ttyUSB0".into(),
            timestamp_us: 105_000,
            link_params: LinkParams::Serial(SerialParams::default()),
            payload: RawFrame::Serial(fp_core::TimestampedChunk::new(
                vec![0x01, 0x03, 0x00, 0x64, 0x00, 0x02],
                Some(105_000),
            )),
            direction: Direction::Rx,
            error_flags: Default::default(),
        };

        let pcap = export_pcapng(&[ev_can, ev_serial]);
        // Verify SHB magic 0x0A0D0D0A (bytes 0..4)
        assert_eq!(&pcap[0..4], &[0x0A, 0x0D, 0x0D, 0x0A]);
        // Two IDBs of 20 bytes each (SHB is 28 bytes):
        // IDB 0 starts at offset 28
        assert_eq!(&pcap[28..32], &[0x01, 0x00, 0x00, 0x00]); // Block type IDB
        assert_eq!(&pcap[36..38], &227u16.to_le_bytes()); // LinkType 227 (CAN)
        // IDB 1 starts at offset 28 + 20 = 48
        assert_eq!(&pcap[48..52], &[0x01, 0x00, 0x00, 0x00]); // Block type IDB
        assert_eq!(&pcap[56..58], &250u16.to_le_bytes()); // LinkType 250 (RTAC Serial)
        // EPB 0 starts at offset 68
        assert_eq!(&pcap[68..72], &[0x06, 0x00, 0x00, 0x00]); // Block type EPB
        assert_eq!(&pcap[76..80], &0u32.to_le_bytes()); // Interface ID 0 for CAN
    }

    #[test]
    fn test_export_telegraf_and_nodered() {
        let mut catalog = RegisterCatalog::new();
        catalog.insert_or_update(InferredRegisterEntry {
            node_or_slave: "Slave1".into(),
            address: 100,
            polling_frequency_hz: 5.0,
            jitter_ms: 1.2,
            raw_hex: "42F6E666".into(),
            plausible_type: "Float32_ABCD".into(),
            confidence: 0.95,
        });

        let telegraf = export_telegraf(&catalog);
        assert!(telegraf.contains("industrial_register,node=Slave1,type=Float32_ABCD address=100i"));

        let nodered = export_nodered_flow(&catalog);
        assert!(nodered.contains("modbus-read"));
        assert!(nodered.contains("mqtt out"));
    }
}
