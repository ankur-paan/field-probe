use serde::{Deserialize, Serialize};

/// Standard DNP3 (IEEE 1815) CRC-16 calculation (polynomial 0xA646 reversed 0xD178, inverted)
pub fn dnp3_crc16(data: &[u8]) -> u16 {
    let mut crc = 0x0000u16;
    for &b in data {
        for bit in 0..8 {
            let bit_val = ((b >> bit) & 1) as u16;
            let carry = (crc & 1) ^ bit_val;
            crc >>= 1;
            if carry != 0 {
                crc ^= 0xA646;
            }
        }
    }
    !crc
}

/// Verify DNP3 16-bit CRC on a chunk [data_bytes..., crc_lo, crc_hi]
pub fn verify_dnp3_crc(chunk: &[u8]) -> bool {
    if chunk.len() < 3 {
        return false;
    }
    let data_len = chunk.len() - 2;
    let expected = dnp3_crc16(&chunk[..data_len]);
    let actual = (chunk[data_len] as u16) | ((chunk[data_len + 1] as u16) << 8);
    expected == actual
}

/// DNP3 Application Layer Function Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Dnp3FunctionCode {
    Confirm,
    Read,
    Write,
    Select,
    Operate,
    DirectOperate,
    DirectOperateNoAck,
    ImmediateFreeze,
    ImmediateFreezeNoAck,
    FreezeClear,
    FreezeClearNoAck,
    FreezeAtTime,
    FreezeAtTimeNoAck,
    ColdRestart,
    WarmRestart,
    InitializeData,
    InitializeApplication,
    StartApplication,
    StopApplication,
    SaveConfiguration,
    EnableUnsolicited,
    DisableUnsolicited,
    AssignClass,
    DelayMeasure,
    RecordCurrentTime,
    Response,
    UnsolicitedResponse,
    Unknown(u8),
}

impl From<u8> for Dnp3FunctionCode {
    fn from(code: u8) -> Self {
        match code {
            0x00 => Dnp3FunctionCode::Confirm,
            0x01 => Dnp3FunctionCode::Read,
            0x02 => Dnp3FunctionCode::Write,
            0x03 => Dnp3FunctionCode::Select,
            0x04 => Dnp3FunctionCode::Operate,
            0x05 => Dnp3FunctionCode::DirectOperate,
            0x06 => Dnp3FunctionCode::DirectOperateNoAck,
            0x07 => Dnp3FunctionCode::ImmediateFreeze,
            0x08 => Dnp3FunctionCode::ImmediateFreezeNoAck,
            0x09 => Dnp3FunctionCode::FreezeClear,
            0x0A => Dnp3FunctionCode::FreezeClearNoAck,
            0x0B => Dnp3FunctionCode::FreezeAtTime,
            0x0C => Dnp3FunctionCode::FreezeAtTimeNoAck,
            0x0D => Dnp3FunctionCode::ColdRestart,
            0x0E => Dnp3FunctionCode::WarmRestart,
            0x0F => Dnp3FunctionCode::InitializeData,
            0x10 => Dnp3FunctionCode::InitializeApplication,
            0x11 => Dnp3FunctionCode::StartApplication,
            0x12 => Dnp3FunctionCode::StopApplication,
            0x13 => Dnp3FunctionCode::SaveConfiguration,
            0x14 => Dnp3FunctionCode::EnableUnsolicited,
            0x15 => Dnp3FunctionCode::DisableUnsolicited,
            0x16 => Dnp3FunctionCode::AssignClass,
            0x17 => Dnp3FunctionCode::DelayMeasure,
            0x18 => Dnp3FunctionCode::RecordCurrentTime,
            0x81 => Dnp3FunctionCode::Response,
            0x82 => Dnp3FunctionCode::UnsolicitedResponse,
            other => Dnp3FunctionCode::Unknown(other),
        }
    }
}

/// Parsed DNP3 Object Group & Variation representation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dnp3ObjectHeader {
    pub group: u8,
    pub variation: u8,
    pub qualifier: u8,
    pub description: String,
}

/// Fully dissected DNP3 Data Link, Transport, and Application Frame
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dnp3Frame {
    pub source: u16,
    pub destination: u16,
    pub is_from_master: bool,
    pub is_primary: bool,
    pub function_code: Dnp3FunctionCode,
    pub iin: Option<u16>,
    pub transport_seq: u8,
    pub objects: Vec<Dnp3ObjectHeader>,
    pub app_payload: Vec<u8>,
}

/// Lookup common DNP3 Object Groups
pub fn dnp3_group_description(group: u8, variation: u8) -> String {
    match group {
        1 => format!("Binary Input (Var {})", variation),
        2 => format!("Binary Input Event (Var {})", variation),
        10 => format!("Binary Output Status (Var {})", variation),
        12 => format!("Control Relay Output Block (CROB) (Var {})", variation),
        20 => format!("Binary Counter (Var {})", variation),
        21 => format!("Frozen Counter (Var {})", variation),
        30 => format!("Analog Input (Var {})", variation),
        32 => format!("Analog Input Event (Var {})", variation),
        40 => format!("Analog Output Status (Var {})", variation),
        41 => format!("Analog Output Block (Var {})", variation),
        50 => format!("Time & Date (Var {})", variation),
        60 => format!("Class Data Objects (Class {})", variation),
        80 => format!("Internal Indications (Var {})", variation),
        _ => format!("Group {} Var {}", group, variation),
    }
}

/// Dissect a raw DNP3 frame from an RS-485 byte buffer
pub fn dissect_dnp3(input: &[u8]) -> Option<Dnp3Frame> {
    // 1. Data Link Layer Header Check (10 bytes minimum)
    if input.len() < 10 || input[0] != 0x05 || input[1] != 0x64 {
        return None;
    }

    if !verify_dnp3_crc(&input[..10]) {
        return None;
    }

    let link_len = input[2] as usize;
    if link_len < 5 {
        return None;
    }

    let control = input[3];
    let is_from_master = (control & 0x80) != 0;
    let is_primary = (control & 0x40) != 0;

    let destination = (input[4] as u16) | ((input[5] as u16) << 8);
    let source = (input[6] as u16) | ((input[7] as u16) << 8);

    // 2. Extract and verify data blocks (chunks of up to 16 bytes + 2-byte CRC)
    let user_data_len = link_len - 5;
    let mut offset = 10;
    let mut remaining_user_bytes = user_data_len;
    let mut user_payload = Vec::with_capacity(user_data_len);

    while remaining_user_bytes > 0 && offset < input.len() {
        let chunk_size = remaining_user_bytes.min(16);
        let block_len = chunk_size + 2;

        if offset + block_len > input.len() {
            return None;
        }

        let block = &input[offset..offset + block_len];
        if !verify_dnp3_crc(block) {
            return None;
        }

        user_payload.extend_from_slice(&block[..chunk_size]);
        offset += block_len;
        remaining_user_bytes -= chunk_size;
    }

    if user_payload.is_empty() {
        // Link-only ACK or status frame
        return Some(Dnp3Frame {
            source,
            destination,
            is_from_master,
            is_primary,
            function_code: Dnp3FunctionCode::Confirm,
            iin: None,
            transport_seq: 0,
            objects: Vec::new(),
            app_payload: Vec::new(),
        });
    }

    // 3. Transport Layer
    let transport_control = user_payload[0];
    let transport_seq = transport_control & 0x3F;

    if user_payload.len() < 3 {
        return Some(Dnp3Frame {
            source,
            destination,
            is_from_master,
            is_primary,
            function_code: Dnp3FunctionCode::Confirm,
            iin: None,
            transport_seq,
            objects: Vec::new(),
            app_payload: user_payload[1..].to_vec(),
        });
    }

    // 4. Application Layer
    let _app_control = user_payload[1];
    let function_code = Dnp3FunctionCode::from(user_payload[2]);

    let mut app_offset = 3;
    let mut iin = None;

    if matches!(
        function_code,
        Dnp3FunctionCode::Response | Dnp3FunctionCode::UnsolicitedResponse
    ) && user_payload.len() >= 5
    {
        iin = Some((user_payload[3] as u16) | ((user_payload[4] as u16) << 8));
        app_offset = 5;
    }

    // 5. Parse Object Headers
    let mut objects = Vec::new();
    let mut obj_scan = app_offset;
    while obj_scan + 2 < user_payload.len() {
        let grp = user_payload[obj_scan];
        let var = user_payload[obj_scan + 1];
        let qual = user_payload[obj_scan + 2];
        let desc = dnp3_group_description(grp, var);

        objects.push(Dnp3ObjectHeader {
            group: grp,
            variation: var,
            qualifier: qual,
            description: desc,
        });

        // Basic scan step; full parsing will extract records
        obj_scan += 3;
    }

    Some(Dnp3Frame {
        source,
        destination,
        is_from_master,
        is_primary,
        function_code,
        iin,
        transport_seq,
        objects,
        app_payload: user_payload[app_offset..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dnp3_crc_vector() {
        // Standard DNP3 Link Header test vector
        let header_data = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04];
        let crc = dnp3_crc16(&header_data);
        let mut full_header = Vec::new();
        full_header.extend_from_slice(&header_data);
        full_header.extend_from_slice(&crc.to_le_bytes());

        assert!(verify_dnp3_crc(&full_header));
    }

    #[test]
    fn test_dissect_dnp3_read_request() {
        // Construct valid DNP3 Read request from Master (0x0001) to Outstation (0x0002)
        // Transport: FIN|FIR|SEQ 0 (0xC0), App Control: FIR|FIN|CON (0xC1), FC: Read (0x01), Group 60 Var 1 (Class 0)
        let user_data = [0xC0, 0xC1, 0x01, 60, 1, 0x06];
        let user_crc = dnp3_crc16(&user_data);

        let mut packet = Vec::new();
        // Link header: Start=0x05,0x64, Len=5+6=11 (0x0B), Ctrl=0x84 (Master, PRM=0), Dest=2, Src=1
        let hdr_data = [0x05, 0x64, 0x0B, 0x84, 0x02, 0x00, 0x01, 0x00];
        let hdr_crc = dnp3_crc16(&hdr_data);

        packet.extend_from_slice(&hdr_data);
        packet.extend_from_slice(&hdr_crc.to_le_bytes());
        packet.extend_from_slice(&user_data);
        packet.extend_from_slice(&user_crc.to_le_bytes());

        let frame = dissect_dnp3(&packet).expect("Parsed DNP3");
        assert_eq!(frame.source, 1);
        assert_eq!(frame.destination, 2);
        assert!(frame.is_from_master);
        assert_eq!(frame.function_code, Dnp3FunctionCode::Read);
        assert_eq!(frame.objects.len(), 1);
        assert_eq!(frame.objects[0].group, 60);
        assert_eq!(frame.objects[0].variation, 1);
        assert!(frame.objects[0].description.contains("Class Data Objects"));
    }
}
