use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u8},
    IResult,
};
use serde::{Deserialize, Serialize};

/// Standard Modbus Exception Codes (0x01 - 0x0B)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModbusExceptionCode {
    IllegalFunction = 0x01,
    IllegalDataAddress = 0x02,
    IllegalDataValue = 0x03,
    ServerDeviceFailure = 0x04,
    Acknowledge = 0x05,
    ServerDeviceBusy = 0x06,
    NegativeAcknowledge = 0x07,
    MemoryParityError = 0x08,
    GatewayPathUnavailable = 0x0A,
    GatewayTargetDeviceFailedToRespond = 0x0B,
    Unknown = 0xFF,
}

impl ModbusExceptionCode {
    pub fn from_u8(code: u8) -> Self {
        match code {
            0x01 => Self::IllegalFunction,
            0x02 => Self::IllegalDataAddress,
            0x03 => Self::IllegalDataValue,
            0x04 => Self::ServerDeviceFailure,
            0x05 => Self::Acknowledge,
            0x06 => Self::ServerDeviceBusy,
            0x07 => Self::NegativeAcknowledge,
            0x08 => Self::MemoryParityError,
            0x0A => Self::GatewayPathUnavailable,
            0x0B => Self::GatewayTargetDeviceFailedToRespond,
            _ => Self::Unknown,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::IllegalFunction => "Illegal Function",
            Self::IllegalDataAddress => "Illegal Data Address",
            Self::IllegalDataValue => "Illegal Data Value",
            Self::ServerDeviceFailure => "Server Device Failure",
            Self::Acknowledge => "Acknowledge",
            Self::ServerDeviceBusy => "Server Device Busy",
            Self::NegativeAcknowledge => "Negative Acknowledge",
            Self::MemoryParityError => "Memory Parity Error",
            Self::GatewayPathUnavailable => "Gateway Path Unavailable",
            Self::GatewayTargetDeviceFailedToRespond => "Gateway Target Device Failed to Respond",
            Self::Unknown => "Unknown Exception Code",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::IllegalFunction => "Function code received in query is not an allowable action for server.",
            Self::IllegalDataAddress => "Address range specified in query exceeds server memory boundary.",
            Self::IllegalDataValue => "Value in query data field is outside acceptable range or count is invalid.",
            Self::ServerDeviceFailure => "Unrecoverable error occurred while server attempted requested action.",
            Self::Acknowledge => "Server accepted request and is processing it; requires prolonged duration.",
            Self::ServerDeviceBusy => "Server engaged in long-duration command; master should retransmit later.",
            Self::NegativeAcknowledge => "Server cannot perform programming request received in query.",
            Self::MemoryParityError => "Server detected parity error in extended memory attempted to read.",
            Self::GatewayPathUnavailable => "Gateway overload or internal bus path unallocated.",
            Self::GatewayTargetDeviceFailedToRespond => "Gateway received no response from targeted downstream slave.",
            Self::Unknown => "Unrecognized vendor-specific or malformed exception code.",
        }
    }
}

/// Modbus Diagnostic Sub-Functions (Function Code 0x08)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiagnosticSubFunction {
    ReturnQueryData = 0x0000,
    RestartCommunicationsOption = 0x0001,
    ReturnDiagnosticRegister = 0x0002,
    ChangeAsciiInputDelimiter = 0x0003,
    ForceListenOnlyMode = 0x0004,
    ClearCountersAndDiagnosticRegister = 0x000A,
    ReturnBusMessageCount = 0x000B,
    ReturnBusCommunicationErrorCount = 0x000C,
    ReturnBusExceptionErrorCount = 0x000D,
    ReturnSlaveMessageCount = 0x000E,
    ReturnSlaveNoResponseCount = 0x000F,
    ReturnSlaveNakCount = 0x0010,
    ReturnSlaveDeviceBusyCount = 0x0011,
    ReturnBusCharacterOverrunCount = 0x0012,
    Unknown = 0xFFFF,
}

impl DiagnosticSubFunction {
    pub fn from_u16(sub: u16) -> Self {
        match sub {
            0x0000 => Self::ReturnQueryData,
            0x0001 => Self::RestartCommunicationsOption,
            0x0002 => Self::ReturnDiagnosticRegister,
            0x0003 => Self::ChangeAsciiInputDelimiter,
            0x0004 => Self::ForceListenOnlyMode,
            0x000A => Self::ClearCountersAndDiagnosticRegister,
            0x000B => Self::ReturnBusMessageCount,
            0x000C => Self::ReturnBusCommunicationErrorCount,
            0x000D => Self::ReturnBusExceptionErrorCount,
            0x000E => Self::ReturnSlaveMessageCount,
            0x000F => Self::ReturnSlaveNoResponseCount,
            0x0010 => Self::ReturnSlaveNakCount,
            0x0011 => Self::ReturnSlaveDeviceBusyCount,
            0x0012 => Self::ReturnBusCharacterOverrunCount,
            _ => Self::Unknown,
        }
    }
}

/// Dissected Modbus PDU (Protocol Data Unit)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModbusPdu {
    // Queries (Master to Slave)
    ReadCoilsQuery {
        start_addr: u16,
        quantity: u16,
    },
    ReadDiscreteInputsQuery {
        start_addr: u16,
        quantity: u16,
    },
    ReadHoldingRegistersQuery {
        start_addr: u16,
        quantity: u16,
    },
    ReadInputRegistersQuery {
        start_addr: u16,
        quantity: u16,
    },
    WriteSingleCoil {
        addr: u16,
        value: u16,
    },
    WriteSingleRegister {
        addr: u16,
        value: u16,
    },
    WriteMultipleCoilsQuery {
        start_addr: u16,
        quantity: u16,
        byte_count: u8,
        values: Vec<u8>,
    },
    WriteMultipleRegistersQuery {
        start_addr: u16,
        quantity: u16,
        byte_count: u8,
        values: Vec<u8>,
    },
    Diagnostics {
        sub_function: DiagnosticSubFunction,
        data: u16,
    },

    // Responses (Slave to Master)
    ReadResponse {
        function_code: u8,
        byte_count: u8,
        data: Vec<u8>,
    },
    WriteMultipleResponse {
        function_code: u8,
        start_addr: u16,
        quantity: u16,
    },

    // Errors
    Exception {
        original_fc: u8,
        exception_code: ModbusExceptionCode,
        raw_code: u8,
    },

    // Unhandled / vendor specific
    Raw {
        function_code: u8,
        payload: Vec<u8>,
    },
}

/// Parsed Modbus RTU ADU (Application Data Unit)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModbusRtuAdu {
    pub slave_id: u8,
    pub pdu: ModbusPdu,
    pub crc16: u16,
}

fn parse_pdu(input: &[u8]) -> IResult<&[u8], ModbusPdu> {
    let (input, fc) = be_u8(input)?;

    // Modbus exception has high bit set on function code (FC >= 0x80)
    if (fc & 0x80) != 0 {
        let (input, exc_byte) = be_u8(input)?;
        return Ok((
            input,
            ModbusPdu::Exception {
                original_fc: fc & 0x7F,
                exception_code: ModbusExceptionCode::from_u8(exc_byte),
                raw_code: exc_byte,
            },
        ));
    }

    match fc {
        // Read functions: 0x01, 0x02, 0x03, 0x04
        // Query has 4 bytes (start_addr: u16, quantity: u16)
        // Response has byte_count: u8 followed by data
        0x01 => {
            // A ReadCoils response has byte_count as first byte.
            // If input.len() == 4 and input[0] == 3, it is a 3-byte coil response ([0x03, b0, b1, b2]).
            if input.len() == 4 && input[0] == 3 {
                let (input, byte_count) = be_u8(input)?;
                let (input, data) = take(byte_count as usize)(input)?;
                Ok((
                    input,
                    ModbusPdu::ReadResponse {
                        function_code: fc,
                        byte_count,
                        data: data.to_vec(),
                    },
                ))
            } else if input.len() == 4 {
                let (input, start_addr) = be_u16(input)?;
                let (input, quantity) = be_u16(input)?;
                Ok((input, ModbusPdu::ReadCoilsQuery { start_addr, quantity }))
            } else if !input.is_empty() {
                let (input, byte_count) = be_u8(input)?;
                let (input, data) = take(byte_count as usize)(input)?;
                Ok((
                    input,
                    ModbusPdu::ReadResponse {
                        function_code: fc,
                        byte_count,
                        data: data.to_vec(),
                    },
                ))
            } else {
                Ok((input, ModbusPdu::Raw { function_code: fc, payload: input.to_vec() }))
            }
        }
        0x02 => {
            // A ReadDiscreteInputs response has byte_count as first byte.
            // If input.len() == 4 and input[0] == 3, it is a 3-byte discrete input response ([0x03, b0, b1, b2]).
            if input.len() == 4 && input[0] == 3 {
                let (input, byte_count) = be_u8(input)?;
                let (input, data) = take(byte_count as usize)(input)?;
                Ok((
                    input,
                    ModbusPdu::ReadResponse {
                        function_code: fc,
                        byte_count,
                        data: data.to_vec(),
                    },
                ))
            } else if input.len() == 4 {
                let (input, start_addr) = be_u16(input)?;
                let (input, quantity) = be_u16(input)?;
                Ok((input, ModbusPdu::ReadDiscreteInputsQuery { start_addr, quantity }))
            } else if !input.is_empty() {
                let (input, byte_count) = be_u8(input)?;
                let (input, data) = take(byte_count as usize)(input)?;
                Ok((
                    input,
                    ModbusPdu::ReadResponse {
                        function_code: fc,
                        byte_count,
                        data: data.to_vec(),
                    },
                ))
            } else {
                Ok((input, ModbusPdu::Raw { function_code: fc, payload: input.to_vec() }))
            }
        }
        0x03 => {
            if input.len() == 4 {
                let (input, start_addr) = be_u16(input)?;
                let (input, quantity) = be_u16(input)?;
                Ok((
                    input,
                    ModbusPdu::ReadHoldingRegistersQuery {
                        start_addr,
                        quantity,
                    },
                ))
            } else if !input.is_empty() {
                let (input, byte_count) = be_u8(input)?;
                let (input, data) = take(byte_count as usize)(input)?;
                Ok((
                    input,
                    ModbusPdu::ReadResponse {
                        function_code: fc,
                        byte_count,
                        data: data.to_vec(),
                    },
                ))
            } else {
                Ok((input, ModbusPdu::Raw { function_code: fc, payload: input.to_vec() }))
            }
        }
        0x04 => {
            if input.len() == 4 {
                let (input, start_addr) = be_u16(input)?;
                let (input, quantity) = be_u16(input)?;
                Ok((input, ModbusPdu::ReadInputRegistersQuery { start_addr, quantity }))
            } else if !input.is_empty() {
                let (input, byte_count) = be_u8(input)?;
                let (input, data) = take(byte_count as usize)(input)?;
                Ok((
                    input,
                    ModbusPdu::ReadResponse {
                        function_code: fc,
                        byte_count,
                        data: data.to_vec(),
                    },
                ))
            } else {
                Ok((input, ModbusPdu::Raw { function_code: fc, payload: input.to_vec() }))
            }
        }
        0x05 => {
            let (input, addr) = be_u16(input)?;
            let (input, value) = be_u16(input)?;
            Ok((input, ModbusPdu::WriteSingleCoil { addr, value }))
        }
        0x06 => {
            let (input, addr) = be_u16(input)?;
            let (input, value) = be_u16(input)?;
            Ok((input, ModbusPdu::WriteSingleRegister { addr, value }))
        }
        0x08 => {
            let (input, sub) = be_u16(input)?;
            let (input, data) = be_u16(input)?;
            Ok((
                input,
                ModbusPdu::Diagnostics {
                    sub_function: DiagnosticSubFunction::from_u16(sub),
                    data,
                },
            ))
        }
        0x0F => {
            if input.len() == 4 {
                // Response
                let (input, start_addr) = be_u16(input)?;
                let (input, quantity) = be_u16(input)?;
                Ok((
                    input,
                    ModbusPdu::WriteMultipleResponse {
                        function_code: fc,
                        start_addr,
                        quantity,
                    },
                ))
            } else if input.len() >= 5 {
                // Query
                let (input, start_addr) = be_u16(input)?;
                let (input, quantity) = be_u16(input)?;
                let (input, byte_count) = be_u8(input)?;
                let (input, values) = take(byte_count as usize)(input)?;
                Ok((
                    input,
                    ModbusPdu::WriteMultipleCoilsQuery {
                        start_addr,
                        quantity,
                        byte_count,
                        values: values.to_vec(),
                    },
                ))
            } else {
                let (remaining, payload) = take(input.len())(input)?;
                Ok((remaining, ModbusPdu::Raw { function_code: fc, payload: payload.to_vec() }))
            }
        }
        0x10 => {
            if input.len() == 4 {
                // Response
                let (input, start_addr) = be_u16(input)?;
                let (input, quantity) = be_u16(input)?;
                Ok((
                    input,
                    ModbusPdu::WriteMultipleResponse {
                        function_code: fc,
                        start_addr,
                        quantity,
                    },
                ))
            } else if input.len() >= 5 {
                // Query
                let (input, start_addr) = be_u16(input)?;
                let (input, quantity) = be_u16(input)?;
                let (input, byte_count) = be_u8(input)?;
                let (input, values) = take(byte_count as usize)(input)?;
                Ok((
                    input,
                    ModbusPdu::WriteMultipleRegistersQuery {
                        start_addr,
                        quantity,
                        byte_count,
                        values: values.to_vec(),
                    },
                ))
            } else {
                let (remaining, payload) = take(input.len())(input)?;
                Ok((remaining, ModbusPdu::Raw { function_code: fc, payload: payload.to_vec() }))
            }
        }
        _ => {
            let (remaining, payload) = take(input.len())(input)?;
            Ok((
                remaining,
                ModbusPdu::Raw {
                    function_code: fc,
                    payload: payload.to_vec(),
                },
            ))
        }
    }
}

/// Zero-panic parse of Modbus RTU byte stream.
/// Returns None on truncated or malformed input without panicking.
pub fn parse_modbus_rtu_frame(raw: &[u8]) -> Option<ModbusRtuAdu> {
    if raw.len() < 4 {
        return None;
    }

    let (payload, crc_slice) = raw.split_at_checked(raw.len() - 2)?;
    let (rem, slave_id) = be_u8::<_, ()>(payload).ok()?;
    let (_rem, pdu) = parse_pdu(rem).ok()?;

    let low = *crc_slice.first()? as u16;
    let high = *crc_slice.get(1)? as u16;
    let crc16 = low | (high << 8);

    Some(ModbusRtuAdu {
        slave_id,
        pdu,
        crc16,
    })
}

/// Parsed Modbus TCP ADU (Application Data Unit with MBAP Header)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModbusTcpAdu {
    pub transaction_id: u16,
    pub protocol_id: u16,
    pub length: u16,
    pub unit_id: u8,
    pub pdu: ModbusPdu,
}

/// Zero-panic parse of Modbus TCP byte stream with MBAP header.
/// Returns None on truncated or invalid frames without panicking.
pub fn parse_modbus_tcp_frame(raw: &[u8]) -> Option<ModbusTcpAdu> {
    if raw.len() < 7 {
        return None;
    }
    let (rem, transaction_id) = be_u16::<_, ()>(raw).ok()?;
    let (rem, protocol_id) = be_u16::<_, ()>(rem).ok()?;
    let (rem, length) = be_u16::<_, ()>(rem).ok()?;
    let (rem, unit_id) = be_u8::<_, ()>(rem).ok()?;

    if protocol_id != 0 {
        return None;
    }

    let pdu_len = (length as usize).saturating_sub(1);
    if rem.len() < pdu_len {
        return None;
    }
    let pdu_slice = &rem[..pdu_len];
    let (_rem, pdu) = parse_pdu(pdu_slice).ok()?;

    Some(ModbusTcpAdu {
        transaction_id,
        protocol_id,
        length,
        unit_id,
        pdu,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_zero_panic_empty_or_truncated() {
        assert_eq!(parse_modbus_rtu_frame(&[]), None);
        assert_eq!(parse_modbus_rtu_frame(&[0x01]), None);
        assert_eq!(parse_modbus_rtu_frame(&[0x01, 0x03]), None);
    }

    #[test]
    fn test_parse_valid_read_holding_registers_query() {
        let raw = [0x01, 0x03, 0x00, 0x6B, 0x00, 0x03, 0x74, 0x17];
        let adu = parse_modbus_rtu_frame(&raw).expect("Valid Modbus RTU frame");
        assert_eq!(adu.slave_id, 0x01);
        assert_eq!(
            adu.pdu,
            ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 107,
                quantity: 3
            }
        );
        assert_eq!(adu.crc16, 0x1774);
    }

    #[test]
    fn test_parse_read_holding_registers_response() {
        // Slave 1, FC 0x03, Byte Count 6, Registers [0x022B, 0x0000, 0x0064], CRC
        let raw = [0x01, 0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00];
        let adu = parse_modbus_rtu_frame(&raw).expect("Valid Modbus response");
        assert_eq!(adu.slave_id, 0x01);
        match adu.pdu {
            ModbusPdu::ReadResponse { function_code, byte_count, data } => {
                assert_eq!(function_code, 0x03);
                assert_eq!(byte_count, 6);
                assert_eq!(data, vec![0x02, 0x2B, 0x00, 0x00, 0x00, 0x64]);
            }
            _ => panic!("Expected ReadResponse"),
        }
    }

    #[test]
    fn test_parse_modbus_exception_frame() {
        // Slave 1, FC 0x83 (Exception on 0x03), Code 0x02 (Illegal Data Address), CRC
        let raw = [0x01, 0x83, 0x02, 0xC0, 0xF1];
        let adu = parse_modbus_rtu_frame(&raw).expect("Valid Modbus exception frame");
        assert_eq!(adu.slave_id, 0x01);
        assert_eq!(
            adu.pdu,
            ModbusPdu::Exception {
                original_fc: 0x03,
                exception_code: ModbusExceptionCode::IllegalDataAddress,
                raw_code: 0x02,
            }
        );
        assert_eq!(adu.pdu.exception_name().unwrap_or(""), "Illegal Data Address");
    }

    #[test]
    fn test_parse_diagnostics_frame() {
        // Slave 1, FC 0x08, Sub 0x0000 (Echo), Data 0x1234, CRC
        let raw = [0x01, 0x08, 0x00, 0x00, 0x12, 0x34, 0xED, 0x7C];
        let adu = parse_modbus_rtu_frame(&raw).expect("Valid Diagnostics frame");
        assert_eq!(
            adu.pdu,
            ModbusPdu::Diagnostics {
                sub_function: DiagnosticSubFunction::ReturnQueryData,
                data: 0x1234,
            }
        );
    }

    #[test]
    fn test_parse_modbus_tcp_frame() {
        // Transaction 0x0001, Proto 0x0000, Length 0x0006, Unit 0x01, FC 0x03, Start 0x0000, Qty 0x0001
        let tcp_raw = [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01];
        let adu = parse_modbus_tcp_frame(&tcp_raw).expect("Valid Modbus TCP frame");
        assert_eq!(adu.transaction_id, 1);
        assert_eq!(adu.unit_id, 1);
        assert_eq!(
            adu.pdu,
            ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 0,
                quantity: 1,
            }
        );
    }

    #[test]
    fn test_parse_read_coils_3byte_response_collision() {
        // FC 0x01, byte count 3, 3 data bytes = 4 bytes input after FC!
        // ADU: Slave 1, FC 0x01, ByteCount 0x03, Data [0xAA, 0xBB, 0xCC], CRC [0x12, 0x34]
        let raw = [0x01, 0x01, 0x03, 0xAA, 0xBB, 0xCC, 0x12, 0x34];
        let adu = parse_modbus_rtu_frame(&raw).expect("Valid ReadCoils response");
        assert_eq!(
            adu.pdu,
            ModbusPdu::ReadResponse {
                function_code: 0x01,
                byte_count: 3,
                data: vec![0xAA, 0xBB, 0xCC],
            }
        );
    }

    // Property-based fuzz tests: random byte sequences MUST NEVER panic
    proptest! {
        #[test]
        fn fuzz_modbus_rtu_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_modbus_rtu_frame(&data);
        }

        #[test]
        fn fuzz_modbus_tcp_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_modbus_tcp_frame(&data);
        }
    }
}

impl ModbusPdu {
    pub fn exception_name(&self) -> Option<&'static str> {
        if let ModbusPdu::Exception { exception_code, .. } = self {
            Some(exception_code.name())
        } else {
            None
        }
    }
}
