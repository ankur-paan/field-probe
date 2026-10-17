/// Compute Modbus RTU CRC-16 (polynomial 0x8005 reflected to 0xA001, initial value 0xFFFF).
pub fn modbus_rtu_crc16(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if (crc & 0x0001) != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Verify if the trailing 2 bytes of a Modbus RTU frame match its computed CRC-16.
pub fn verify_modbus_rtu_crc16(frame: &[u8]) -> bool {
    if frame.len() < 4 {
        return false;
    }
    let payload = &frame[..frame.len() - 2];
    let expected = modbus_rtu_crc16(payload);
    let low = frame[frame.len() - 2] as u16;
    let high = frame[frame.len() - 1] as u16;
    let actual = low | (high << 8);
    expected == actual
}

/// Compute Longitudinal Redundancy Check (LRC) for Modbus ASCII.
pub fn modbus_ascii_lrc(data: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for &b in data {
        sum = sum.wrapping_add(b);
    }
    (!sum).wrapping_add(1)
}

/// BACnet MS/TP Header CRC-8 (polynomial X^8 + X^7 + X^4 + X^3 + X + 1, init 0xFF).
pub fn bacnet_crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0xFF;
    for &byte in data {
        let mut data_byte = byte;
        for _ in 0..8 {
            let carry = (crc ^ data_byte) & 0x01;
            crc >>= 1;
            if carry != 0 {
                crc ^= 0x8C;
            }
            data_byte >>= 1;
        }
    }
    !crc
}

/// Compute DNP3 Data Link Layer CRC-16 (polynomial 0x3D65 reflected to 0xA6BC, inverted result).
pub fn dnp3_crc16(data: &[u8]) -> u16 {
    let mut crc = 0x0000u16;
    for &byte in data {
        let mut temp = (byte as u16) ^ (crc & 0xFF);
        for _ in 0..8 {
            if (temp & 0x01) != 0 {
                temp = (temp >> 1) ^ 0xA6BC;
            } else {
                temp >>= 1;
            }
        }
        crc = (crc >> 8) ^ temp;
    }
    !crc
}

/// Verify trailing 2 bytes of a DNP3 chunk against its computed CRC-16 (Little-Endian).
pub fn verify_dnp3_crc16(chunk: &[u8]) -> bool {
    if chunk.len() < 3 {
        return false;
    }
    let payload = &chunk[..chunk.len() - 2];
    let expected = dnp3_crc16(payload);
    let low = chunk[chunk.len() - 2] as u16;
    let high = chunk[chunk.len() - 1] as u16;
    let actual = low | (high << 8);
    expected == actual
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modbus_rtu_crc16_standard_vector() {
        // Modbus RTU read query: Slave 0x01, FC 0x03, Start 0x0000, Count 0x0001 -> CRC = 0x840A (0x0A, 0x84)
        let query = [0x01, 0x03, 0x00, 0x00, 0x00, 0x01];
        let crc = modbus_rtu_crc16(&query);
        assert_eq!(crc, 0x0A84); // low byte 0x84, high byte 0x0A

        let full_frame = [0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x84, 0x0A];
        assert!(verify_modbus_rtu_crc16(&full_frame));

        let bad_frame = [0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x84, 0x0B];
        assert!(!verify_modbus_rtu_crc16(&bad_frame));
    }

    #[test]
    fn test_dnp3_crc_vector() {
        // Standard DNP3 frame header: 0x05, 0x64, Len 0x05, Ctrl 0xC0, Dest 0x01, 0x00, Src 0x02, 0x00
        let header = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00];
        let crc = dnp3_crc16(&header);
        let low = (crc & 0xFF) as u8;
        let high = ((crc >> 8) & 0xFF) as u8;
        let chunk = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00, low, high];
        assert!(verify_dnp3_crc16(&chunk));
    }
}
