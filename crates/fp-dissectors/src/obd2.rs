use serde::{Deserialize, Serialize};

/// Standard 5-character Diagnostic Trouble Code (SAE J2012 / ISO 15031-6)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Obd2Dtc {
    /// 5-character DTC string, e.g. "P0300", "U0100"
    pub code: String,
    /// Vehicle system category ("Powertrain", "Chassis", "Body", "Network")
    pub system: String,
    /// True if SAE standard code (0 or 2 second digit), false if manufacturer-specific (1 or 3)
    pub is_standard: bool,
    /// Raw 2-byte wire representation
    pub raw_bytes: [u8; 2],
    /// Known human-readable diagnostic description
    pub description: Option<String>,
}

impl Obd2Dtc {
    /// Parse a 2-byte pair into a 5-character OBD-II DTC
    pub fn parse_dtc(b0: u8, b1: u8) -> Option<Self> {
        if b0 == 0 && b1 == 0 {
            return None;
        }

        let (prefix, system) = match (b0 >> 6) & 0x03 {
            0 => ('P', "Powertrain"),
            1 => ('C', "Chassis"),
            2 => ('B', "Body"),
            3 => ('U', "Network"),
            _ => unreachable!(),
        };

        let second_val = (b0 >> 4) & 0x03;
        let second_char = match second_val {
            0 => '0',
            1 => '1',
            2 => '2',
            3 => '3',
            _ => unreachable!(),
        };
        let is_standard = second_val == 0 || second_val == 2;

        let third_char = format!("{:X}", b0 & 0x0F).chars().next().unwrap_or('0');
        let fourth_char = format!("{:X}", (b1 >> 4) & 0x0F)
            .chars()
            .next()
            .unwrap_or('0');
        let fifth_char = format!("{:X}", b1 & 0x0F).chars().next().unwrap_or('0');

        let code = format!(
            "{}{}{}{}{}",
            prefix, second_char, third_char, fourth_char, fifth_char
        );
        let description = lookup_dtc_description(&code).map(|s| s.to_string());

        Some(Self {
            code,
            system: system.to_string(),
            is_standard,
            raw_bytes: [b0, b1],
            description,
        })
    }

    /// Parse a sequence of bytes into contiguous 2-byte DTC entries
    pub fn parse_dtc_list(data: &[u8]) -> Vec<Self> {
        let mut dtcs = Vec::new();
        let mut i = 0;
        while i + 1 < data.len() {
            if let Some(dtc) = Self::parse_dtc(data[i], data[i + 1]) {
                dtcs.push(dtc);
            }
            i += 2;
        }
        dtcs
    }
}

fn lookup_dtc_description(code: &str) -> Option<&'static str> {
    match code {
        "P0100" => Some("Mass or Volume Air Flow Circuit"),
        "P0115" => Some("Engine Coolant Temperature Circuit"),
        "P0120" => Some("Throttle/Pedal Position Sensor Circuit"),
        "P0300" => Some("Random/Multiple Cylinder Misfire Detected"),
        "P0301" => Some("Cylinder 1 Misfire Detected"),
        "P0302" => Some("Cylinder 2 Misfire Detected"),
        "P0420" => Some("Catalyst System Efficiency Below Threshold (Bank 1)"),
        "P0500" => Some("Vehicle Speed Sensor A"),
        "C0035" => Some("Left Front Wheel Speed Sensor Supply"),
        "B0001" => Some("Driver Frontal Stage 1 Deployment Control"),
        "U0100" => Some("Lost Communication With ECM/PCM A"),
        "U0101" => Some("Lost Communication with TCM"),
        "U0121" => Some("Lost Communication With Anti-Lock Brake System (ABS) Control Module"),
        "U0155" => Some("Lost Communication With Instrument Panel Cluster (IPC) Control Module"),
        _ => None,
    }
}

/// Standard PID nomenclature according to SAE J1979 / ISO 15031-5
pub fn obd2_pid_name(pid: u8) -> &'static str {
    match pid {
        0x00 => "PIDsSupported_01_20",
        0x01 => "MonitorStatusSinceDTCsCleared",
        0x02 => "FreezeDTC",
        0x03 => "FuelSystemStatus",
        0x04 => "CalculatedEngineLoad",
        0x05 => "EngineCoolantTemperature",
        0x06 => "ShortTermFuelTrimBank1",
        0x07 => "LongTermFuelTrimBank1",
        0x08 => "ShortTermFuelTrimBank2",
        0x09 => "LongTermFuelTrimBank2",
        0x0A => "FuelPressure",
        0x0B => "IntakeManifoldAbsolutePressure",
        0x0C => "EngineRPM",
        0x0D => "VehicleSpeed",
        0x0E => "TimingAdvance",
        0x0F => "IntakeAirTemperature",
        0x10 => "MAFAirFlowRate",
        0x11 => "ThrottlePosition",
        0x1F => "RunTimeSinceEngineStart",
        0x20 => "PIDsSupported_21_40",
        0x21 => "DistanceTraveledWithMILOn",
        0x2F => "FuelTankLevelInput",
        0x31 => "DistanceTraveledSinceCodesCleared",
        0x33 => "AbsoluteBarometricPressure",
        0x40 => "PIDsSupported_41_60",
        0x42 => "ControlModuleVoltage",
        0x46 => "AmbientAirTemperature",
        0x5C => "EngineOilTemperature",
        _ => "CustomOrReservedPID",
    }
}

/// Convert raw PID byte buffer into physical engineering units
pub fn format_obd2_pid_value(pid: u8, data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    match pid {
        0x04 => {
            let pct = (data[0] as f32) / 2.55;
            Some(format!("{:.1} %", pct))
        }
        0x05 => {
            let temp = (data[0] as i16) - 40;
            Some(format!("{} °C", temp))
        }
        0x06..=0x09 => {
            let trim = ((data[0] as f32) / 1.28) - 100.0;
            Some(format!("{:.1} %", trim))
        }
        0x0A => {
            let kpa = (data[0] as u32) * 3;
            Some(format!("{} kPa", kpa))
        }
        0x0B => Some(format!("{} kPa", data[0])),
        0x0C => {
            if data.len() < 2 {
                return None;
            }
            let rpm = (((data[0] as u32) << 8) | (data[1] as u32)) as f32 / 4.0;
            Some(format!("{:.0} rpm", rpm))
        }
        0x0D => Some(format!("{} km/h", data[0])),
        0x0E => {
            let adv = ((data[0] as f32) / 2.0) - 64.0;
            Some(format!("{:.1} °", adv))
        }
        0x0F => {
            let temp = (data[0] as i16) - 40;
            Some(format!("{} °C", temp))
        }
        0x10 => {
            if data.len() < 2 {
                return None;
            }
            let maf = (((data[0] as u32) << 8) | (data[1] as u32)) as f32 / 100.0;
            Some(format!("{:.2} g/s", maf))
        }
        0x11 => {
            let pct = (data[0] as f32) / 2.55;
            Some(format!("{:.1} %", pct))
        }
        0x1F => {
            if data.len() < 2 {
                return None;
            }
            let sec = ((data[0] as u32) << 8) | (data[1] as u32);
            Some(format!("{} s", sec))
        }
        0x21 => {
            if data.len() < 2 {
                return None;
            }
            let km = ((data[0] as u32) << 8) | (data[1] as u32);
            Some(format!("{} km", km))
        }
        0x2F => {
            let pct = (data[0] as f32) / 2.55;
            Some(format!("{:.1} %", pct))
        }
        0x33 => Some(format!("{} kPa", data[0])),
        0x42 => {
            if data.len() < 2 {
                return None;
            }
            let volts = (((data[0] as u32) << 8) | (data[1] as u32)) as f32 / 1000.0;
            Some(format!("{:.3} V", volts))
        }
        0x46 => {
            let temp = (data[0] as i16) - 40;
            Some(format!("{} °C", temp))
        }
        0x5C => {
            let temp = (data[0] as i16) - 40;
            Some(format!("{} °C", temp))
        }
        _ => None,
    }
}

/// Standard Mode 09 InfoType nomenclature
pub fn obd2_mode09_name(info_type: u8) -> &'static str {
    match info_type {
        0x02 => "VIN",
        0x04 => "CalibrationID",
        0x06 => "CalibrationVerificationNumber",
        0x08 => "InUsePerformanceTracking",
        0x0A => "ECUName",
        _ => "CustomVehicleInfo",
    }
}

/// Format Mode 09 ASCII strings (VIN, CALID, ECUName)
pub fn format_obd2_mode09_text(info_type: u8, data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    match info_type {
        0x02 | 0x04 | 0x0A => {
            // Strip leading null bytes or framing counters if present
            let slice = if data.len() > 1 && (data[0] == 0x01 || data[0] == 0x00) {
                &data[1..]
            } else {
                data
            };
            let text = String::from_utf8_lossy(slice)
                .trim_matches(char::from(0))
                .trim()
                .to_string();
            if !text.is_empty() {
                Some(text)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Structured representation of parsed SAE J1979 OBD-II diagnostic message
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Obd2Message {
    ShowCurrentData {
        pid: u8,
        pid_name: String,
        raw_data: Vec<u8>,
        formatted_value: Option<String>,
    },
    ShowFreezeFrame {
        pid: u8,
        frame_number: u8,
        raw_data: Vec<u8>,
    },
    ShowStoredDtc {
        dtcs: Vec<Obd2Dtc>,
    },
    ClearDiagnosticInfo,
    OxygenSensorMonitoring {
        test_id: u8,
        data: Vec<u8>,
    },
    OnBoardMonitoring {
        obd_mid: u8,
        tid: u8,
        data: Vec<u8>,
    },
    ShowPendingDtc {
        dtcs: Vec<Obd2Dtc>,
    },
    ControlOperation {
        tid: u8,
        data: Vec<u8>,
    },
    RequestVehicleInfo {
        info_type: u8,
        info_name: String,
        data: Vec<u8>,
        text_value: Option<String>,
    },
    PermanentDtc {
        dtcs: Vec<Obd2Dtc>,
    },
    RawMode {
        mode: u8,
        is_response: bool,
        data: Vec<u8>,
    },
}

fn extract_dtc_slice(is_response: bool, payload: &[u8]) -> &[u8] {
    if is_response && payload.len() >= 2 {
        if (payload.len() & 1) == 0 {
            &payload[2..]
        } else {
            &payload[1..]
        }
    } else if payload.len() > 1 {
        &payload[1..]
    } else {
        &[]
    }
}

/// Dissect reassembled ISO-TP payload into an SAE J1979 OBD-II message
pub fn dissect_obd2(payload: &[u8]) -> Option<Obd2Message> {
    if payload.is_empty() {
        return None;
    }

    let sid = payload[0];
    let is_response = (0x41..=0x4A).contains(&sid);
    let mode = if is_response { sid - 0x40 } else { sid };

    match mode {
        0x01 => {
            let pid = payload.get(1).copied().unwrap_or(0);
            let raw_data = if payload.len() > 2 {
                payload[2..].to_vec()
            } else {
                Vec::new()
            };
            let formatted_value = format_obd2_pid_value(pid, &raw_data);
            Some(Obd2Message::ShowCurrentData {
                pid,
                pid_name: obd2_pid_name(pid).to_string(),
                raw_data,
                formatted_value,
            })
        }

        0x02 => {
            let pid = payload.get(1).copied().unwrap_or(0);
            let frame_number = payload.get(2).copied().unwrap_or(0);
            let raw_data = if payload.len() > 3 {
                payload[3..].to_vec()
            } else {
                Vec::new()
            };
            Some(Obd2Message::ShowFreezeFrame {
                pid,
                frame_number,
                raw_data,
            })
        }

        0x03 => {
            let dtcs = Obd2Dtc::parse_dtc_list(extract_dtc_slice(is_response, payload));
            Some(Obd2Message::ShowStoredDtc { dtcs })
        }

        0x04 => Some(Obd2Message::ClearDiagnosticInfo),

        0x05 => {
            let test_id = payload.get(1).copied().unwrap_or(0);
            let data = if payload.len() > 2 {
                payload[2..].to_vec()
            } else {
                Vec::new()
            };
            Some(Obd2Message::OxygenSensorMonitoring { test_id, data })
        }

        0x06 => {
            let obd_mid = payload.get(1).copied().unwrap_or(0);
            let tid = payload.get(2).copied().unwrap_or(0);
            let data = if payload.len() > 3 {
                payload[3..].to_vec()
            } else {
                Vec::new()
            };
            Some(Obd2Message::OnBoardMonitoring { obd_mid, tid, data })
        }

        0x07 => {
            let dtcs = Obd2Dtc::parse_dtc_list(extract_dtc_slice(is_response, payload));
            Some(Obd2Message::ShowPendingDtc { dtcs })
        }

        0x08 => {
            let tid = payload.get(1).copied().unwrap_or(0);
            let data = if payload.len() > 2 {
                payload[2..].to_vec()
            } else {
                Vec::new()
            };
            Some(Obd2Message::ControlOperation { tid, data })
        }

        0x09 => {
            let info_type = payload.get(1).copied().unwrap_or(0);
            let data = if payload.len() > 2 {
                payload[2..].to_vec()
            } else {
                Vec::new()
            };
            let text_value = format_obd2_mode09_text(info_type, &data);
            Some(Obd2Message::RequestVehicleInfo {
                info_type,
                info_name: obd2_mode09_name(info_type).to_string(),
                data,
                text_value,
            })
        }

        0x0A => {
            let dtcs = Obd2Dtc::parse_dtc_list(extract_dtc_slice(is_response, payload));
            Some(Obd2Message::PermanentDtc { dtcs })
        }

        _ => Some(Obd2Message::RawMode {
            mode: sid,
            is_response,
            data: payload[1..].to_vec(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obd2_dtc_parsing() {
        // P0300: 0x03, 0x00
        let p0300 = Obd2Dtc::parse_dtc(0x03, 0x00).expect("DTC P0300");
        assert_eq!(p0300.code, "P0300");
        assert_eq!(p0300.system, "Powertrain");
        assert!(p0300.is_standard);
        assert_eq!(
            p0300.description,
            Some("Random/Multiple Cylinder Misfire Detected".to_string())
        );

        // U0155: (3 << 6) | (0 << 4) | 0x01 = 0xC1, 0x55
        let u0155 = Obd2Dtc::parse_dtc(0xC1, 0x55).expect("DTC U0155");
        assert_eq!(u0155.code, "U0155");
        assert_eq!(u0155.system, "Network");
        assert!(u0155.is_standard);

        // C0035: (1 << 6) | (0 << 4) | 0x00 = 0x40, 0x35
        let c0035 = Obd2Dtc::parse_dtc(0x40, 0x35).expect("DTC C0035");
        assert_eq!(c0035.code, "C0035");
        assert_eq!(c0035.system, "Chassis");

        // Zero bytes -> None
        assert_eq!(Obd2Dtc::parse_dtc(0x00, 0x00), None);
    }

    #[test]
    fn test_obd2_mode01_live_pids() {
        // Engine RPM: 0x41, PID 0x0C, 0x1F, 0x40 (8000 / 4 = 2000 rpm)
        let resp_rpm = [0x41, 0x0C, 0x1F, 0x40];
        let msg = dissect_obd2(&resp_rpm).expect("Dissected OBD2");
        match msg {
            Obd2Message::ShowCurrentData {
                pid,
                pid_name,
                formatted_value,
                ..
            } => {
                assert_eq!(pid, 0x0C);
                assert_eq!(pid_name, "EngineRPM");
                assert_eq!(formatted_value, Some("2000 rpm".to_string()));
            }
            _ => panic!("Expected ShowCurrentData"),
        }

        // Coolant Temp: 0x41, PID 0x05, 0x78 (120 - 40 = 80 °C)
        let resp_temp = [0x41, 0x05, 0x78];
        let msg_temp = dissect_obd2(&resp_temp).unwrap();
        match msg_temp {
            Obd2Message::ShowCurrentData {
                pid,
                formatted_value,
                ..
            } => {
                assert_eq!(pid, 0x05);
                assert_eq!(formatted_value, Some("80 °C".to_string()));
            }
            _ => panic!("Expected ShowCurrentData"),
        }
    }

    #[test]
    fn test_obd2_mode03_dtc_report() {
        // Mode 03 response: 0x43, 2 DTCs, P0300 (0x03, 0x00), U0100 (0xC1, 0x00)
        let resp = [0x43, 0x02, 0x03, 0x00, 0xC1, 0x00];
        let msg = dissect_obd2(&resp).unwrap();
        match msg {
            Obd2Message::ShowStoredDtc { dtcs } => {
                assert_eq!(dtcs.len(), 2);
                assert_eq!(dtcs[0].code, "P0300");
                assert_eq!(dtcs[1].code, "U0100");
            }
            _ => panic!("Expected ShowStoredDtc"),
        }
    }

    #[test]
    fn test_obd2_mode09_vin_decoding() {
        // Mode 09 response: 0x49, infoType 0x02 (VIN), 0x01 (count), "WBA31AZ0000000000"
        let mut resp = vec![0x49, 0x02, 0x01];
        resp.extend_from_slice(b"WBA31AZ0000000000");
        let msg = dissect_obd2(&resp).unwrap();
        match msg {
            Obd2Message::RequestVehicleInfo {
                info_type,
                text_value,
                ..
            } => {
                assert_eq!(info_type, 0x02);
                assert_eq!(text_value, Some("WBA31AZ0000000000".to_string()));
            }
            _ => panic!("Expected RequestVehicleInfo"),
        }
    }
}
