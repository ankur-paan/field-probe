use fp_dissectors::{ModbusPdu, ModbusRtuAdu};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Matched Modbus transaction (query paired with subsequent response)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchedTransaction {
    pub slave_id: u8,
    pub function_code: u8,
    pub start_address: u16,
    pub quantity: u16,
    pub query_timestamp_us: u64,
    pub response_timestamp_us: u64,
    /// Round-trip time in microseconds
    pub latency_us: u64,
    /// Decoded 16-bit register values: (address, register_value)
    pub register_values: Vec<(u16, u16)>,
}

#[derive(Debug, Clone)]
struct PendingQuery {
    start_address: u16,
    quantity: u16,
    timestamp_us: u64,
}

/// Transaction matcher correlating Master queries with Slave responses across the wire
#[derive(Debug, Clone, Default)]
pub struct TransactionMatcher {
    // Key: (slave_id, function_code)
    pending_queries: HashMap<(u8, u8), PendingQuery>,
    pub max_turnaround_timeout_us: u64,
}

impl TransactionMatcher {
    pub fn new(max_turnaround_timeout_ms: u64) -> Self {
        Self {
            pending_queries: HashMap::new(),
            max_turnaround_timeout_us: max_turnaround_timeout_ms * 1000,
        }
    }

    /// Process a dissected Modbus RTU frame with its arrival timestamp in microseconds.
    /// Returns MatchedTransaction if this frame completes a pending query.
    pub fn ingest_modbus_frame(
        &mut self,
        adu: &ModbusRtuAdu,
        timestamp_us: u64,
    ) -> Option<MatchedTransaction> {
        match &adu.pdu {
            // Queries
            ModbusPdu::ReadHoldingRegistersQuery { start_addr, quantity } => {
                self.pending_queries.insert(
                    (adu.slave_id, 0x03),
                    PendingQuery {
                        start_address: *start_addr,
                        quantity: *quantity,
                        timestamp_us,
                    },
                );
                None
            }
            ModbusPdu::ReadInputRegistersQuery { start_addr, quantity } => {
                self.pending_queries.insert(
                    (adu.slave_id, 0x04),
                    PendingQuery {
                        start_address: *start_addr,
                        quantity: *quantity,
                        timestamp_us,
                    },
                );
                None
            }

            // Responses
            ModbusPdu::ReadResponse { function_code, byte_count, data } => {
                let key = (adu.slave_id, *function_code);
                if let Some(query) = self.pending_queries.remove(&key) {
                    let elapsed_us = timestamp_us.saturating_sub(query.timestamp_us);
                    if elapsed_us <= self.max_turnaround_timeout_us {
                        // Unpack 16-bit registers
                        let mut register_values = Vec::new();
                        for i in 0..(*byte_count as usize / 2) {
                            let idx = i * 2;
                            if idx + 1 < data.len() {
                                let val = u16::from_be_bytes([data[idx], data[idx + 1]]);
                                let reg_addr = query.start_address.wrapping_add(i as u16);
                                register_values.push((reg_addr, val));
                            }
                        }

                        return Some(MatchedTransaction {
                            slave_id: adu.slave_id,
                            function_code: *function_code,
                            start_address: query.start_address,
                            quantity: query.quantity,
                            query_timestamp_us: query.timestamp_us,
                            response_timestamp_us: timestamp_us,
                            latency_us: elapsed_us,
                            register_values,
                        });
                    }
                }
                None
            }

            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modbus_query_response_pairing() {
        let mut matcher = TransactionMatcher::new(1000); // 1000ms timeout

        // Query: Slave 1, FC 0x03, Start 100, Qty 2 at t = 10,000 us
        let query_adu = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadHoldingRegistersQuery {
                start_addr: 100,
                quantity: 2,
            },
            crc16: 0,
        };
        assert_eq!(matcher.ingest_modbus_frame(&query_adu, 10_000), None);

        // Response: Slave 1, FC 0x03, Bytes: [0x12, 0x34, 0x56, 0x78] at t = 25,000 us (15ms RTT)
        let resp_adu = ModbusRtuAdu {
            slave_id: 1,
            pdu: ModbusPdu::ReadResponse {
                function_code: 0x03,
                byte_count: 4,
                data: vec![0x12, 0x34, 0x56, 0x78],
            },
            crc16: 0,
        };

        let tx = matcher
            .ingest_modbus_frame(&resp_adu, 25_000)
            .expect("Matched transaction");

        assert_eq!(tx.slave_id, 1);
        assert_eq!(tx.function_code, 0x03);
        assert_eq!(tx.start_address, 100);
        assert_eq!(tx.quantity, 2);
        assert_eq!(tx.latency_us, 15_000);
        assert_eq!(tx.register_values.len(), 2);
        assert_eq!(tx.register_values[0], (100, 0x1234));
        assert_eq!(tx.register_values[1], (101, 0x5678));
    }
}
