//! `fp-store`
//!
//! In-memory bounded circular capture buffer and trace storage for `field-probe`.

use fp_core::RawBusEvent;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Bounded in-memory event buffer storing sliding window of raw bus traffic.
#[derive(Debug, Clone)]
pub struct CaptureBuffer {
    capacity: usize,
    buffer: Arc<RwLock<VecDeque<RawBusEvent>>>,
}

impl CaptureBuffer {
    /// Create buffer with maximum capacity of events
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            buffer: Arc::new(RwLock::new(VecDeque::with_capacity(capacity))),
        }
    }

    /// Push an event into the capture ring buffer, dropping oldest when at capacity
    pub async fn push(&self, event: RawBusEvent) {
        let mut guard = self.buffer.write().await;
        if guard.len() >= self.capacity {
            guard.pop_front();
        }
        guard.push_back(event);
    }

    /// Return count of currently buffered events
    pub async fn len(&self) -> usize {
        self.buffer.read().await.len()
    }

    /// Check if buffer is empty
    pub async fn is_empty(&self) -> bool {
        self.buffer.read().await.is_empty()
    }

    /// Retrieve snapshot of all stored events
    pub async fn snapshot(&self) -> Vec<RawBusEvent> {
        self.buffer.read().await.iter().cloned().collect()
    }

    /// Query events within a specific microsecond time interval [start_us, end_us]
    pub async fn query_time_window(&self, start_us: u64, end_us: u64) -> Vec<RawBusEvent> {
        self.buffer
            .read()
            .await
            .iter()
            .filter(|ev| ev.timestamp_us >= start_us && ev.timestamp_us <= end_us)
            .cloned()
            .collect()
    }

    /// Clear all events from the buffer
    pub async fn clear(&self) {
        self.buffer.write().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fp_core::{CanFrame, LinkParams};

    #[tokio::test]
    async fn test_capture_buffer_capacity_eviction() {
        let buf = CaptureBuffer::new(3);
        assert!(buf.is_empty().await);

        for i in 1..=5 {
            let ev = RawBusEvent::new_can_rx(
                "can0",
                i * 1000,
                LinkParams::Auto,
                CanFrame::new_standard(0x100, &[i as u8]),
            );
            buf.push(ev).await;
        }

        assert_eq!(buf.len().await, 3);
        let items = buf.snapshot().await;
        assert_eq!(items.len(), 3);
        // Oldest (1000, 2000) evicted, 3000, 4000, 5000 remain
        assert_eq!(items[0].timestamp_us, 3000);
        assert_eq!(items[2].timestamp_us, 5000);

        let window = buf.query_time_window(3500, 4500).await;
        assert_eq!(window.len(), 1);
        assert_eq!(window[0].timestamp_us, 4000);
    }
}
