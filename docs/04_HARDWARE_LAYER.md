# 04. Hardware Layer (fp-hal)

> **Topic:** The Hardware Abstraction Layer and deterministic synthetic replay interface.

---

## 1. Description

The `fp-hal` crate provides a unified async interface for bus hardware.  
It supports physical serial ports, native CAN sockets, and recorded files.  
Every interface enforces the `SafetyTier::PassiveListenOnly` invariant on startup.

---

## 2. Replay Architecture

The `ReplayInterface` reads synthetic `.pcap` and `.candump` captures.  
It broadcasts events through an async channel at microsecond intervals.  
This allows testing algorithms in CI without physical adapters.

![Replay HAL Architecture](./assets/hal_replay.svg)

---

## 3. The BusInterface Trait

All hardware drivers implement the `BusInterface` trait:

```rust
#[async_trait]
pub trait BusInterface: Send + Sync {
    fn capabilities(&self) -> AdapterCapabilities;
    fn current_safety_tier(&self) -> SafetyTier;
    async fn set_link_params(&mut self, params: &LinkParams) -> Result<(), HalError>;
    async fn set_safety_tier(&mut self, tier: SafetyTier) -> Result<(), HalError>;
    fn subscribe_rx(&self) -> broadcast::Receiver<RawBusEvent>;
    async fn transmit(&mut self, frame: OutboundFrame, permit: &SafetyPermit) -> Result<(), HalError>;
}
```

---

## 4. Transmission Safety Rules

1. If the current tier is `PassiveListenOnly`, `transmit()` must fail immediately.
2. If the permit is expired, `transmit()` must fail immediately.
3. If the permit scope does not match the target, `transmit()` must fail.
4. Valid transmissions emit an event with `Direction::Tx` on the broadcast stream.
