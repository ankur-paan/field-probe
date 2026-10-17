# 08. Field CLI and Workflows (fp-cli)

> **Topic:** Terminal user interface and field wiring diagnostic procedures.

---

## 1. Description

The `fp-cli` crate provides the native binary and Terminal User Interface (TUI).  
Engineers use `fp` directly on a rugged field laptop without network access.  
The interface displays live bus load, framing errors, and discovered registers.

---

## 2. Cabinet Connection Topology

Connect the USB dongle to the differential communication pair in passive tap mode:

![Field Cabinet Wiring](./assets/field_wiring.svg)

---

## 3. Step-by-Step Field Diagnostic Procedure

Follow these steps when diagnosing an unknown cabinet:

1. **Connect Hardware:**  
   Attach the USB-to-RS485 or USB-to-CAN dongle to the field laptop.  
   Attach the differential probe clips to the active bus lines (A and B, or CAN_H and CAN_L).

2. **Launch field-probe in Passive Mode:**  
   Execute the CLI binary:
   ```bash
   fp
   ```
   Verify the adapter status reports `SafetyTier::PassiveListenOnly`.

3. **Allow 10 Seconds for Auto-Lock:**  
   The engine scans candidate baud rates and bit-timings.  
   The engine locks automatically when CRC errors decrease to zero.

4. **Review Discovered Topology:**  
   Examine active node IDs, polling frequencies, and register values in the terminal table.

5. **Execute Compliance Audit:**  
   Review physical link warnings (e.g., termination resistor missing or wire polarity swapped).
