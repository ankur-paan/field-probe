# 05. Dissectors and Compliance (fp-dissectors)

> **Topic:** Zero-panic protocol dissectors, multi-packet transport reassembly, and standards compliance auditing.

---

## 1. System Overview

The `fp-dissectors` crate parses raw byte streams and CAN frames from untrusted, noisy physical lines.  
It provides structured dissection for:
- **Modbus RTU & Modbus TCP:** Including Encapsulated Interface Transport (MEI FC `0x2B` / `0x0E`) for device identification.
- **IEEE 1815 (DNP3):** Data Link, Transport, and Application layers with FT3 CRC-16 verification for substation RS-485 networks.
- **ISO 15765-2 (ISO-TP):** Multi-frame CAN transport reassembly with sequence number checking and timeout eviction.
- **ISO 14229 (UDS):** Unified Diagnostic Services session control, data identifier queries, security access, and negative response auditing.
- **SAE J1939:** Single-frame PGN extraction plus multi-packet Transport Protocol (BAM & CMDT) reassembly for VIN, Component ID, and DM1 Active DTCs.
- **CANopen:** NMT network management state transitions, Heartbeat, and SDO expedited upload/download protocols.
- **BACnet MS/TP:** Master-Slave/Token-Passing token ring arbitration and application frame parsing.

---

## 2. Zero-Panic Rule

Industrial line noise creates truncated and malformed byte sequences.  
A dissector must never panic during execution.  
Engineers must enforce these rules in all parser paths:
- Never use `.unwrap()` or `.expect()` in production paths.
- Never use direct slice indexing `buf[i..j]`.
- Always use `nom` combinators or checked slice operations (`split_at_checked`, `.get()`).
- Verify framing lengths and byte counts before parsing inner payloads.

---

## 3. Sliding-Window CRC Scanner

The scanner searches a noisy serial byte buffer for valid Modbus frames:

![Sliding-Window CRC Scanner](./assets/crc_scanner.svg)

1. Test candidate sub-slices of length 4 to 256 bytes.
2. Verify the trailing 2 bytes against the computed Modbus RTU CRC-16.
3. When a match is found, extract the Application Data Unit (ADU).
4. Slide the window by one byte if the checksum fails.

---

## 4. ISO 15765-2 (ISO-TP) Transport Reassembler

Automotive and industrial CAN frames are limited to 8 payload bytes in classic CAN and 64 bytes in CAN-FD. Large diagnostic messages use ISO 15765-2 transport reassembly:

| PCI Frame Type | Nibble | Function | Payload Capacity |
| :--- | :--- | :--- | :--- |
| **Single Frame (SF)** | `0x0_` | Unfragmented message (Classical CAN: 1 to 7 bytes; CAN-FD: `0x00` escape up to 62 bytes) | 1 to 62 bytes |
| **First Frame (FF)** | `0x1_` | Initiates segmented transfer; announces 12-bit length (`0x1N`) or CAN-FD 32-bit length (`0x10 0x00`) | Up to $2^{32}-1$ bytes |
| **Consecutive Frame (CF)** | `0x2_` | Transfers payload chunks with sequence counter (`0..15`) | Up to 63 bytes per frame |
| **Flow Control (FC)** | `0x3_` | Flow status (`CTS = 0`, `Wait = 1`, `Overflow = 2`), Block Size (`BS`), and Separation Time (`STmin`: ms or µs) | Protocol control |

The `IsoTpReassembler` manages per-CAN-ID assembly sessions across all four standard addressing schemas:
- **Normal 11-Bit:** Direct arbitration ID mapping (e.g., `0x7E0` request / `0x7E8` response).
- **Normal Fixed 29-Bit:** Priority (3-bit), Target Address / PS (8-bit), and Source Address / SA (8-bit). Supports Physical addressing (`0x18DA...`) and Functional broadcast (`0x18DB...`).
- **Extended 11-Bit:** Transmits Target Address (`N_TA`) in payload byte 0.
- **Mixed 29-Bit:** Transmits Address Extension (`N_AE`) in payload byte 0 with Format `0xCE` (`0x18CE...`).

---

## 5. ISO 14229 (UDS) Diagnostic Service Dissector

The UDS dissector parses reassembled ISO-TP payloads into structured diagnostic services:

- **Diagnostic Session Control (`0x10` / `0x50`):** Default, Programming, and Extended Diagnostic sessions with P2/P2* server timing parameters.
- **ECU Reset (`0x11`):** Hard reset, key-off-on reset, soft reset, and enable rapid power shutdown.
- **Clear Diagnostic Information (`0x14`):** Purges stored emission and manufacturer fault records.
- **Read DTC Information (`0x19` / `0x59`):** Extracts 3-byte DTCs (2-byte SAE code + 1-byte Failure Mode Indicator [FMI] / Fault Type Byte [FTB]) and 1-byte status mask (`testFailed`, `pending`, `confirmed`, `warningIndicator`).
- **Read & Write Data By Identifier (`0x22`, `0x2E`, `0x62`):** Extracts 16-bit DIDs with automatic name lookup across standard automotive DIDs (`0xF180` BootSoftwareIdentification, `0xF186` ActiveDiagnosticSession, `0xF187` SparePartNumber, `0xF189` SoftwareVersion, `0xF190` VIN).
- **Security Access (`0x27` / `0x67`):** Parses seed request and key send handshakes.
- **Input / Output Control (`0x2F` / `0x6F`):** Audits actuator overrides, short-term adjustments, and returns control to ECU.
- **Routine Control (`0x31` / `0x71`):** Monitors startRoutine (`0x01`), stopRoutine (`0x02`), and requestRoutineResults (`0x03`) across 16-bit Routine Identifiers (e.g., `0x0203` Check Memory, `0x0202` Erase Memory).
- **Firmware Flashing & Data Transfer (`0x34`–`0x37`):** Dissects RequestDownload (`0x34`), RequestUpload (`0x35`), TransferData (`0x36`) with block sequence counter auditing, and RequestTransferExit (`0x37`).
- **Tester Present (`0x3E` / `0x7E`):** Audits keep-alive signals and suppress-positive-response flags.
- **Negative Response (`0x7F`):** Identifies rejected Service ID (SID) and maps Negative Response Codes (NRC) such as `ConditionsNotCorrect` (`0x22`), `SecurityAccessDenied` (`0x33`), or `ServiceNotSupportedInActiveSession` (`0x7F`).

---

## 6. SAE J1979 / ISO 15031-5 (OBD-II) Dissector

The OBD-II engine provides automated decoding of vehicle powertrain diagnostics across Modes $01 through $0A:

- **Mode $01 (Show Current Data):** Translates raw PID bytes into scaled physical units:
  - `0x0C` Engine RPM: $\frac{A \times 256 + B}{4}\text{ rpm}$
  - `0x0D` Vehicle Speed: $A\text{ km/h}$
  - `0x05` Engine Coolant Temperature: $A - 40\text{ }^\circ\text{C}$
  - `0x0F` Intake Air Temperature: $A - 40\text{ }^\circ\text{C}$
  - `0x10` MAF Air Flow Rate: $\frac{A \times 256 + B}{100}\text{ g/s}$
  - `0x04` Calculated Engine Load / `0x11` Throttle Position: $\frac{A}{2.55}\text{ \%}$
  - `0x1F` Run Time Since Engine Start: $A \times 256 + B\text{ s}$
  - `0x42` Control Module Voltage: $\frac{A \times 256 + B}{1000}\text{ V}$
- **Mode $02 (Show Freeze Frame):** Captures snapshot PID records logged when a DTC triggered.
- **Mode $03 / $07 / $0A (DTC Extraction):** Parses 2-byte trouble codes into standard 5-character SAE J2012 codes (`P0300`, `U0100`, `C0035`, `B0001`):
  - Prefix determined by bits 7-6 (`00 = P` Powertrain, `01 = C` Chassis, `10 = B` Body, `11 = U` Network).
  - Code type determined by bits 5-4 (`0` or `2` = SAE Standard, `1` or `3` = Manufacturer Specific).
- **Mode $04 (Clear Diagnostic Information):** Erases DTCs and freeze frame data.
- **Mode $09 (Request Vehicle Information):** Decodes ASCII vehicle metadata, including 17-character VIN (`0x02`), Calibration ID / CALID (`0x04`), CVN (`0x06`), and ECU Name (`0x0A`).

---

## 7. IEEE 1815 (DNP3) Substation Dissector

DNP3 is widely deployed across electric utility, water, and oil/gas SCADA networks. The dissector supports:

1. **Data Link Layer:**
   - Detects standard start octets `0x05 0x64`.
   - Validates the 10-byte header with FT3 CRC-16 (`polynomial 0xA646`, inverted).
   - Verifies 16-bit CRCs across successive 16-byte user data blocks.
2. **Transport Layer:**
   - Decodes Transport Header sequence numbering and FIR/FIN fragmentation flags.
3. **Application Layer:**
   - Classifies Application Function Codes: `Read (0x01)`, `Write (0x02)`, `Select (0x03)`, `Operate (0x04)`, `DirectOperate (0x05)`, `Response (0x81)`, and `UnsolicitedResponse (0x82)`.
   - Extracts Internal Indications (IIN) 16-bit bitfield on slave responses.
   - Parses Object Groups and Variations (Binary Inputs Grp 1/2, Binary Outputs Grp 10/12, Counters Grp 20/21, Analog Inputs Grp 30/32, Analog Outputs Grp 40/41, and Class Data Grp 60).

---

## 8. SAE J1939 Transport Protocol (BAM & CMDT)

Heavy-duty commercial vehicles and machinery transmit parameters exceeding 8 bytes via J1939 Transport Protocol:

- **Broadcast Announce Message (BAM):**
  - Advertised on Connection Management PGN 60416 (`0x00EC00`) with Global Destination `0xFF`.
  - Ingests Data Transfer packets on PGN 60160 (`0x00EB00`) with monotonic sequence numbers.
- **Connection Mode Data Transfer (CMDT):**
  - Point-to-point transfer negotiated via RTS/CTS handshakes.
- **Decoded Parameter Groups:**
  - **VIN (PGN 65260 / `0x00FEEC`):** Reassembles 17-character ASCII Vehicle Identification Number.
  - **Component Identification (PGN 65259 / `0x00FEEB`):** Extracts Make, Model, Serial Number, and Unit ID delimiters (`*`).
  - **DM1 Active Trouble Codes (PGN 65226 / `0x00FECA`):** Decodes Protect Lamp, Amber Warning Lamp, Red Stop Lamp, Suspect Parameter Number (SPN), Failure Mode Identifier (FMI), and occurrence counts.

---

## 9. Modbus Device Identification (FC 0x2B / 0x0E)

Modbus Encapsulated Interface (MEI Type `0x0E`) provides non-intrusive vendor and model interrogation:

- **Query Parsing:** Dissects Read Device ID codes (`0x01` Basic, `0x02` Regular, `0x03` Extended, `0x04` Specific) and initial Object IDs.
- **Response Parsing:** Decodes conformity levels, continuation flags (`MoreFollows`), and extracts key identity objects:
  - Object `0x00`: VendorName
  - Object `0x01`: ProductCode
  - Object `0x02`: MajorMinorRevision
  - Object `0x03`..`0x06`: VendorUrl, ProductName, ModelName, UserApplicationName

---

## 10. Standards Compliance Auditing

Inspired by Zeek ICSNPP, the compliance auditor compares real-time bus traffic against specification constraints:

- **Timing Violations:** Flags responses received faster than the standard turnaround time ($3.5 \text{ character times}$) or exceeding slave timeout limits.
- **Addressing Violations:** Detects requests spanning beyond valid 16-bit register address space ($start + quantity > 65536$).
- **Quantity Limits:** Flags queries requesting illegal register counts ($> 125$ registers or $> 2000$ coils).
- **Physical Link Health:** Measures transmission bit error rate, frame CRC error counts, and bus overload metrics.
