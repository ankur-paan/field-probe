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

Automotive and industrial CAN frames are limited to 8 payload bytes in classic CAN. Large diagnostic messages use ISO 15765-2 transport reassembly:

| PCI Frame Type | Nibble | Function | Payload Capacity |
| :--- | :--- | :--- | :--- |
| **Single Frame (SF)** | `0x0_` | Unfragmented message | 1 to 7 bytes |
| **First Frame (FF)** | `0x1_` | Initiates segmented transfer; announces total length | 6 bytes (first chunk) |
| **Consecutive Frame (CF)** | `0x2_` | Transfers payload chunks with sequence counter (`0..15`) | Up to 7 bytes per frame |
| **Flow Control (FC)** | `0x3_` | Flow status, block size, and separation time (STmin) | Protocol control |

The `IsoTpReassembler` manages per-CAN-ID assembly sessions, validates sequence continuity, rejects unexpected consecutive frames, and discards stale sessions after configurable inactivity timeouts.

---

## 5. ISO 14229 (UDS) Diagnostic Service Dissector

The UDS dissector parses reassembled ISO-TP payloads into structured diagnostic services:

- **Diagnostic Session Control (`0x10`):** Default, Programming, and Extended Diagnostic sessions with P2/P2* server timing parameters.
- **Read Data By Identifier (`0x22` / `0x62`):** Extracts 16-bit DIDs (e.g., VIN, software version, sensor readings).
- **Security Access (`0x27` / `0x67`):** Parses seed request and key send handshakes.
- **Tester Present (`0x3E` / `0x7E`):** Audits keep-alive signals and suppress-positive-response flags.
- **Negative Response (`0x7F`):** Identifies rejected Service ID (SID) and maps Negative Response Codes (NRC) such as `ConditionsNotCorrect` (`0x22`), `SecurityAccessDenied` (`0x33`), or `ServiceNotSupportedInActiveSession` (`0x7F`).

---

## 6. IEEE 1815 (DNP3) Substation Dissector

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

## 7. SAE J1939 Transport Protocol (BAM & CMDT)

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

## 8. Modbus Device Identification (FC 0x2B / 0x0E)

Modbus Encapsulated Interface (MEI Type `0x0E`) provides non-intrusive vendor and model interrogation:

- **Query Parsing:** Dissects Read Device ID codes (`0x01` Basic, `0x02` Regular, `0x03` Extended, `0x04` Specific) and initial Object IDs.
- **Response Parsing:** Decodes conformity levels, continuation flags (`MoreFollows`), and extracts key identity objects:
  - Object `0x00`: VendorName
  - Object `0x01`: ProductCode
  - Object `0x02`: MajorMinorRevision
  - Object `0x03`..`0x06`: VendorUrl, ProductName, ModelName, UserApplicationName

---

## 9. Standards Compliance Auditing

Inspired by Zeek ICSNPP, the compliance auditor compares real-time bus traffic against specification constraints:

- **Timing Violations:** Flags responses received faster than the standard turnaround time ($3.5 \text{ character times}$) or exceeding slave timeout limits.
- **Addressing Violations:** Detects requests spanning beyond valid 16-bit register address space ($start + quantity > 65536$).
- **Quantity Limits:** Flags queries requesting illegal register counts ($> 125$ registers or $> 2000$ coils).
- **Physical Link Health:** Measures transmission bit error rate, frame CRC error counts, and bus overload metrics.
