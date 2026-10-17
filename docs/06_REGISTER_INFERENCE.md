# 06. Register Inference Engine (fp-inference)

> **Topic:** Semantic register decoding and physical signal identification.

---

## 1. Description

Industrial field devices do not transmit data type schemas over the wire.  
A Modbus response contains only unformatted 16-bit registers.  
The `fp-inference` crate evaluates raw values across all common encodings.  
It identifies whether a register pair contains integer, floating-point, or ASCII data.

---

## 2. Multi-Representation Decoding

The decoder tests adjacent 16-bit registers across four word orders:

![Word Order Permutations](./assets/word_orders.svg)

1. **ABCD (Big-Endian):** Standard IEEE 754 format.
2. **CDAB (Word-Swapped):** Most common Modbus floating-point encoding.
3. **BADC (Byte-Swapped):** Mid-big endian encoding.
4. **DCBA (Little-Endian):** True little-endian format.

---

## 3. Temporal Plausibility Scoring

The engine tracks register value changes over successive polling cycles:
- Physical variables (temperature, pressure, voltage) change smoothly over time.
- If order `CDAB` yields 23.41 &rarr; 23.45 &rarr; 23.48, confidence is high (0.98).
- If order `ABCD` yields -1.42e28 &rarr; 8.11e-12, confidence is low.
- The engine ranks the most plausible engineering interpretation.

---

## 4. Delta Isolation Mode

The operator triggers `start_diff_capture` and modifies a physical control:
- The engine isolates only the bits that mutated during the window.
- High-frequency counters and noise are filtered out.
- The system returns the exact register address controlling that function.
