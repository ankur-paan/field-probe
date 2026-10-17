//! NIST SP 800-38B and RFC 4493 AES-128-CMAC and AUTOSAR SecOC verification engine
//! Implemented in zero-dependency pure Rust for industrial and automotive bus security.

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn xtime(x: u8) -> u8 {
    (x << 1) ^ if (x & 0x80) != 0 { 0x1b } else { 0x00 }
}

/// Expand 16-byte AES-128 key into 176-byte round keys (11 rounds of 16 bytes)
pub fn aes128_key_expansion(key: &[u8; 16]) -> [u8; 176] {
    let mut round_keys = [0u8; 176];
    round_keys[..16].copy_from_slice(key);

    let mut bytes_generated = 16;
    let mut rcon_iteration = 0;
    let mut temp = [0u8; 4];

    while bytes_generated < 176 {
        temp.copy_from_slice(&round_keys[bytes_generated - 4..bytes_generated]);

        if bytes_generated % 16 == 0 {
            // RotWord
            temp.rotate_left(1);
            // SubWord
            for b in &mut temp {
                *b = SBOX[*b as usize];
            }
            // Rcon XOR
            temp[0] ^= RCON[rcon_iteration];
            rcon_iteration += 1;
        }

        for item in &temp {
            round_keys[bytes_generated] = round_keys[bytes_generated - 16] ^ item;
            bytes_generated += 1;
        }
    }

    round_keys
}

/// Encrypt a single 16-byte block with AES-128
pub fn aes128_encrypt_block(block: &[u8; 16], round_keys: &[u8; 176]) -> [u8; 16] {
    let mut state = *block;

    // Initial round key addition
    for i in 0..16 {
        state[i] ^= round_keys[i];
    }

    // 9 main rounds
    for round in 1..10 {
        // SubBytes
        for b in &mut state {
            *b = SBOX[*b as usize];
        }

        // ShiftRows
        state = [
            state[0], state[5], state[10], state[15], state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7], state[12], state[1], state[6], state[11],
        ];

        // MixColumns
        let mut mixed = [0u8; 16];
        for c in 0..4 {
            let i = c * 4;
            let a0 = state[i];
            let a1 = state[i + 1];
            let a2 = state[i + 2];
            let a3 = state[i + 3];

            mixed[i] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
            mixed[i + 1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
            mixed[i + 2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
            mixed[i + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
        }
        state = mixed;

        // AddRoundKey
        let offset = round * 16;
        for i in 0..16 {
            state[i] ^= round_keys[offset + i];
        }
    }

    // Final round (Round 10, no MixColumns)
    for b in &mut state {
        *b = SBOX[*b as usize];
    }

    state = [
        state[0], state[5], state[10], state[15], state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7], state[12], state[1], state[6], state[11],
    ];

    for i in 0..16 {
        state[i] ^= round_keys[160 + i];
    }

    state
}

/// Left shift a 16-byte block by 1 bit for CMAC subkey derivation
fn left_shift_one(input: &[u8; 16]) -> ([u8; 16], u8) {
    let mut out = [0u8; 16];
    let mut overflow = 0u8;

    for i in (0..16).rev() {
        out[i] = (input[i] << 1) | overflow;
        overflow = (input[i] & 0x80) >> 7;
    }

    (out, overflow)
}

/// Derive subkeys K1 and K2 for AES-128-CMAC (RFC 4493)
pub fn derive_cmac_subkeys(key: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let round_keys = aes128_key_expansion(key);
    let zero_block = [0u8; 16];
    let l = aes128_encrypt_block(&zero_block, &round_keys);

    let (mut k1, msb_l) = left_shift_one(&l);
    if msb_l != 0 {
        k1[15] ^= 0x87;
    }

    let (mut k2, msb_k1) = left_shift_one(&k1);
    if msb_k1 != 0 {
        k2[15] ^= 0x87;
    }

    (k1, k2)
}

/// Compute AES-128-CMAC (RFC 4493) over an arbitrary byte sequence
pub fn aes128_cmac(key: &[u8; 16], message: &[u8]) -> [u8; 16] {
    let (k1, k2) = derive_cmac_subkeys(key);
    let round_keys = aes128_key_expansion(key);

    let block_count = if message.is_empty() {
        1
    } else {
        message.len().div_ceil(16)
    };

    let is_last_complete = !message.is_empty() && message.len().is_multiple_of(16);

    let mut state = [0u8; 16];

    for i in 0..(block_count - 1) {
        let chunk = &message[i * 16..(i + 1) * 16];
        for j in 0..16 {
            state[j] ^= chunk[j];
        }
        state = aes128_encrypt_block(&state, &round_keys);
    }

    // Process last block
    let mut last_block = [0u8; 16];
    if is_last_complete {
        let start = (block_count - 1) * 16;
        last_block.copy_from_slice(&message[start..start + 16]);
        for j in 0..16 {
            last_block[j] ^= k1[j];
        }
    } else {
        let start = if message.is_empty() {
            0
        } else {
            (block_count - 1) * 16
        };
        let remaining = message.len().saturating_sub(start);
        if remaining > 0 {
            last_block[..remaining].copy_from_slice(&message[start..]);
        }
        last_block[remaining] = 0x80; // Padding bit
        for j in 0..16 {
            last_block[j] ^= k2[j];
        }
    }

    for j in 0..16 {
        state[j] ^= last_block[j];
    }

    aes128_encrypt_block(&state, &round_keys)
}

/// Verify AUTOSAR Secure Onboard Communication (SecOC) MAC tag
///
/// Constructs authentic message: [DataID (2 bytes) | Payload (N bytes) | Freshness (4 bytes)]
/// Computes AES-128-CMAC and checks against truncated MAC tag in constant time.
pub fn verify_secoc_mac(
    key: &[u8; 16],
    data_id: u16,
    payload: &[u8],
    freshness_val: u32,
    expected_mac: &[u8],
) -> bool {
    let mut secured_data = Vec::with_capacity(2 + payload.len() + 4);
    secured_data.extend_from_slice(&data_id.to_be_bytes());
    secured_data.extend_from_slice(payload);
    secured_data.extend_from_slice(&freshness_val.to_be_bytes());

    let cmac_full = aes128_cmac(key, &secured_data);

    let tag_len = expected_mac.len().min(16);
    if tag_len == 0 {
        return false;
    }

    // Constant-time comparison
    let mut diff = 0u8;
    for i in 0..tag_len {
        diff |= cmac_full[i] ^ expected_mac[i];
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc4493_test_vectors() {
        // Test key from RFC 4493 Section 4
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];

        // Example 1: Empty message (length = 0)
        let cmac_0 = aes128_cmac(&key, &[]);
        let expected_0 = [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
            0x67, 0x46,
        ];
        assert_eq!(cmac_0, expected_0);

        // Example 2: 16-byte message
        let msg_16 = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let cmac_16 = aes128_cmac(&key, &msg_16);
        let expected_16 = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
            0x28, 0x7c,
        ];
        assert_eq!(cmac_16, expected_16);
    }

    #[test]
    fn test_secoc_verification() {
        let key = [0x55u8; 16];
        let data_id: u16 = 0x1020;
        let payload = [0x01, 0x02, 0x03, 0x04];
        let freshness: u32 = 42;

        let mut secured_data = Vec::new();
        secured_data.extend_from_slice(&data_id.to_be_bytes());
        secured_data.extend_from_slice(&payload);
        secured_data.extend_from_slice(&freshness.to_be_bytes());

        let full_cmac = aes128_cmac(&key, &secured_data);
        let truncated_mac = &full_cmac[..4]; // 32-bit SecOC truncated tag

        assert!(verify_secoc_mac(
            &key,
            data_id,
            &payload,
            freshness,
            truncated_mac
        ));

        // Corrupted MAC should fail
        let mut bad_mac = truncated_mac.to_vec();
        bad_mac[0] ^= 0x01;
        assert!(!verify_secoc_mac(
            &key, data_id, &payload, freshness, &bad_mac
        ));
    }
}
