/// Calculate Shannon entropy in bits per byte (0.0 to 8.0).
/// Payloads with entropy > 7.2 bits/byte typically indicate encryption or compression.
pub fn calculate_shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0f32;

    for &count in &counts {
        if count > 0 {
            let p = (count as f32) / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if a payload likely contains encrypted or compressed data.
pub fn is_high_entropy_payload(data: &[u8], threshold: f32) -> bool {
    calculate_shannon_entropy(data) >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy_for_repeated_bytes() {
        let zeroes = vec![0x00; 128];
        assert_eq!(calculate_shannon_entropy(&zeroes), 0.0);
    }

    #[test]
    fn test_high_entropy_detection() {
        // Uniformly distributed pseudorandom bytes have entropy close to 8.0
        let mut pseudo_random = Vec::with_capacity(256);
        for i in 0..256 {
            pseudo_random.push(i as u8);
        }
        let entropy = calculate_shannon_entropy(&pseudo_random);
        assert!((entropy - 8.0).abs() < 0.01);
        assert!(is_high_entropy_payload(&pseudo_random, 7.2));
    }
}
