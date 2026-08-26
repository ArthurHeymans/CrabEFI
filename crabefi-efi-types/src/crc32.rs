/// Calculates the IEEE CRC-32 checksum of a byte slice.

///

/// # Examples

///

/// ```

/// assert_eq!(calculate(b"123456789"), 0xcbf4_3926);

/// ```
pub fn calculate(bytes: &[u8]) -> u32 {
    bytes.iter().copied().fold(u32::MAX, |crc, byte| {
        (0..8).fold(crc ^ u32::from(byte), |value, _| {
            (value >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(value & 1))
        })
    }) ^ u32::MAX
}

/// Calculate IEEE CRC-32 over bytes supplied by index.
pub fn calculate_with(len: usize, mut byte_at: impl FnMut(usize) -> u8) -> u32 {
    (0..len).fold(u32::MAX, |crc, index| {
        (0..8).fold(crc ^ u32::from(byte_at(index)), |value, _| {
            (value >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(value & 1))
        })
    }) ^ u32::MAX
}
