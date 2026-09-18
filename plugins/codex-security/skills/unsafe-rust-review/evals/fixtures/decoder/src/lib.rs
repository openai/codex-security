/// Extracts the supplied value.
///
/// # Safety
/// `value` must be `Some`.
pub unsafe fn extract(value: Option<u8>) -> u8 {
    unsafe { value.unwrap_unchecked() }
}

pub fn decode_byte(input: &[u8]) -> u8 {
    unsafe { extract(input.first().copied()) }
}
