pub fn first_byte(bytes: &[u8]) -> Option<u8> {
    if bytes.is_empty() {
        None
    } else {
        Some(unsafe { *bytes.get_unchecked(0) })
    }
}
