pub fn first<I: ExactSizeIterator<Item = u8>>(mut values: I) -> Option<u8> {
    if values.len() == 0 {
        None
    } else {
        Some(unsafe { values.next().unwrap_unchecked() })
    }
}
