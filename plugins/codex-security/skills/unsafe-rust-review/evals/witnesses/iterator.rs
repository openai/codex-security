struct Empty;

impl Iterator for Empty {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (1, Some(1))
    }
}

impl ExactSizeIterator for Empty {}

fn main() {
    let _ = review_fixture::first(Empty);
}
