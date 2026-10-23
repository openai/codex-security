"""Classify source bytes for the remaining Python workbench Git snapshots."""

DEFAULT_PREVIEW_READ_BYTES = 64 * 1024
_UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")


def _decode_source(data: bytes) -> str:
    encoding = "utf-16" if data.startswith(_UTF16_BOMS) else "utf-8-sig"
    return data.decode(encoding, errors="ignore")


def is_binary_sample(data: bytes) -> bool:
    if data.startswith(_UTF16_BOMS):
        return "\0" in _decode_source(data)
    return b"\0" in data
