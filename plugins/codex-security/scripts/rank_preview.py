"""Build bounded source previews for rank inputs regardless of language."""

from __future__ import annotations

import argparse
from bisect import bisect_right
from pathlib import Path

DEFAULT_PREVIEW_BYTES = 1024
DEFAULT_PREVIEW_READ_BYTES = 64 * 1024
PREVIEW_HEAD_LINES = 12
PREVIEW_SAMPLE_LINES = 10
_UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")


def _decode_source(data: bytes) -> str:
    encoding = "utf-16" if data.startswith(_UTF16_BOMS) else "utf-8-sig"
    return data.decode(encoding, errors="ignore")


def is_binary_sample(data: bytes) -> bool:
    if data.startswith(_UTF16_BOMS):
        return "\0" in _decode_source(data)
    return b"\0" in data


def is_binary_file(path: Path) -> bool:
    """Classify the whole file in bounded chunks."""
    try:
        with path.open("rb") as source:
            sample = source.read(DEFAULT_PREVIEW_READ_BYTES)
            if is_binary_sample(sample):
                return True
            bom = sample[:2] if sample.startswith(_UTF16_BOMS) else b""
            while chunk := source.read(DEFAULT_PREVIEW_READ_BYTES):
                # Even-sized reads preserve UTF-16 code-unit alignment and byte order.
                if is_binary_sample(bom + chunk) if bom else b"\0" in chunk:
                    return True
    except OSError:
        return True
    return False


def truncate_utf8(text: str, max_bytes: int) -> str:
    if max_bytes <= 0:
        return ""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def select_preview_lines(lines: list[str]) -> list[str]:
    nonblank = [line for line in lines if line.strip()]
    head = nonblank[:PREVIEW_HEAD_LINES]
    remainder = nonblank[PREVIEW_HEAD_LINES:]
    if len(remainder) <= PREVIEW_SAMPLE_LINES:
        return [*head, *remainder]

    last_index = len(remainder) - 1
    sampled = [
        remainder[index * last_index // (PREVIEW_SAMPLE_LINES - 1)]
        for index in range(PREVIEW_SAMPLE_LINES)
    ]
    return [*head, "...", *sampled]


def fit_preview_lines(lines: list[str], max_bytes: int) -> str:
    if not lines or max_bytes <= 0:
        return ""

    full_preview = "\n".join(lines)
    if len(full_preview.encode("utf-8")) <= max_bytes:
        return full_preview

    def render(line_bytes: int) -> str:
        return "\n".join(
            line if line == "..." else truncate_utf8(line, line_bytes) for line in lines
        )

    high = max(len(line.encode("utf-8")) for line in lines)
    limit = bisect_right(
        range(high + 1), max_bytes, key=lambda size: len(render(size).encode("utf-8"))
    )
    best = render(limit - 1) if limit else ""
    if best.strip() not in {"", "..."}:
        return best
    return truncate_utf8(full_preview, max_bytes)


def preview_for(
    path: Path, preview_bytes: int, *, max_read_bytes: int = DEFAULT_PREVIEW_READ_BYTES
) -> tuple[str, bool]:
    """Preview the first 64 KiB by default, including the binary-detection sample."""
    if max_read_bytes <= 0:
        raise ValueError("max_read_bytes must be positive")
    try:
        with path.open("rb") as source:
            sample = source.read(min(4096, max_read_bytes))
            if is_binary_sample(sample):
                return "", True
            remaining = source.read(max_read_bytes - len(sample))
            data = sample + remaining
    except OSError:
        return "", True
    return preview_for_bytes(data, preview_bytes)


def preview_for_bytes(data: bytes, preview_bytes: int) -> tuple[str, bool]:
    if is_binary_sample(data):
        return "", True
    lines = _decode_source(data).replace("\r\n", "\n").replace("\r", "\n").split("\n")
    start, end = 0, len(lines)
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1
    lines = lines[start:end]
    text = "\n".join(lines)
    if len(text.encode("utf-8")) <= preview_bytes:
        return text, False
    return fit_preview_lines(select_preview_lines(lines), preview_bytes), False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build bounded source previews for Codex Security rank inputs."
    )
    parser.parse_args()
