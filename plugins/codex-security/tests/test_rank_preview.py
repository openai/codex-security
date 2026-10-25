from __future__ import annotations

import sys
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
from rank_preview import DEFAULT_PREVIEW_BYTES, preview_for, preview_for_bytes


@pytest.fixture(
    params=[("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")],
    ids=["utf16-le", "utf16-be"],
)
def utf16_encoding(request: pytest.FixtureRequest) -> tuple[str, bytes]:
    return request.param


def test_preview_for_decodes_bom_marked_utf16(
    tmp_path: Path, utf16_encoding: tuple[str, bytes]
) -> None:
    encoding, bom = utf16_encoding
    source = "Write-Output 'café 😀'\n"
    path = tmp_path / "source.ps1"
    data = bom + source.encode(encoding)
    path.write_bytes(data)
    expected = (source.strip(), False)

    assert preview_for(path, DEFAULT_PREVIEW_BYTES) == expected
    assert preview_for_bytes(data, DEFAULT_PREVIEW_BYTES) == expected
    assert preview_for_bytes(source.encode("utf-8"), DEFAULT_PREVIEW_BYTES) == expected


@pytest.mark.parametrize(
    "data",
    [
        b"header\0payload",
        b"\xff\xfe" + "text\0binary".encode("utf-16-le"),
        b"\xfe\xff" + "text\0binary".encode("utf-16-be"),
        "unmarked utf16".encode("utf-16-le"),
    ],
    ids=["generic-binary", "utf16-le-nul", "utf16-be-nul", "no-bom"],
)
def test_preview_for_rejects_binary_source_bytes(tmp_path: Path, data: bytes) -> None:
    path = tmp_path / "source.ps1"
    path.write_bytes(data)

    assert preview_for(path, DEFAULT_PREVIEW_BYTES) == ("", True)
    assert preview_for_bytes(data, DEFAULT_PREVIEW_BYTES) == ("", True)


def test_preview_for_handles_utf16_surrogate_at_sample_boundary(
    tmp_path: Path, utf16_encoding: tuple[str, bytes]
) -> None:
    encoding, bom = utf16_encoding
    source = "a" * 2046 + "😀\nWrite-Output 'done'\n"
    path = tmp_path / "source.ps1"
    data = bom + source.encode(encoding)
    path.write_bytes(data)

    assert preview_for(path, 8192) == (source.strip(), False)
    assert preview_for_bytes(data, 8192) == (source.strip(), False)


def test_preview_for_bounds_utf16_source_at_incomplete_character(
    tmp_path: Path, utf16_encoding: tuple[str, bytes]
) -> None:
    encoding, bom = utf16_encoding
    source = "a" * 32766 + "😀\nWrite-Output 'outside preview'\n"
    path = tmp_path / "source.ps1"
    path.write_bytes(bom + source.encode(encoding))

    assert preview_for(path, 128, max_read_bytes=64 * 1024) == ("a" * 128, False)


def test_preview_for_ignores_incomplete_utf16_tail(
    tmp_path: Path, utf16_encoding: tuple[str, bytes]
) -> None:
    encoding, bom = utf16_encoding
    source = "Write-Output 'café'"
    path = tmp_path / "source.ps1"
    data = bom + source.encode(encoding) + b"\0"
    path.write_bytes(data)

    assert preview_for(path, DEFAULT_PREVIEW_BYTES) == (source, False)
    assert preview_for_bytes(data, DEFAULT_PREVIEW_BYTES) == (source, False)


class BudgetedReader(BytesIO):
    def __init__(self, data: bytes, limit: int) -> None:
        super().__init__(data)
        self.limit = limit
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        assert 0 <= size <= self.limit - self.bytes_read
        data = super().read(size)
        self.bytes_read += len(data)
        return data


@pytest.mark.parametrize(
    ("filename", "nul_offset", "limit"),
    [("payload.bin", 0, 4096), ("payload.py", 4096, 64 * 1024)],
    ids=["initial-sample", "after-initial-sample"],
)
def test_preview_for_bounds_binary_reads(filename: str, nul_offset: int, limit: int) -> None:
    reader = BudgetedReader(b"x" * nul_offset + b"\0" + b"x" * limit, limit)
    with patch.object(Path, "open", return_value=reader):
        assert preview_for(Path(filename), DEFAULT_PREVIEW_BYTES) == ("", True)
    assert reader.bytes_read > nul_offset


@pytest.mark.parametrize("max_read_bytes", [None, 1024, 4096, 4097, 128 * 1024])
def test_preview_for_bounds_large_text_reads(max_read_bytes: int | None) -> None:
    limit = 64 * 1024 if max_read_bytes is None else max_read_bytes
    line = b"# source comment\n"
    reader = BudgetedReader(line * (limit // len(line) + 1), limit)
    with patch.object(Path, "open", return_value=reader):
        if max_read_bytes is None:
            preview, binary = preview_for(Path("large.py"), 128)
        else:
            preview, binary = preview_for(Path("large.py"), 128, max_read_bytes=max_read_bytes)

    assert reader.bytes_read == limit
    assert not binary
    assert preview
    assert len(preview.encode("utf-8")) <= 128


@pytest.mark.parametrize("max_read_bytes", [0, -1])
def test_preview_for_rejects_nonpositive_read_limit(max_read_bytes: int) -> None:
    with patch.object(Path, "open", side_effect=AssertionError("unexpected file read")):
        with pytest.raises(ValueError, match="max_read_bytes must be positive"):
            preview_for(Path("source.py"), 128, max_read_bytes=max_read_bytes)


@pytest.mark.parametrize(
    ("filename", "prefix", "suffix", "expected"),
    [
        ("source.py", b"def visible():\n    value = (", b"1)\n", "def visible():\n    value = ("),
        ("source.css", b"body { color: red; }\n\xf0\x9f", b"\x98\x80", "body { color: red; }"),
        ("source.css", b"body { color: red; }\n", b"\0binary", "body { color: red; }"),
    ],
)
def test_preview_for_uses_only_the_bounded_prefix(
    tmp_path: Path, filename: str, prefix: bytes, suffix: bytes, expected: str
) -> None:
    source = tmp_path / filename
    source.write_bytes(prefix + suffix)

    assert preview_for(source, 128, max_read_bytes=len(prefix)) == (expected, False)


def generate_preview(
    tmp_path: Path, filename: str, source: str, *, preview_bytes: int | None = None
) -> str:
    source_path = tmp_path / filename
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(source, encoding="utf-8")
    preview, is_binary = preview_for(
        source_path,
        DEFAULT_PREVIEW_BYTES if preview_bytes is None else preview_bytes,
    )
    assert not is_binary
    return preview


def test_small_source_is_complete(tmp_path: Path) -> None:
    source = (
        "\n\n# Source context\n"
        + "\n".join(f"setting_{index} = {index}" for index in range(24))
        + '\n\ndef handle(request):\n    text = "two  spaces"\n'
        + '    return subprocess.run(request.args["cmd"], shell=True)\n\n'
    )
    assert len(source.strip().encode("utf-8")) < DEFAULT_PREVIEW_BYTES

    preview = generate_preview(tmp_path, "entrypoint", source)

    assert preview == source.strip()
    assert preview_for_bytes(source.encode("utf-8"), DEFAULT_PREVIEW_BYTES) == (
        preview,
        False,
    )


@pytest.mark.parametrize("large", [False, True], ids=["complete", "sampled"])
def test_source_preview_preserves_retained_whitespace(tmp_path: Path, large: bool) -> None:
    retained = '    value = "two  spaces\tand\u0085a separator"  \n    return value  '
    source = "\n \t\n" + retained
    if large:
        source += "\n# " + "x" * DEFAULT_PREVIEW_BYTES
    source += "\n \t\n"

    preview = generate_preview(tmp_path, "source.py", source)

    if large:
        assert preview.startswith(retained + "\n")
        assert len(preview.encode("utf-8")) <= DEFAULT_PREVIEW_BYTES
    else:
        assert preview == retained


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"], ids=["lf", "crlf", "cr"])
def test_source_preview_normalizes_newlines(tmp_path: Path, newline: str) -> None:
    expected = 'def handle():\n    text = "two  spaces"\n\n    return text'
    data = (expected.replace("\n", newline) + newline).encode("utf-8")
    path = tmp_path / "source.py"
    path.write_bytes(data)

    assert preview_for(path, DEFAULT_PREVIEW_BYTES) == (expected, False)
    assert preview_for_bytes(data, DEFAULT_PREVIEW_BYTES) == (expected, False)


@pytest.mark.parametrize("preview_bytes", [0, -1])
def test_nonpositive_preview_budget_returns_no_source(preview_bytes: int) -> None:
    assert preview_for_bytes(b"value = 1\n", preview_bytes) == ("", False)


def test_empty_source_preview(tmp_path: Path) -> None:
    assert generate_preview(tmp_path, "empty.py", "\n \t\n") == ""


def test_large_source_preview_preserves_head_and_tail(tmp_path: Path) -> None:
    source = (
        "function first() { return count / total; }\n"
        + ("// " + "é" * 128 + "\n") * 100
        + "function last() {}\n"
    )
    path = tmp_path / "example.js"
    path.write_text(source, encoding="utf-8")

    preview, binary = preview_for(path, DEFAULT_PREVIEW_BYTES)

    assert binary is False
    assert len(preview.encode("utf-8")) <= DEFAULT_PREVIEW_BYTES
    assert "function first()" in preview
    assert "function last()" in preview
    assert "..." in preview


def test_source_preview_ignores_utf8_bom(tmp_path: Path) -> None:
    source = b"def first():\n    pass\n\ndef second():\n    pass\n"
    path = tmp_path / "example.py"
    path.write_bytes(b"\xef\xbb\xbf" + source)

    expected = preview_for_bytes(source, DEFAULT_PREVIEW_BYTES)
    assert expected == (source.decode("utf-8").strip(), False)
    assert preview_for(path, DEFAULT_PREVIEW_BYTES) == expected


def test_large_source_preview_samples_nonblank_lines(tmp_path: Path) -> None:
    source = "\n\n".join(f"line_{index:02d} {{ color: red; }}" for index in range(40))

    preview = generate_preview(tmp_path, "styles.css", source, preview_bytes=700)

    assert preview.splitlines() == [
        *(f"line_{index:02d} {{ color: red; }}" for index in range(12)),
        "...",
        *(
            f"line_{index:02d} {{ color: red; }}"
            for index in (12, 15, 18, 21, 24, 27, 30, 33, 36, 39)
        ),
    ]


def test_preview_byte_budget_preserves_sampled_tail_and_valid_unicode(tmp_path: Path) -> None:
    source = "\n".join(f"line_{index:02d} {'😀' * 20}" for index in range(40))

    preview = generate_preview(tmp_path, "styles.css", source, preview_bytes=220)

    assert len(preview.encode("utf-8")) <= 220
    assert "..." in preview
    assert "line_39" in preview


def test_literal_elision_line_respects_tiny_byte_budget(tmp_path: Path) -> None:
    preview = generate_preview(tmp_path, "styles.css", "...", preview_bytes=2)

    assert preview == ".."


@pytest.mark.parametrize(("prefix", "preview_bytes"), [("line", 25), ("😀", 30), ("    line", 80)])
def test_tiny_preview_budget_retains_source(
    tmp_path: Path, prefix: str, preview_bytes: int
) -> None:
    source = "\n".join(f"{prefix}_{index:02d}" for index in range(40))

    preview = generate_preview(tmp_path, "source.txt", source, preview_bytes=preview_bytes)

    assert preview.startswith(f"{prefix}_00")
    assert source.startswith(preview)
    assert len(preview.encode("utf-8")) <= preview_bytes
