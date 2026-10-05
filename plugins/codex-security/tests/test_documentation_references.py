from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"!?\[[^\]\n]*\]\(([^)\n]+)\)")


def markdown_without_fenced_code(text: str) -> str:
    lines: list[str] = []
    fence: str | None = None
    for line in text.splitlines():
        match = re.match(r"^\s*(\x60{3,}|~~~+)", line)
        if match:
            marker = match.group(1)[0]
            if fence is None:
                fence = marker
            elif fence == marker:
                fence = None
            lines.append("")
            continue
        lines.append("" if fence else line)
    return "\n".join(lines)


def markdown_links(text: str) -> list[str]:
    text = markdown_without_fenced_code(text)
    text = re.sub(r"\x60[^\x60\n]*\x60", "", text)
    return [match.group(1).strip() for match in LINK_RE.finditer(text)]


def heading_slug(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"<[^>]*>", "", text)
    text = re.sub(r"[\x60*_~]", "", text)
    text = re.sub(r"[^\w\s-]", "", text.strip().lower(), flags=re.UNICODE)
    return re.sub(r"\s+", "-", text.strip())


def markdown_anchors(text: str) -> set[str]:
    text = markdown_without_fenced_code(text)
    counts: dict[str, int] = {}
    anchors: set[str] = set()
    for line in text.splitlines():
        heading = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
        if heading:
            base = heading_slug(heading.group(1))
            if base:
                count = counts.get(base, 0)
                counts[base] = count + 1
                anchors.add(base if count == 0 else f"{base}-{count}")
        for anchor in re.finditer(
            r"""<a\s+[^>]*(?:id|name)=["']([^"']+)["'][^>]*>""",
            line,
            re.IGNORECASE,
        ):
            anchors.add(anchor.group(1).lower())
    return anchors


def normalized_destination(destination: str) -> str:
    destination = destination.strip()
    if destination.startswith("<") and ">" in destination:
        close = destination.find(">")
        destination = destination[1:close] + destination[close + 1 :]
    return re.sub(r"""\s+["'][^"']*["']\s*$""", "", destination).strip()


def documentation_reference_errors(root: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    for source in sorted(root.rglob("*.md")):
        for raw_destination in markdown_links(source.read_text(encoding="utf-8")):
            destination = normalized_destination(raw_destination)
            if (
                not destination
                or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", destination)
                or destination.startswith("//")
            ):
                continue

            path_text, separator, fragment = destination.partition("#")
            path_text = unquote(path_text)
            fragment = unquote(fragment).lower() if separator else ""
            target = (source.parent / path_text).resolve() if path_text else source.resolve()
            try:
                target.relative_to(root)
            except ValueError:
                continue

            if not target.exists():
                errors.append(
                    f"{source.relative_to(root)}: missing local target {destination}"
                )
                continue

            if fragment and target.is_file() and target.suffix.lower() == ".md":
                anchors = markdown_anchors(target.read_text(encoding="utf-8"))
                if fragment not in anchors:
                    errors.append(
                        f"{source.relative_to(root)}: missing anchor #{fragment} "
                        f"in {target.relative_to(root)}"
                    )
    return errors


def test_documentation_reference_checker_accepts_supported_links(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    nested = docs / "nested"
    nested.mkdir(parents=True)
    (docs / "target.md").write_text(
        "# Target Heading\n"
        "# Duplicate\n"
        "# Duplicate\n"
        '<a id="manual-anchor"></a>\n',
        encoding="utf-8",
    )
    tick = chr(96)
    (nested / "source.md").write_text(
        "[heading](../target.md#target-heading)\n"
        "[duplicate](../target.md#duplicate-1)\n"
        "[explicit](../target.md#manual-anchor)\n"
        "[external](https://example.com/docs)\n"
        "[app](app://example)\n"
        f"{tick}[inline code](missing.md){tick}\n"
        f"{tick * 3}md\n[fenced code](missing.md)\n{tick * 3}\n",
        encoding="utf-8",
    )

    assert documentation_reference_errors(docs) == []


def test_documentation_reference_checker_reports_missing_references(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "target.md").write_text("# Existing\n", encoding="utf-8")
    (docs / "source.md").write_text(
        "[missing path](missing.md)\n"
        "[missing anchor](target.md#absent)\n",
        encoding="utf-8",
    )

    assert documentation_reference_errors(docs) == [
        "source.md: missing local target missing.md",
        "source.md: missing anchor #absent in target.md",
    ]


def test_plugin_markdown_references_resolve() -> None:
    assert documentation_reference_errors(PLUGIN_ROOT) == []
