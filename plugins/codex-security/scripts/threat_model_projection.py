#!/usr/bin/env python3
"""Render saved structured or Markdown threat models without running analysis."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def _markdown_content(model: dict[str, Any]) -> str | None:
    content = model.get("content")
    if model.get("format") == "markdown" and isinstance(content, str) and content.strip():
        return content
    return None


def threat_model_body(model: dict[str, Any], *, heading_level: int = 2) -> str:
    """Keep authored Markdown intact, including summaries from older scans."""
    content = _markdown_content(model)
    if content is not None:
        return content
    summary = model.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        if model.get("format") == "markdown":
            raise ValueError("threatModel.content: expected non-empty Markdown")
        raise ValueError("threatModel.summary: expected a non-empty string")
    sections = [summary]
    for heading, key in (
        ("Assets", "assets"),
        ("Trust Boundaries", "trustBoundaries"),
        ("Attacker Capabilities", "attackerCapabilities"),
        ("Security Objectives", "securityObjectives"),
        ("Assumptions", "assumptions"),
    ):
        values = model.get(key)
        if not isinstance(values, list) or not values:
            continue
        for index, value in enumerate(values):
            if not isinstance(value, str):
                raise ValueError(f"threatModel.{key}[{index}]: expected a string")
        sections.append(f"{'#' * heading_level} {heading}")
        sections.append("\n".join("- " + value.replace("\n", "\n  ") for value in values))
    return "\n\n".join(sections)


def _scope_lines(scope: dict[str, Any], label: str) -> list[str]:
    lines = [f"- {label}: {', '.join(scope.get('includePaths', [])) or 'none'}"]
    if scope.get("excludePaths"):
        lines.append(f"- {label} exclusions: {', '.join(scope['excludePaths'])}")
    if scope.get("summary"):
        lines.append(f"- {label} description: {scope['summary']}")
    return lines


def render_threat_model(model: dict[str, Any], provenance: dict[str, Any] | None = None) -> bytes:
    """Render a portable document with authored content and recorded provenance."""
    body = threat_model_body(model)
    if _markdown_content(model) is None:
        body = "# Threat Model\n\n" + body
    provenance = provenance or {}
    footer = ["---", "", "## Saved Model Context", ""]
    for key, label in (
        ("source", "Source"),
        ("scanId", "Scan"),
        ("target", "Target"),
        ("revision", "Revision"),
        ("snapshotDigest", "Snapshot"),
        ("status", "Result status"),
    ):
        if provenance.get(key):
            footer.append(f"- {label}: {provenance[key]}")
    footer.append(f"- Model origin: {model.get('origin', 'not recorded')}")
    model_scope = model.get("scope")
    footer.extend(
        _scope_lines(model_scope, "Model scope")
        if isinstance(model_scope, dict)
        else ["- Model scope: not recorded"]
    )
    scan_scope = provenance.get("scanScope")
    if isinstance(scan_scope, dict):
        footer.extend(_scope_lines(scan_scope, "Scan scope"))
    if provenance.get("provisional"):
        footer.extend(["", "This is a provisional model saved before successful completion."])
    return (body + ("\n" if body.endswith("\n") else "\n\n") + "\n".join(footer) + "\n").encode(
        "utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-json-stdin", action="store_true", required=True)
    parser.parse_args()
    try:
        payload = json.load(sys.stdin)
        sys.stdout.buffer.write(
            render_threat_model(payload["threatModel"], payload.get("provenance"))
        )
    except (KeyError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
