#!/usr/bin/env python3
"""Render saved structured or Markdown threat models without running analysis."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

_STRUCTURED_SECTIONS = (
    ("Assets", "assets"),
    ("Trust Boundaries", "trustBoundaries"),
    ("Attacker Capabilities", "attackerCapabilities"),
    ("Security Objectives", "securityObjectives"),
    ("Assumptions", "assumptions"),
)


def _is_structured_model(model: dict[str, Any]) -> bool:
    summary = model.get("summary")
    return (
        isinstance(summary, str)
        and bool(summary)
        and all(
            isinstance(values := model.get(key, []), list)
            and all(isinstance(value, str) and value for value in values)
            for _, key in _STRUCTURED_SECTIONS
        )
    )


def _markdown_content(model: dict[str, Any]) -> str | None:
    content = model.get("content")
    if model.get("format") == "markdown" and isinstance(content, str) and content.strip():
        return content
    return None


def threat_model_body(model: dict[str, Any]) -> str:
    """Keep authored Markdown intact, including summaries from older scans."""
    content = _markdown_content(model)
    if content is not None:
        # The structured schema permits legacy metadata as extension fields.
        if _is_structured_model(model):
            return content
        if "origin" in model and model["origin"] not in (
            "generated",
            "provided",
            "reconciled",
            "recovered",
        ):
            raise ValueError("threatModel.origin: unsupported value")
        if "scope" in model:
            scope = model["scope"]
            if not isinstance(scope, dict) or "includePaths" not in scope:
                raise ValueError("threatModel.scope: expected an object with includePaths")
            for key in ("includePaths", "excludePaths"):
                if key in scope and (
                    not isinstance(scope[key], list)
                    or not all(isinstance(path, str) and path for path in scope[key])
                ):
                    raise ValueError(
                        f"threatModel.scope.{key}: expected an array of non-empty strings"
                    )
            if "summary" in scope and (
                not isinstance(scope["summary"], str) or not scope["summary"]
            ):
                raise ValueError("threatModel.scope.summary: expected a non-empty string")
        return content
    summary = model.get("summary")
    if not isinstance(summary, str) or not summary:
        if model.get("format") == "markdown":
            raise ValueError("threatModel.content: expected non-empty Markdown")
        raise ValueError("threatModel.summary: expected a non-empty string")
    sections = [
        summary if summary.strip() else "No explicit canonical threat-model summary was recorded."
    ]
    for heading, key in _STRUCTURED_SECTIONS:
        values = model.get(key, [])
        if not isinstance(values, list):
            raise ValueError(f"threatModel.{key}: expected an array")
        if not values:
            continue
        for index, value in enumerate(values):
            if not isinstance(value, str) or not value:
                raise ValueError(f"threatModel.{key}[{index}]: expected a non-empty string")
        sections.append(f"## {heading}")
        sections.append("\n".join("- " + value.replace("\n", "\n  ") for value in values))
    return "\n\n".join(sections)


def _scope_lines(scope: Any, label: str, text: Callable[[Any, str], str]) -> list[str]:
    # Older structured models may use these extension names for unrelated data.
    included = scope.get("includePaths") if isinstance(scope, dict) else None
    if not isinstance(included, list) or not all(isinstance(path, str) for path in included):
        return [f"- {label}: not recorded"]
    lines = [f"- {label}: {text(', '.join(included), 'none')}"]
    excluded = scope.get("excludePaths")
    if isinstance(excluded, list) and excluded and all(isinstance(path, str) for path in excluded):
        lines.append(f"- {label} exclusions: {text(', '.join(excluded), 'none')}")
    summary = scope.get("summary")
    if isinstance(summary, str) and summary:
        lines.append(f"- {label} description: {text(summary, 'not recorded')}")
    return lines


def render_threat_model(model: dict[str, Any], provenance: dict[str, Any] | None = None) -> bytes:
    """Render a portable document with authored content and recorded provenance."""
    body = threat_model_body(model)
    if _markdown_content(model) is None:
        body = "# Threat Model\n\n" + body
    script = Path(__file__).resolve().with_name("report_projection.py")
    spec = importlib.util.spec_from_file_location("codex_security_report_projection", script)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load report projection helper: {script}")
    report = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(report)
    text = report._text
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
            footer.append(f"- {label}: {text(str(provenance[key]), 'not recorded')}")
    footer.append(
        f"- Model origin: {text(str(model.get('origin', 'not recorded')), 'not recorded')}"
    )
    footer.extend(_scope_lines(model.get("scope"), "Model scope", text))
    scan_scope = provenance.get("scanScope")
    if isinstance(scan_scope, dict):
        footer.extend(_scope_lines(scan_scope, "Scan scope", text))
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
