"""Validate the exact public package versions selected for a dependency scan."""

from __future__ import annotations

import argparse
import json
import re

_PACKAGE = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")
_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def selected_dependencies(value: object) -> list[dict[str, str | None]]:
    """Return a normalized nonempty selection, rejecting unresolved versions."""
    if not isinstance(value, list) or not 1 <= len(value) <= 20:
        raise ValueError("Select between 1 and 20 exact public npm package versions.")
    selected: list[dict[str, str | None]] = []
    for entry in value:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"ecosystem", "registry", "package", "oldVersion", "newVersion"}
            or entry.get("ecosystem") != "npm"
            or entry.get("registry") != "https://registry.npmjs.org"
            or entry.get("oldVersion") is not None
            or not isinstance(entry.get("package"), str)
            or _PACKAGE.fullmatch(entry["package"]) is None
            or not isinstance(entry.get("newVersion"), str)
            or _VERSION.fullmatch(entry["newVersion"]) is None
        ):
            raise ValueError(
                "Selected dependencies must be exact versions from the public npm registry."
            )
        if entry in selected:
            raise ValueError("Selected dependencies must not contain duplicate package versions.")
        selected.append(dict(entry))
    return sorted(selected, key=lambda entry: (entry["package"] or "", entry["newVersion"] or ""))


def encoded_selected_dependencies(args: argparse.Namespace) -> str | None:
    """Encode selected coordinates for native and CLI scan persistence."""
    value = getattr(args, "selected_dependencies", None)
    if value is None:
        return None
    mode = getattr(args, "dependency_mode", None) or getattr(args, "mode", None)
    if mode != "full_dependency":
        raise SystemExit("Selected dependencies require a full dependency scan.")
    try:
        selected = selected_dependencies(json.loads(value))
    except (ValueError, TypeError) as exc:
        raise SystemExit(str(exc)) from exc
    return json.dumps(selected, separators=(",", ":"), sort_keys=True)


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
