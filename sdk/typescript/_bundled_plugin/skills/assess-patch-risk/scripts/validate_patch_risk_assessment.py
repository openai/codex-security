#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SCHEMA = PLUGIN_ROOT / "schemas" / "patch-risk-assessment.schema.json"


def read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{path}: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a patch risk assessment against its shipped schema."
    )
    parser.add_argument("assessment", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    arguments = parser.parse_args()

    try:
        schema = read_json(arguments.schema)
        payload = read_json(arguments.assessment)
        if not isinstance(schema, dict):
            raise ValueError(f"{arguments.schema}: schema root must be an object")
        Draft202012Validator.check_schema(schema)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.absolute_path))
    if errors:
        for error in errors:
            print(f"{error.json_path}: {error.message}", file=sys.stderr)
        return 1

    print(f"valid: {arguments.assessment}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
