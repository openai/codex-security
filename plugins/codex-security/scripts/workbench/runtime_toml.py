"""Load TOML using the supported Python runtime."""

import sys

__all__ = ["tomllib"]

if sys.version_info < (3, 10):
    raise SystemExit(
        "Codex Security requires Python 3.10 or later. Update the Codex managed runtime "
        "or set PYTHON to a supported interpreter, then restart Codex."
    )

try:
    import tomllib as tomllib
except ModuleNotFoundError:  # Python 3.10
    try:
        import tomli as tomllib
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "Codex Security requires tomli with Python 3.10. Install tomli for the selected "
            "interpreter or set PYTHON to Python 3.11 or later, then restart Codex."
        ) from exc
