"""Read optional checkout owner suggestions from the packaged verifier."""

import json
import os
import subprocess
from pathlib import Path
from typing import Any


def read_owner_results(
    findings: list[dict[str, Any]], repository: Path, revision: str, warnings: list[str]
) -> tuple[str, bool]:
    """Return verifier output, including complete records emitted before a timeout."""
    helper = Path(__file__).resolve().parents[1] / "mcp" / "scan-owners.mjs"
    try:
        result = subprocess.run(
            [os.environ["CODEX_MCP_NODE_PATH"], str(helper), str(repository), revision],
            input=json.dumps(findings),
            capture_output=True,
            encoding="utf-8",
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        warnings.append("Optional owner verification timed out")
        return (error.stdout or b"").decode("utf-8", errors="replace"), False
    if result.returncode:
        warnings.append(
            f"Optional owner verification stopped: {result.stderr.strip() or result.returncode}"
        )
    return result.stdout, result.returncode == 0
