"""Shared constants for the Codex Security workbench."""

import argparse
import os
import sys
from pathlib import Path

MODES = ("diff", "standard", "deep")
DIFF_TARGET_KINDS = ("working_tree", "commit", "range")
PHASES = ("preflight", "threat_model", "discovery", "validation", "attack_path", "reporting")
PHASE_PROGRESS_UNITS = (
    "checks",
    "threat_surfaces",
    "review_receipts",
    "candidate_findings",
    "validated_findings",
    "report_artifacts",
)
FINDING_SEVERITIES = ("critical", "high", "medium", "low", "informational")
FINDING_STATUSES = ("open", "closed")
FINDING_CLOSE_REASONS = ("already_fixed", "wont_fix", "false_positive")
REMEDIATION_STATES = (
    "idle",
    "requested",
    "generated",
    "applied",
    "verifying",
    "verified",
    "failed",
    "superseded",
)
REMEDIATION_UPDATE_STATES = ("generated", "applied", "verifying", "verified", "failed")
REMEDIATION_PENDING_ACTIONS = ("generate", "apply", "verify")
EXPORT_FORMATS = ("csv", "json", "sarif")
ARTIFACTS = {
    "coverage": "coverage.json",
    "findings": "findings.json",
    "manifest": "scan-manifest.json",
    "markdownReport": "report.md",
}
SQLITE_RETRY_ATTEMPTS = 5
CLAIM_LEASE_SECONDS = 120
DELIVERED_ACTION_LEASE_SECONDS = 900
PATCH_PREVIEW_BYTES = 16_000
FINDINGS_RESULT_LIMIT = 20
FINDINGS_PAGE_MAX = 20
FINDING_DETAILS_PREVIEW_BYTES = 16_000
FINDING_ROOT_CAUSE_PREVIEW_BYTES = 2_000
FINDING_VALIDATION_PREVIEW_BYTES = 3_000
FINDING_ATTACK_PATH_PREVIEW_BYTES = 4_000
FINDING_CODE_EVIDENCE_LIMIT = 4
FINDING_CODE_EVIDENCE_SNIPPET_BYTES = 1_500
FINDING_EVIDENCE_EXCERPT_BYTES = 8_000
FINDING_LOCATIONS_LIMIT = 8
FINDING_TITLE_BYTES = 512
FINDING_SUMMARY_BYTES = 2_000
FINDING_REMEDIATION_BYTES = 2_000
FINDING_LOCATION_PATH_BYTES = 2_048
FINDING_LOCATION_ROLE_BYTES = 128
FINDING_ABSOLUTE_PATH_BYTES = 4_096
FINDING_LEVEL_BYTES = 128
GIT_REPOSITORY_ENVIRONMENT = (
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
)
EMPTY_GIT_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _protected_repository_root(target: Path) -> Path:
    root = target.resolve()
    if root.is_file():
        root = root.parent
    protected = root
    for ancestor in (root, *root.parents):
        try:
            (ancestor / ".git").lstat()
        except FileNotFoundError:
            continue
        protected = ancestor
    return protected


def trusted_git_executable(protected_root: Path) -> str | None:
    """Return the host-selected Git executable without searching ``PATH``."""
    configured = os.environ.get("CODEX_SECURITY_GIT")
    if not configured:
        return None

    candidate = Path(configured)
    if not candidate.is_absolute():
        raise SystemExit("CODEX_SECURITY_GIT must name an absolute trusted executable.")

    try:
        invocation = Path(os.path.abspath(candidate))
        canonical = candidate.resolve(strict=True)
        repository = _protected_repository_root(protected_root)
    except (OSError, RuntimeError):
        return None

    windows = sys.platform == "win32"
    native_windows_suffixes = {".exe", ".com"}
    if (
        not canonical.is_file()
        or not os.access(canonical, os.F_OK if windows else os.X_OK)
        or (
            windows
            and (
                candidate.suffix.lower() not in native_windows_suffixes
                or canonical.suffix.lower() in {".bat", ".cmd"}
            )
        )
    ):
        return None
    if any(path == repository or repository in path.parents for path in (invocation, canonical)):
        raise SystemExit("CODEX_SECURITY_GIT must stay outside the protected repository.")
    return str(invocation)


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
