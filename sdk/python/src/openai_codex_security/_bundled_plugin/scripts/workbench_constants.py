"""Shared constants for the Codex Security workbench."""

import argparse

MODES = ("diff", "standard", "deep")
DIFF_TARGET_KINDS = ("working_tree", "commit", "range")
PHASES = ("preflight", "threat_model", "discovery", "validation", "attack_path", "reporting")
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
PATCH_ARTIFACT_MAX_BYTES = 2 * 1024 * 1024
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
MAX_CAPABILITY_PREFLIGHT_INPUT_JSON_BYTES = 160_000
MAX_CAPABILITY_PREFLIGHT_PERSISTED_JSON_BYTES = 180_000
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


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
