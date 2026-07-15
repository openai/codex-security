"""Command-line argument parsing for the Codex Security workbench."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import deep_scan_workbench as deep_scan
import workbench_remediation as remediation
from workbench_constants import (
    DIFF_TARGET_KINDS,
    EXPORT_FORMATS,
    FINDING_CLOSE_REASONS,
    FINDING_STATUSES,
    FINDINGS_PAGE_MAX,
    MODES,
    PHASES,
    REMEDIATION_UPDATE_STATES,
)


def parse_args(description: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=description)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_workspace = subparsers.add_parser("create-workspace")
    create_workspace.add_argument("--workspace-id", required=True)
    create_workspace.add_argument("--thread-id")
    create_workspace.add_argument("--target-path")
    create_workspace.add_argument("--target-title")
    create_workspace.add_argument("--target-summary")
    create_workspace.add_argument("--user-context")
    create_preflight = create_workspace.add_mutually_exclusive_group()
    create_preflight.add_argument("--capability-preflight-json")
    create_preflight.add_argument("--capability-preflight-json-file", type=Path)
    create_workspace.add_argument("--scope")
    create_workspace.add_argument("--mode", choices=MODES, default="standard")
    create_workspace.add_argument("--diff-target-kind", choices=DIFF_TARGET_KINDS)
    create_workspace.add_argument("--diff-base-revision")
    create_workspace.add_argument("--diff-head-revision")
    create_workspace.add_argument("--diff-content-digest")

    get_workspace = subparsers.add_parser("get-workspace")
    get_workspace.add_argument("--workspace-id", required=True)
    get_workspace.add_argument("--thread-id")

    get_latest_workspace = subparsers.add_parser("get-latest-workspace")
    get_latest_workspace.add_argument("--thread-id", required=True)

    list_workspace_scans = subparsers.add_parser("list-workspace-scans")
    list_workspace_scans.add_argument("--workspace-id", required=True)
    list_workspace_scans.add_argument("--offset", type=non_negative_int, default=0)
    list_workspace_scans.add_argument("--limit", type=workspace_scan_limit, default=20)

    inspect_target = subparsers.add_parser("inspect-target")
    inspect_target.add_argument("--target-path", required=True)

    inspect_setup = subparsers.add_parser("inspect-setup")
    inspect_setup.add_argument("--target-path", required=True)
    inspect_setup.add_argument("--scope", required=True)
    inspect_setup.add_argument("--mode", choices=MODES, required=True)
    inspect_setup.add_argument("--diff-target-kind", choices=DIFF_TARGET_KINDS)
    inspect_setup.add_argument("--diff-base-revision")
    inspect_setup.add_argument("--diff-head-revision")
    inspect_setup.add_argument("--diff-content-digest")

    begin_diff_resolution = subparsers.add_parser("begin-diff-resolution")
    begin_diff_resolution.add_argument("--workspace-id", required=True)
    begin_diff_resolution.add_argument("--request-id", required=True)
    begin_diff_resolution.add_argument("--target-path", required=True)
    begin_diff_resolution.add_argument("--user-context", required=True)

    cancel_diff_resolution = subparsers.add_parser("cancel-diff-resolution")
    cancel_diff_resolution.add_argument("--workspace-id", required=True)
    cancel_diff_resolution.add_argument("--request-id", required=True)

    set_diff_target = subparsers.add_parser("set-diff-target")
    set_diff_target.add_argument("--workspace-id", required=True)
    set_diff_target.add_argument("--request-id", required=True)
    set_diff_target.add_argument("--target-summary", required=True)
    set_diff_target.add_argument("--diff-target-kind", choices=DIFF_TARGET_KINDS, required=True)
    set_diff_target.add_argument("--diff-base-revision")
    set_diff_target.add_argument("--diff-head-revision")
    set_diff_target.add_argument("--diff-content-digest")

    save_workspace = subparsers.add_parser("save-workspace")
    save_workspace.add_argument("--workspace-id", required=True)
    save_workspace.add_argument("--target-path", required=True)
    save_workspace.add_argument("--scope", required=True)
    save_workspace.add_argument("--mode", choices=MODES, required=True)
    save_workspace.add_argument("--target-summary")
    save_workspace.add_argument("--user-context")
    save_workspace.add_argument("--diff-target-kind", choices=DIFF_TARGET_KINDS)
    save_workspace.add_argument("--diff-base-revision")
    save_workspace.add_argument("--diff-head-revision")
    save_workspace.add_argument("--diff-content-digest")

    set_capability_preflight = subparsers.add_parser("set-capability-preflight")
    set_capability_preflight.add_argument("--workspace-id", required=True)
    set_capability_preflight.add_argument("--checked-target-path", required=True)
    set_capability_preflight.add_argument("--checked-mode", choices=MODES, required=True)
    set_preflight = set_capability_preflight.add_mutually_exclusive_group(required=True)
    set_preflight.add_argument("--capability-preflight-json")
    set_preflight.add_argument("--capability-preflight-json-file", type=Path)

    start_scan = subparsers.add_parser("start-scan")
    start_scan.add_argument("--workspace-id", required=True)
    start_scan.add_argument("--scan-root")

    deep_scan.register_subcommands(subparsers, positive_int)

    get_scan = subparsers.add_parser("get-scan")
    get_scan.add_argument("--scan-id", required=True)
    get_scan.add_argument("--occurrence-id")

    list_findings = subparsers.add_parser("list-findings")
    list_findings.add_argument("--scan-id", required=True)
    list_findings.add_argument("--offset", type=non_negative_int, default=0)
    list_findings.add_argument("--limit", type=positive_int, default=FINDINGS_PAGE_MAX)

    update_progress = subparsers.add_parser("update-progress")
    update_progress.add_argument("--scan-id", required=True)
    update_progress.add_argument("--phase", choices=PHASES)
    update_progress.add_argument("--review-items-total", type=non_negative_int)
    update_progress.add_argument("--review-items-completed", type=non_negative_int)
    update_progress.add_argument("--reportable-findings-count", type=non_negative_int)
    update_progress.add_argument("--deep-review-pass", type=positive_int)

    complete_scan = subparsers.add_parser("complete-scan")
    complete_scan.add_argument("--scan-id", required=True)

    cancel_scan = subparsers.add_parser("cancel-scan")
    cancel_scan.add_argument("--scan-id", required=True)
    cancel_scan.add_argument("--thread-id", required=True)

    fail_scan = subparsers.add_parser("fail-scan")
    fail_scan.add_argument("--scan-id", required=True)
    fail_scan.add_argument("--message", required=True)

    mark_handoff_delivered = subparsers.add_parser("mark-handoff-delivered")
    mark_handoff_delivered.add_argument("--scan-id", required=True)
    mark_handoff_delivered.add_argument("--claim-token", required=True)
    mark_handoff_delivered.add_argument("--thread-id")

    claim_handoff_delivery = subparsers.add_parser("claim-handoff-delivery")
    claim_handoff_delivery.add_argument("--scan-id", required=True)
    claim_handoff_delivery.add_argument("--claim-token", required=True)
    claim_handoff_delivery.add_argument("--take-over-stale", action="store_true")

    release_handoff_delivery = subparsers.add_parser("release-handoff-delivery")
    release_handoff_delivery.add_argument("--scan-id", required=True)
    release_handoff_delivery.add_argument("--claim-token", required=True)

    set_finding_triage = subparsers.add_parser("set-finding-triage")
    set_finding_triage.add_argument("--occurrence-id", required=True)
    set_finding_triage.add_argument("--status", choices=FINDING_STATUSES, required=True)
    set_finding_triage.add_argument("--close-reason", choices=FINDING_CLOSE_REASONS)
    set_finding_triage.add_argument("--note")

    request_finding_remediation = subparsers.add_parser("request-finding-remediation")
    request_finding_remediation.add_argument("--occurrence-id", required=True)
    request_finding_remediation.add_argument("--request-id", required=True)
    request_finding_remediation.add_argument("--action-token", required=True)

    request_finding_remediation_action = subparsers.add_parser("request-finding-remediation-action")
    request_finding_remediation_action.add_argument("--occurrence-id", required=True)
    request_finding_remediation_action.add_argument("--request-id", required=True)
    request_finding_remediation_action.add_argument(
        "--expected-version", type=positive_int, required=True
    )
    request_finding_remediation_action.add_argument(
        "--action", choices=("apply", "verify"), required=True
    )
    request_finding_remediation_action.add_argument("--action-token", required=True)

    claim_finding_remediation_resend = subparsers.add_parser("claim-finding-remediation-resend")
    claim_finding_remediation_resend.add_argument("--occurrence-id", required=True)
    claim_finding_remediation_resend.add_argument("--request-id", required=True)
    claim_finding_remediation_resend.add_argument("--action-token", required=True)

    mark_finding_remediation_delivered = subparsers.add_parser("mark-finding-remediation-delivered")
    mark_finding_remediation_delivered.add_argument("--occurrence-id", required=True)
    mark_finding_remediation_delivered.add_argument("--request-id", required=True)
    mark_finding_remediation_delivered.add_argument("--action-token", required=True)

    release_finding_remediation_claim = subparsers.add_parser("release-finding-remediation-claim")
    release_finding_remediation_claim.add_argument("--occurrence-id", required=True)
    release_finding_remediation_claim.add_argument("--request-id", required=True)
    release_finding_remediation_claim.add_argument("--action-token", required=True)

    remediation.register_cancel_finding_remediation_request(subparsers)

    set_finding_remediation = subparsers.add_parser("set-finding-remediation")
    set_finding_remediation.add_argument("--occurrence-id", required=True)
    set_finding_remediation.add_argument("--request-id", required=True)
    set_finding_remediation.add_argument("--action-token", required=True)
    set_finding_remediation.add_argument("--expected-version", type=positive_int, required=True)
    set_finding_remediation.add_argument(
        "--state", choices=REMEDIATION_UPDATE_STATES, required=True
    )
    set_finding_remediation.add_argument("--summary")
    set_finding_remediation.add_argument("--patch-path")
    set_finding_remediation.add_argument("--patch-digest")
    set_finding_remediation.add_argument("--base-revision")
    set_finding_remediation.add_argument("--verification-summary")

    export_findings = subparsers.add_parser("export-findings")
    export_findings.add_argument("--scan-id", required=True)
    export_findings.add_argument("--format", choices=EXPORT_FORMATS, required=True)

    subparsers.add_parser("database-info")
    return parser.parse_args()


def non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("expected a non-negative integer")
    return parsed


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return parsed


def workspace_scan_limit(value: str) -> int:
    parsed = positive_int(value)
    if parsed > 100:
        raise argparse.ArgumentTypeError("expected an integer between 1 and 100")
    return parsed


if __name__ == "__main__":
    parse_args(__doc__)
