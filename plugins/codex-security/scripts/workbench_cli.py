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
    FINDING_SEVERITIES,
    FINDING_STATUSES,
    FINDINGS_PAGE_MAX,
    MODES,
    PHASE_PROGRESS_UNITS,
    PHASES,
    REMEDIATION_UPDATE_STATES,
)


def add_user_context(parser: argparse.ArgumentParser, *, required: bool = False) -> None:
    context = parser.add_mutually_exclusive_group(required=required)
    context.add_argument("--user-context")
    context.add_argument("--user-context-stdin", action="store_true")


def parse_args(description: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=description)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_workspace = subparsers.add_parser("create-workspace")
    create_workspace.add_argument("--workspace-id", required=True)
    create_workspace.add_argument("--thread-id")
    create_workspace.add_argument("--target-path")
    create_workspace.add_argument("--target-title")
    create_workspace.add_argument("--target-summary")
    add_user_context(create_workspace)
    create_workspace.add_argument("--scope")
    create_workspace.add_argument("--mode", choices=MODES, default="standard")
    create_workspace.add_argument("--diff-target-kind", choices=DIFF_TARGET_KINDS)
    create_workspace.add_argument("--diff-base-revision")
    create_workspace.add_argument("--diff-head-revision")
    create_workspace.add_argument("--diff-content-digest")

    get_workspace = subparsers.add_parser("get-workspace")
    get_workspace.add_argument("--workspace-id", required=True)
    get_workspace.add_argument("--thread-id")

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

    save_workspace = subparsers.add_parser("save-workspace")
    save_workspace.add_argument("--workspace-id", required=True)
    save_workspace.add_argument("--target-path", required=True)
    save_workspace.add_argument("--scope", required=True)
    save_workspace.add_argument("--mode", choices=MODES, required=True)
    save_workspace.add_argument("--target-summary")
    add_user_context(save_workspace)
    save_workspace.add_argument("--diff-target-kind", choices=DIFF_TARGET_KINDS)
    save_workspace.add_argument("--diff-base-revision")
    save_workspace.add_argument("--diff-head-revision")
    save_workspace.add_argument("--diff-content-digest")

    start_scan = subparsers.add_parser("start-scan")
    start_scan.add_argument("--workspace-id", required=True)
    start_scan.add_argument("--scan-root")
    start_scan.add_argument("--model")
    start_scan.add_argument("--reasoning-effort")

    start_prompt_only_scan = subparsers.add_parser("start-prompt-only-scan")
    start_prompt_only_scan.add_argument("--thread-id", required=True)
    start_prompt_only_scan.add_argument("--target-path", required=True)
    start_prompt_only_scan.add_argument("--scope", required=True)
    start_prompt_only_scan.add_argument("--mode", choices=("diff", "standard"), required=True)
    start_prompt_only_scan.add_argument("--target-summary")
    add_user_context(start_prompt_only_scan)
    start_prompt_only_scan.add_argument("--diff-target-kind", choices=DIFF_TARGET_KINDS)
    start_prompt_only_scan.add_argument("--diff-base-revision")
    start_prompt_only_scan.add_argument("--diff-head-revision")
    start_prompt_only_scan.add_argument("--diff-content-digest")
    start_prompt_only_scan.add_argument("--scan-root")
    start_prompt_only_scan.add_argument("--model")
    start_prompt_only_scan.add_argument("--reasoning-effort")

    start_headless_standard_scan = subparsers.add_parser("start-headless-standard-scan")
    start_headless_standard_scan.add_argument("--thread-id", required=True)
    start_headless_standard_scan.add_argument("--target-path", required=True)
    start_headless_standard_scan.add_argument("--scope", required=True)
    start_headless_standard_scan.add_argument("--target-summary")
    add_user_context(start_headless_standard_scan)
    start_headless_standard_scan.add_argument("--scan-root")
    start_headless_standard_scan.add_argument("--model")
    start_headless_standard_scan.add_argument("--reasoning-effort")
    start_headless_standard_scan.set_defaults(
        mode="standard",
        diff_target_kind=None,
        diff_base_revision=None,
        diff_head_revision=None,
        diff_content_digest=None,
    )

    deep_scan.register_subcommands(subparsers, positive_int)

    get_scan = subparsers.add_parser("get-scan")
    get_scan.add_argument("--scan-id", required=True)
    get_scan.add_argument("--occurrence-id")

    get_scan_feedback = subparsers.add_parser("get-scan-feedback")
    get_scan_feedback.add_argument("--scan-id", required=True)

    update_scan_context = subparsers.add_parser("update-scan-context")
    update_scan_context.add_argument("--scan-id", required=True)
    add_user_context(update_scan_context, required=True)
    update_scan_context_owner = update_scan_context.add_mutually_exclusive_group(required=True)
    update_scan_context_owner.add_argument("--workspace-id")
    update_scan_context_owner.add_argument("--thread-id")
    update_scan_context.add_argument("--claim-token")

    list_scans = subparsers.add_parser("list-scans")
    list_scans.add_argument("--query")
    list_scans.add_argument("--target-id")
    list_scans.add_argument("--status", choices=("running", "complete", "failed", "canceled"))
    list_scans.add_argument("--mode", choices=MODES)
    list_scans.add_argument("--repository")
    list_scans.add_argument("--scan-root")
    list_scans.add_argument("--offset", type=non_negative_int, default=0)
    list_scans.add_argument("--limit", type=positive_int)

    list_unmatched_scan_pairs = subparsers.add_parser("list-unmatched-scan-pairs")
    list_unmatched_scan_pairs.add_argument("--repository", required=True)
    list_unmatched_scan_pairs.add_argument("--force", action="store_true")

    register_cli_scan = subparsers.add_parser("register-cli-scan")
    register_cli_scan.add_argument("--scan-dir", required=True)
    register_cli_scan.add_argument("--repository", required=True)
    recipe = register_cli_scan.add_mutually_exclusive_group(required=True)
    recipe.add_argument("--recipe-json")
    recipe.add_argument("--recipe-json-stdin", action="store_true")
    recipe.add_argument("--registration-json-stdin", action="store_true")
    register_cli_scan.add_argument("--parent-scan-id")
    register_cli_scan.add_argument("--archive-existing", action="store_true")
    register_cli_scan.add_argument("--archived-scan-dir")

    set_scan_thread = subparsers.add_parser("set-scan-thread")
    set_scan_thread.add_argument("--scan-id", required=True)
    set_scan_thread.add_argument("--thread-id", required=True)

    get_scan_recipe = subparsers.add_parser("get-scan-recipe")
    get_scan_recipe.add_argument("--scan-id", required=True)

    compare_scans = subparsers.add_parser("compare-scans")
    compare_scans.add_argument("--before-scan-id", required=True)
    compare_scans.add_argument("--after-scan-id", required=True)
    compare_scans.add_argument("--include-matching-inputs", action="store_true")
    compare_scans.add_argument("--require-matches", action="store_true")

    save_scan_comparison = subparsers.add_parser("save-scan-comparison")
    save_scan_comparison.add_argument("--before-scan-id", required=True)
    save_scan_comparison.add_argument("--after-scan-id", required=True)
    matches = save_scan_comparison.add_mutually_exclusive_group(required=True)
    matches.add_argument("--matches-json")
    matches.add_argument("--matches-json-stdin", action="store_true")

    list_global_findings = subparsers.add_parser("list-global-findings")
    list_global_findings.add_argument("--query")
    list_global_findings.add_argument("--severity", choices=FINDING_SEVERITIES)
    list_global_findings.add_argument("--status", choices=FINDING_STATUSES)
    list_global_findings.add_argument("--target-id")
    list_global_findings.add_argument("--offset", type=non_negative_int, default=0)
    list_global_findings.add_argument("--limit", type=positive_int, default=FINDINGS_PAGE_MAX)
    list_repositories = subparsers.add_parser("list-repositories")
    list_repositories.add_argument("--query")
    list_repositories.add_argument("--target-id")
    list_repositories.add_argument("--status", choices=("scanned", "not_scanned", "open_findings"))
    list_repositories.add_argument("--offset", type=non_negative_int, default=0)
    list_repositories.add_argument("--limit", type=positive_int)

    list_findings = subparsers.add_parser("list-findings")
    list_findings.add_argument("--scan-id", required=True)
    list_findings.add_argument("--query")
    list_findings.add_argument("--severity", choices=FINDING_SEVERITIES)
    list_findings.add_argument("--status", choices=FINDING_STATUSES)
    list_findings.add_argument("--offset", type=non_negative_int, default=0)
    list_findings.add_argument("--limit", type=positive_int, default=FINDINGS_PAGE_MAX)

    update_progress = subparsers.add_parser("update-progress")
    update_progress.add_argument("--scan-id", required=True)
    update_progress.add_argument("--phase", choices=PHASES)
    update_progress.add_argument("--phase-items-total", type=non_negative_int)
    update_progress.add_argument("--phase-items-completed", type=non_negative_int)
    update_progress.add_argument("--phase-progress-unit", choices=PHASE_PROGRESS_UNITS)
    preflight_issues = update_progress.add_mutually_exclusive_group()
    preflight_issues.add_argument("--preflight-issues-json")
    preflight_issues.add_argument("--preflight-issues-json-stdin", action="store_true")
    update_progress.add_argument("--review-items-total", type=non_negative_int)
    update_progress.add_argument("--review-items-completed", type=non_negative_int)
    update_progress.add_argument("--reportable-findings-count", type=non_negative_int)
    update_progress.add_argument("--deep-review-pass", type=positive_int)
    update_progress.add_argument("--claim-token")
    update_progress.add_argument("--coordinator-generation", type=positive_int)
    update_progress.add_argument("--model")
    update_progress.add_argument("--reasoning-effort")

    prepare_scan_completion = subparsers.add_parser("prepare-scan-completion")
    prepare_scan_completion.add_argument("--scan-id", required=True)
    prepare_scan_completion.add_argument("--claim-token")

    complete_scan = subparsers.add_parser("complete-scan")
    complete_scan.add_argument("--scan-id", required=True)
    complete_scan.add_argument("--claim-token")
    complete_scan.add_argument("--cost-json")
    complete_scan.add_argument("--thread-id")

    complete_budget_exhausted_scan = subparsers.add_parser("complete-budget-exhausted-scan")
    complete_budget_exhausted_scan.add_argument("--scan-id", required=True)
    complete_budget_exhausted_scan.add_argument("--cost-json", required=True)
    complete_budget_exhausted_scan.add_argument("--message")

    cancel_scan = subparsers.add_parser("cancel-scan")
    cancel_scan.add_argument("--scan-id", required=True)
    cancel_scan.add_argument("--thread-id")

    fail_scan = subparsers.add_parser("fail-scan")
    fail_scan.add_argument("--scan-id", required=True)
    fail_scan.add_argument("--message", required=True)
    fail_scan.add_argument("--claim-token")
    fail_scan.add_argument("--cost-json")

    preserve_scan = subparsers.add_parser("preserve-scan-results")
    preserve_scan.add_argument("--scan-id", required=True)
    preserve_scan.add_argument("--thread-id")
    preserve_scan.add_argument("--claim-token")
    preserve_scan.add_argument("--coordinator-generation", type=positive_int)

    write_scan_draft = subparsers.add_parser("write-scan-draft")
    write_scan_draft.add_argument("--scan-id", required=True)
    write_scan_draft.add_argument("--draft-path", required=True)
    write_scan_draft.add_argument("--checkpoint-path")
    write_scan_draft.add_argument("--expected-draft-digest")
    write_scan_draft.add_argument("--claim-token")

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

    attach_scan_continuation_thread = subparsers.add_parser("attach-scan-continuation-thread")
    attach_scan_continuation_thread.add_argument("--scan-id", required=True)
    attach_scan_continuation_thread.add_argument("--claim-token", required=True)
    attach_scan_continuation_thread.add_argument("--thread-id", required=True)

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

    for command in (
        "inspect-linear-publication",
        "prepare-linear-publication",
        "record-linear-publications",
    ):
        publication = subparsers.add_parser(command)
        publication.add_argument("--input-file", required=True)

    subparsers.add_parser("database-info")
    arguments = sys.argv[1:]
    if "--user-context-stdin" in arguments:
        if arguments.count("--user-context-stdin") != 1 or "--user-context" in arguments:
            parser.error("pass exactly one user-context transport")
        index = arguments.index("--user-context-stdin")
        arguments[index] = "--user-context=" + sys.stdin.buffer.read().decode("utf-8")
    return parser.parse_args(arguments)


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


if __name__ == "__main__":
    parse_args(__doc__)
