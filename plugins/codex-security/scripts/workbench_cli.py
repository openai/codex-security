"""Command-line argument parsing for the Codex Security workbench."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import deep_scan_workbench as deep_scan
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
    positive_int,
)


def add_user_context(parser: argparse.ArgumentParser, *, required: bool = False) -> None:
    context = parser.add_mutually_exclusive_group(required=required)
    context.add_argument("--user-context")
    context.add_argument("--user-context-stdin", action="store_true")


def parse_args(description: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=description)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_command(name: str, *required: str) -> argparse.ArgumentParser:
        command_parser = subparsers.add_parser(name)
        for flag in required:
            command_parser.add_argument(flag, required=True)
        return command_parser

    resolve_scan_root = subparsers.add_parser("resolve-scan-root")
    resolve_scan_root.add_argument("--scan-root")

    create_workspace = add_command("create-workspace", "--workspace-id")
    create_workspace.add_argument("--thread-id")
    create_workspace.add_argument("--target-path")
    create_workspace.add_argument("--target-title")
    create_workspace.add_argument("--target-summary")
    add_user_context(create_workspace)
    create_workspace.add_argument("--scope")
    create_workspace.add_argument("--mode", choices=MODES, default="standard")

    get_workspace = add_command("get-workspace", "--workspace-id")
    get_workspace.add_argument("--thread-id")

    add_command("inspect-target", "--target-path")

    inspect_setup = add_command("inspect-setup", "--target-path", "--scope")
    inspect_setup.add_argument("--mode", choices=MODES, required=True)

    save_workspace = add_command("save-workspace", "--workspace-id", "--target-path", "--scope")
    save_workspace.add_argument("--mode", choices=MODES, required=True)
    save_workspace.add_argument("--target-summary")
    add_user_context(save_workspace)

    start_scan = add_command("start-scan", "--workspace-id")

    start_prompt_only_scan = add_command(
        "start-prompt-only-scan", "--thread-id", "--target-path", "--scope"
    )
    start_prompt_only_scan.add_argument("--mode", choices=("diff", "standard"), required=True)
    start_prompt_only_scan.add_argument("--target-summary")
    add_user_context(start_prompt_only_scan)
    # Place shared options after each command's preceding arguments to preserve help order.
    for diff_parser in (create_workspace, inspect_setup, save_workspace, start_prompt_only_scan):
        diff_parser.add_argument("--diff-target-kind", choices=DIFF_TARGET_KINDS)
        diff_parser.add_argument("--diff-base-revision")
        diff_parser.add_argument("--diff-head-revision")
        diff_parser.add_argument("--diff-content-digest")

    start_headless_standard_scan = add_command(
        "start-headless-standard-scan", "--thread-id", "--target-path", "--scope"
    )
    start_headless_standard_scan.add_argument("--target-summary")
    add_user_context(start_headless_standard_scan)
    for scan_parser in (start_scan, start_prompt_only_scan, start_headless_standard_scan):
        scan_parser.add_argument("--scan-root")
        scan_parser.add_argument("--model")
        scan_parser.add_argument("--reasoning-effort")
    start_headless_standard_scan.set_defaults(
        mode="standard",
        diff_target_kind=None,
        diff_base_revision=None,
        diff_head_revision=None,
        diff_content_digest=None,
    )

    deep_scan.register_subcommands(subparsers, positive_int)

    get_scan = add_command("get-scan", "--scan-id")
    get_scan.add_argument("--occurrence-id")

    add_command("rename-scan", "--scan-id", "--name")

    add_command("get-scan-feedback", "--scan-id")

    update_scan_context = add_command("update-scan-context", "--scan-id")
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
    list_scans.add_argument("--offset", type=deep_scan.non_negative_int, default=0)
    list_scans.add_argument("--limit", type=positive_int)

    list_unmatched_scan_pairs = add_command("list-unmatched-scan-pairs", "--repository")
    list_unmatched_scan_pairs.add_argument("--force", action="store_true")

    register_cli_scan = add_command("register-cli-scan", "--scan-dir", "--repository")
    recipe = register_cli_scan.add_mutually_exclusive_group(required=True)
    recipe.add_argument("--recipe-json")
    recipe.add_argument("--recipe-json-stdin", action="store_true")
    recipe.add_argument("--registration-json-stdin", action="store_true")
    register_cli_scan.add_argument("--parent-scan-id")
    register_cli_scan.add_argument(
        "--archive-existing",
        action="store_true",
        help="Archive output in the registration transaction. Supports cancellable archival preparation.",
    )
    register_cli_scan.add_argument("--archived-scan-dir")

    add_command("set-scan-thread", "--scan-id", "--thread-id")

    set_scan_cost_limit = add_command("set-scan-cost-limit", "--scan-id")
    set_scan_cost_limit.add_argument("--max-cost-usd", required=True, type=float)

    add_command("get-scan-recipe", "--scan-id")

    get_cli_scan_resume = add_command("get-cli-scan-resume", "--scan-id")
    get_cli_scan_resume.add_argument("--allow-unavailable", action="store_true")

    compare_scans = add_command("compare-scans", "--before-scan-id", "--after-scan-id")
    compare_scans.add_argument("--include-matching-inputs", action="store_true")
    compare_scans.add_argument("--require-matches", action="store_true")

    save_scan_comparison = subparsers.add_parser(
        "save-scan-comparison",
        description="Comparison payload supports related findings.",
    )
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
    list_global_findings.add_argument("--offset", type=deep_scan.non_negative_int, default=0)
    list_global_findings.add_argument("--limit", type=positive_int, default=FINDINGS_PAGE_MAX)
    list_repositories = subparsers.add_parser("list-repositories")
    list_repositories.add_argument("--query")
    list_repositories.add_argument("--target-id")
    list_repositories.add_argument("--status", choices=("scanned", "not_scanned", "open_findings"))
    list_repositories.add_argument("--offset", type=deep_scan.non_negative_int, default=0)
    list_repositories.add_argument("--limit", type=positive_int)

    list_findings = add_command("list-findings", "--scan-id")
    list_findings.add_argument("--query")
    list_findings.add_argument("--severity", choices=FINDING_SEVERITIES)
    list_findings.add_argument("--status", choices=FINDING_STATUSES)
    list_findings.add_argument("--offset", type=deep_scan.non_negative_int, default=0)
    list_findings.add_argument("--limit", type=positive_int, default=FINDINGS_PAGE_MAX)

    update_progress = add_command("update-progress", "--scan-id")
    update_progress.add_argument("--phase", choices=PHASES)
    update_progress.add_argument("--phase-items-total", type=deep_scan.non_negative_int)
    update_progress.add_argument("--phase-items-completed", type=deep_scan.non_negative_int)
    update_progress.add_argument("--phase-progress-unit", choices=PHASE_PROGRESS_UNITS)
    preflight_issues = update_progress.add_mutually_exclusive_group()
    preflight_issues.add_argument("--preflight-issues-json")
    preflight_issues.add_argument("--preflight-issues-json-stdin", action="store_true")
    update_progress.add_argument("--review-items-total", type=deep_scan.non_negative_int)
    update_progress.add_argument("--review-items-completed", type=deep_scan.non_negative_int)
    update_progress.add_argument("--reportable-findings-count", type=deep_scan.non_negative_int)
    update_progress.add_argument("--deep-review-pass", type=positive_int)
    update_progress.add_argument("--claim-token")
    update_progress.add_argument("--coordinator-generation", type=positive_int)
    update_progress.add_argument("--model")
    update_progress.add_argument("--reasoning-effort")

    prepare_scan_completion = add_command("prepare-scan-completion", "--scan-id")
    prepare_scan_completion.add_argument("--claim-token")

    complete_scan = add_command("complete-scan", "--scan-id")
    complete_scan.add_argument("--claim-token")
    complete_scan.add_argument("--cost-json")
    complete_scan.add_argument("--thread-id")

    complete_budget_exhausted_scan = add_command(
        "complete-budget-exhausted-scan", "--scan-id", "--cost-json"
    )
    complete_budget_exhausted_scan.add_argument("--message")

    cancel_scan = add_command("cancel-scan", "--scan-id")
    cancel_scan.add_argument("--thread-id")

    fail_scan = add_command("fail-scan", "--scan-id", "--message")
    fail_scan.add_argument("--claim-token")
    fail_scan.add_argument("--cost-json")

    preserve_scan = add_command("preserve-scan-results", "--scan-id")
    preserve_scan.add_argument("--thread-id")
    preserve_scan.add_argument("--claim-token")
    preserve_scan.add_argument("--coordinator-generation", type=positive_int)

    recovery_help = "Validate and republish retained checkpoints for a failed, non-canceled scan."
    recover_scan = subparsers.add_parser(
        "recover-scan-results", help=recovery_help, description=recovery_help
    )
    recover_scan.add_argument("--scan-id", required=True, help="ID of the stopped scan to recover.")

    write_scan_draft = add_command("write-scan-draft", "--scan-id", "--draft-path")
    write_scan_draft.add_argument("--checkpoint-path")
    write_scan_draft.add_argument("--expected-draft-digest")
    write_scan_draft.add_argument("--claim-token")

    save_scan_artifact = add_command("save-scan-artifact", "--scan-id", "--artifact-path")
    save_scan_artifact.add_argument("--claim-token")

    for command in ("save-artifact", "read-artifact"):
        add_command(command, "--artifact-root", "--artifact-path")

    mark_handoff_delivered = add_command("mark-handoff-delivered", "--scan-id", "--claim-token")
    mark_handoff_delivered.add_argument("--thread-id")

    claim_handoff_delivery = add_command("claim-handoff-delivery", "--scan-id", "--claim-token")
    claim_handoff_delivery.add_argument("--take-over-stale", action="store_true")

    add_command("release-handoff-delivery", "--scan-id", "--claim-token")

    add_command("attach-scan-continuation-thread", "--scan-id", "--claim-token", "--thread-id")

    set_finding_triage = add_command("set-finding-triage", "--occurrence-id")
    set_finding_triage.add_argument("--status", choices=FINDING_STATUSES, required=True)
    set_finding_triage.add_argument("--close-reason", choices=FINDING_CLOSE_REASONS)
    set_finding_triage.add_argument("--note")

    add_command("request-finding-remediation", "--occurrence-id", "--request-id", "--action-token")

    request_finding_remediation_action = add_command(
        "request-finding-remediation-action", "--occurrence-id", "--request-id"
    )
    request_finding_remediation_action.add_argument(
        "--expected-version", type=positive_int, required=True
    )
    request_finding_remediation_action.add_argument(
        "--action", choices=("apply", "verify"), required=True
    )
    request_finding_remediation_action.add_argument("--action-token", required=True)

    for command in (
        "claim-finding-remediation-resend",
        "mark-finding-remediation-delivered",
        "release-finding-remediation-claim",
        "cancel-finding-remediation-request",
    ):
        add_command(command, "--occurrence-id", "--request-id", "--action-token")

    set_finding_remediation = add_command(
        "set-finding-remediation", "--occurrence-id", "--request-id", "--action-token"
    )
    set_finding_remediation.add_argument("--expected-version", type=positive_int, required=True)
    set_finding_remediation.add_argument(
        "--state", choices=REMEDIATION_UPDATE_STATES, required=True
    )
    set_finding_remediation.add_argument("--summary")
    set_finding_remediation.add_argument("--patch-path")
    set_finding_remediation.add_argument("--patch-digest")
    set_finding_remediation.add_argument("--base-revision")
    set_finding_remediation.add_argument("--verification-summary")

    export_findings = add_command("export-findings", "--scan-id")
    export_findings.add_argument(
        "--artifact", choices=("findings", "threat-model"), default="findings"
    )
    export_findings.add_argument("--format", choices=(*EXPORT_FORMATS, "md"))
    export_findings.add_argument("--validate-only", action="store_true")

    for command in (
        "inspect-linear-publication",
        "prepare-linear-publication",
        "record-linear-publications",
    ):
        add_command(command, "--input-file")

    subparsers.add_parser("database-info")
    subparsers.add_parser("finding-workflow")
    subparsers.add_parser("local-dedupe")
    subparsers.add_parser("severity-classification")
    add_command("read-severity-classification", "--scan-id")
    arguments = sys.argv[1:]
    if "--user-context-stdin" in arguments:
        if arguments.count("--user-context-stdin") != 1 or "--user-context" in arguments:
            parser.error("pass exactly one user-context transport")
        index = arguments.index("--user-context-stdin")
        arguments[index] = "--user-context=" + sys.stdin.buffer.read().decode("utf-8")
    return parser.parse_args(arguments)


if __name__ == "__main__":
    parse_args(__doc__)
