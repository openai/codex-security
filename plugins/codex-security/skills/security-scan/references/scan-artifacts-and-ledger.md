# Standalone Diff Worklists and Artifacts

Use this reference only for standalone or legacy diff discovery without a compact host inventory. Standard, Deep, and compact Workbench Diff scans do not use it. Follow `../../../references/artifact-storage.md` for managed temporary and retained files, and `../../../references/scan-artifacts.md` for paths.

## Changed-file Worklist

Generate `rank_input.jsonl` from every changed text file, including deleted files. Tracked changes remain in scope regardless of ignore rules; local patches also include non-ignored untracked files.

```text
<plugin_dir>/scripts/launch_codex_security_mcp --helper make-diff-rank-input --repo <repo_root> --base <base> --mode revisions --head <head> --out <discovery_dir>/rank_input.jsonl
<plugin_dir>/scripts/launch_codex_security_mcp --helper make-diff-rank-input --repo <repo_root> --base <base> --mode local-patch --out <discovery_dir>/rank_input.jsonl
```

Choose the first command for PR, commit, or branch diffs, and the second for a local patch. On Windows, use the [PowerShell generation commands](#windows-diff-worklist-generation). Keep the exact baseline and target unchanged.

Copy every row to the review worklist; diff scans do not rank or drop changed files:

```text
<plugin_dir>/scripts/launch_codex_security_mcp --helper copy-deep-review-input --rank-input <discovery_dir>/rank_input.jsonl --out <discovery_dir>/deep_review_input.jsonl
```

On Windows, use the [PowerShell copy command](#windows-worklist-copy). Run file-producing helpers in managed temporary storage and import retained output through the artifact tool. In these commands, `<discovery_dir>` is the prepared helper-output directory, not an invitation to write directly into retained storage.

## Scoped Deep Review

Review each worklist file, using its baseline contents when deleted. Read supporting files only as needed to explain changed security behavior, and record why they were included. Cover the file's security-relevant behavior rather than treating a search hit as completed review.

Use available subagents for independent assignments when useful. Size assignments around coherent behavior and review complexity, within the runtime's available capacity. If delegation fails, the parent reviews unstarted work. On native v2, use self-contained prompts with `fork_turns=none`.

Each assignment needs the target and diff range, assigned paths, applicable security policy and threat model, relevant user seeds, and output locations. Workers return reviewed paths and limitations, candidates with source/control/sink/impact evidence, counterevidence, and open validation questions. Discovery does not require validation or attack-path results before a candidate can be returned or deduplicated.

When the host consumes worker progress, emit `CODEX_SECURITY_WORKER_STATUS {"phase":"file_review","planned":6,"started":3}` after dispatch with the actual phase and counts. Do not add worker IDs, paths, prompts, or errors to this marker, and never report a worker as started without a successful spawn.

## Coverage and Phase Handoff

The parent reconciles assigned paths against the worklist. Retain a concise completion or limitation for each row in `work_ledger.jsonl`; do not manufacture coverage for unread files. Preserve explicit advisory seeds and their evidence or unresolved questions in `seed_research.md` when seed research is part of the request. Supplied context does not authorize additional source access.

For retained candidates, use stable IDs and a discovery receipt in `<findings_dir>/<candidate_id>/candidate_ledger.jsonl`. Each receipt identifies the scope, locations, evidence, and discovery status. Save the discovery result in `finding_discovery_report.md`. These files use the managed storage tool; do not append directly to retained files.

When combining several reviewers, retain `raw_candidates.jsonl` if needed to preserve their results. Merge duplicate observations before further analysis, preserving raw IDs and affected locations in `deduped_candidates.jsonl`; use `dedupe_report.md` only when the merge needs explanation. Independently vulnerable instances remain addressable.

Validation and attack-path analysis belong to their respective phases. Their owners add the method, evidence or proof gap, disposition, and phase receipt to the existing candidate record. Reuse completed analysis rather than rerunning it to satisfy another ledger. Final reporting must account for every candidate as resolved or explicitly deferred; a standalone discovery request ends at the discovery handoff.

## Windows Worklist Copy

In PowerShell, replace the placeholders inside single quotes with literal paths, doubling any single quote in a path:

```powershell
$env:worklistPluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:worklistDiscoveryDir = Convert-Path -LiteralPath '<discovery_dir>' -ErrorAction Stop
cmd.exe /d /v:off /s /c '""%worklistPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper copy-deep-review-input --rank-input "%worklistDiscoveryDir%\rank_input.jsonl" --out "%worklistDiscoveryDir%\deep_review_input.jsonl""'
```

These are temporary shell variables. Resolve paths against PowerShell's current location, including UNC shares. The input directory and `rank_input.jsonl` must exist; the output file need not. CMD expands these references once, preserving literal `%` and `!` in paths.

## Windows Diff Worklist Generation

Use literal paths as in the copy command and the full commit object IDs resolved for the scan target.

For PR, commit or branch diffs, run this command.

```powershell
$env:worklistPluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:worklistRepoRoot = Convert-Path -LiteralPath '<repo_root>' -ErrorAction Stop
$env:worklistDiscoveryDir = Convert-Path -LiteralPath '<discovery_dir>' -ErrorAction Stop
$env:worklistBase = '<resolved_base_object_id>'
$env:worklistHead = '<resolved_head_object_id>'
cmd.exe /d /v:off /s /c '""%worklistPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper make-diff-rank-input --repo "%worklistRepoRoot%\." --base "%worklistBase%" --mode revisions --head "%worklistHead%" --out "%worklistDiscoveryDir%\rank_input.jsonl""'
```

For a local patch, run this command.

```powershell
$env:worklistPluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:worklistRepoRoot = Convert-Path -LiteralPath '<repo_root>' -ErrorAction Stop
$env:worklistDiscoveryDir = Convert-Path -LiteralPath '<discovery_dir>' -ErrorAction Stop
$env:worklistBase = '<resolved_base_object_id>'
cmd.exe /d /v:off /s /c '""%worklistPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper make-diff-rank-input --repo "%worklistRepoRoot%\." --base "%worklistBase%" --mode local-patch --out "%worklistDiscoveryDir%\rank_input.jsonl""'
```

The repository’s `\.` suffix preserves drive-root paths. Use the resolved object IDs because quotes in a revision expression can change CMD argument parsing.
