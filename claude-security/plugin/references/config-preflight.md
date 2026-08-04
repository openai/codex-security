# Claude Security Capability Preflight

Every top-level scan skill runs this read-only helper before substantive scan work. It answers one question: can this session honestly claim the coverage the requested workflow promises?

Resolve `<python_command>` to `$PYTHON` when it is set, otherwise `python` on Windows and `python3` elsewhere. The command is written on one line so it works in PowerShell, Command Prompt, and POSIX shells:

```text
<python_command> <plugin_dir>/scripts/config_preflight.py --profile <capability-profile> --runtime-check repository_tools=<true|false> --runtime-check write_scan_artifacts=<true|false> --runtime-check shell_commands=<true|false> --runtime-check delegated_workers=<true|false>
```

For the `deep_security_scan` profile, also repeat `--available-plugin-skill <skill-name>` for each `claude-security` skill this session actually exposes, using its plugin-local name (`security-scan`, `validation`, …). Use the session's own skill surface, not files you find on disk.

Run the helper directly in the parent session, even when delegation is available. That keeps the exact command, exit code, and JSON result in the visible event stream instead of attributing an unobservable child result to this session.

## Determining the runtime checks

Inspect your current tool surface once, before building the command, and answer from what you actually see:

| Check | True when the session exposes |
| --- | --- |
| `repository_tools` | `Read`, plus `Grep` or `Glob` |
| `write_scan_artifacts` | `Write` (and `Edit` for revising drafts) |
| `shell_commands` | `Bash` or `PowerShell` |
| `delegated_workers` | `Task` |

Delegation tools are sometimes deferred rather than listed as active. If a tool-search facility exists and `Task` is not already active, search for it before answering `delegated_workers=false`. Answer `false` only after discovery fails to surface a usable delegation tool.

Omitting a check is not the same as answering `false`. An omitted check is reported as `unknown`, and an unknown value never counts as satisfied — if the profile needs it at `block` severity, the overall result is `incomplete`.

## Interpreting the result

The helper prints one JSON object with a top-level `status` and a `results` array.

- `ready` — every `block` requirement passed. Continue.
- `incomplete` — a `block` requirement is `unknown`. Establish the missing fact from the tool surface and rerun the helper once with an explicit `--runtime-check`.
- `blocked` — a `block` requirement failed. This session genuinely cannot perform the requested workflow.

Per-requirement severities mean:

- `block` — the requested workflow cannot be claimed honestly when unmet.
- `warn` — the workflow can continue only on the documented degraded path.
- `suggest` — the workflow can continue; mention the improvement when it materially affects scan quality.

Use the helper result as the source of truth. Do not independently reinterpret profile requirements.

## Degraded paths

When a `warn` or `suggest` requirement is unmet, the helper returns a concrete `remediation` string. Follow it, then record what changed in the scan's coverage limitations so the report does not overstate what was reviewed:

- **No `delegated_workers`.** Run every phase in the parent session. Coverage is unchanged; the scan is slower and consumes more context. Do not describe configured worker slots as running workers, and do not reduce the file set to compensate.
- **No `shell_commands`.** Skip the optional ranking, inventory, and preview helpers and review files directly through the read and search tools. Note the skipped helpers in coverage limitations.
- **`blocked` on `repository_tools` or `write_scan_artifacts`.** Stop and report that this session cannot scan. The `claude-security` CLI grants both; a session started another way may not.
- **`blocked` on `deep_scan_phase_skills`.** Stop and report which skills are missing. The CLI loads the plugin with `--plugin-dir`, which registers all of them.

A preflight problem is never a reason to abandon a scan whose earlier phases already completed. Record it, continue on the degraded path when one exists, and surface it in the final result.

This session is non-interactive: there is no user to ask about remediation, and no persistent configuration to edit. Never wait for input, and never modify user or project settings from inside a scan.
