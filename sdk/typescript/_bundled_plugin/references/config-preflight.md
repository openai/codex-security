# Codex Security Config Preflight

Codex Security Standard and diff scan skills should run the read-only helper before substantive scan work. Deep scans have no parent capability requirements and do not run this helper.

Load `desktop-config-preflight.md` only after the host explicitly identifies itself as the Codex desktop app.

Resolve `<python_command>` to the configured Python interpreter (`"$PYTHON"` in POSIX shells or `& "$env:PYTHON"` in PowerShell), otherwise use `python` on Windows and `python3` on Unix-like hosts. Before constructing the first helper command, inspect the current tool surface once and use that discovery result for both the runtime checks and `<verified-multi-agent-runtime-arguments>`. Do not omit active runtime facts from the first invocation and wait for an `incomplete` result before supplying them. The command is written on one line so it works in PowerShell, Command Prompt, and POSIX shells:

```text
<python_command> <plugin_dir>/scripts/config_preflight.py --profile <capability-profile> --cwd <scan-working-directory> --runtime-check delegation_available=<true|false> <verified-multi-agent-runtime-arguments>
```

Determine the runtime-check values from the current tool surface. Delegation tools may be deferred instead of appearing in the initial active tool list. If `tool_search` is available and delegation tools are not already active, search for subagent or multi-agent tools before passing `--runtime-check delegation_available=false`. Pass `false` only after tool discovery fails to expose a usable delegation tool. The `security_diff_scan` profile additionally retains its existing `--runtime-check goal_tools_available=<true|false>`; Standard and Deep profiles do not inspect or require goal tools. Consume the discovered tool namespace as runtime evidence too: when the current tool surface exposes `multi_agent_v1`, replace `<verified-multi-agent-runtime-arguments>` with `--multi-agent-runtime-owner native --multi-agent-runtime-version v1 --multi-agent-runtime-provenance tool-surface`. Do not pass a V2 session cap for V1. For other runtimes, use the verified owner, version, capacity when required, and provenance described below. When static config fully describes the active mode and no session-selected runtime overrides it, remove the placeholder. When the runtime exposes a more accurate effective config value than the user's base config file, add `--effective-config <path>=<json-value>`.

For standard and diff scans, a passed `delegated_workers` check means the runtime supports delegated review and the explicitly invoked scan authorizes it; a worker-slot result is the configured maximum, not a promise that every worker will start. If the runtime forbids delegation, pass `delegation_available=false`, continue on the documented parent fallback, and do not describe configured slots as running workers or reduced coverage.

When `CODEX_SECURITY_CONFIG_PATH` is set, add `--config "$CODEX_SECURITY_CONFIG_PATH"` in POSIX shells or `--config "$env:CODEX_SECURITY_CONFIG_PATH"` in PowerShell. The CLI provides this sanitized, shell-readable copy of the active worker configuration because the credential-bearing `CODEX_HOME` is intentionally inaccessible to repository-influenced commands. Do not substitute an ambient Codex home in that case.

Otherwise, the helper discovers Codex config paths itself from `--cwd`, which defaults to the current working directory. It reads `/etc/codex/config.toml` on Unix-like hosts or `%ProgramData%\OpenAI\Codex\config.toml` on Windows, then `$CODEX_HOME/config.toml`, resolves `project_root_markers`, checks the matching `[projects."<absolute-project-root>"].trust_level`, and loads trusted project `.codex/config.toml` layers from the project root down to `--cwd`. It does not load project layers unless the user config marks that project root as `trusted`.

When the current Codex CLI session selected `-p/--profile <name>`, pass `--codex-config-profile <name>`. Current Codex loads `$CODEX_HOME/<name>.config.toml` above the base user config and below trusted project config, so the helper uses that layer for project-root markers, trust, and capability values before it discovers project config. A missing profile file is an empty layer, matching the CLI. Embedded `[profiles.<name>]` lookup remains only for older Codex configs that select `profile` without the CLI flag. Project-local `profile` and `profiles` values are ignored. For session-only CLI overrides or other effective config values that cannot be recovered from config paths, pass `--effective-config <path>=<json-value>`.

For targeted tests or unusual runtimes, repeated `--config <path>` arguments override automatic discovery. Pass those manual layers from lower to higher precedence.

In Codex CLI, run the helper directly in the parent even when delegation is available. This keeps the exact command, exit code, and JSON result in the CLI event stream and avoids attributing an unobservable child result to the active runtime. In other hosts with delegation, run preflight in one dedicated worker before substantive scan work. Dispatch means a successful worker-spawn tool call that returns a concrete worker or thread id. Do not claim that a worker is running, or call a generic wait with no receiver, unless that spawn succeeded. Wait for the specific returned id and accept a result only from that worker. If spawning fails or returns no id, run the helper directly in the parent and report the spawn failure; never invent or reconstruct a helper result. The worker should return only a compact summary: the executed command and exit code, overall status, unmet or unknown capabilities, the returned `user_config_path`, and applicable remediation. Include the source path for any conflicting setting. Do not return the helper's raw JSON unless the parent needs it to resolve an ambiguity. This keeps preflight inspection out of the primary scan context.

The parent should pass only the runtime facts the worker cannot establish itself, such as a selected config profile or effective runtime-only config values. If delegation is unavailable after tool discovery, run the helper directly in the parent so the preflight can report the degraded or blocked path.

Multi-agent config mode is auto-detected when static config fully describes it. Model- or session-selected runtimes must additionally supply the verified runtime facts exposed by the active session. Keep protocol, owner, cap, and provenance separate:

```text
--multi-agent-runtime-owner native --multi-agent-runtime-version v2 --multi-agent-session-cap <count> --multi-agent-runtime-provenance <app-server|thread-context|tool-surface>
```

The V2 session cap includes the root thread. For profiles that evaluate current-session worker capacity, the helper subtracts that root thread when evaluating usable worker slots. For native V2 selected by static config, the documented Codex default session cap is four when no explicit cap is configured. Do not apply that static default to model- or session-selected V2 when a profile needs the active capacity: pass the observed runtime cap, or a blocking capacity requirement remains `incomplete`.

When the active session is actually managed by `codex_bridge`, provide explicit verified ownership. A backend config value alone is not ownership evidence:

```text
--multi-agent-runtime-owner codex-bridge --multi-agent-runtime-version v2 --multi-agent-runtime-provenance verified-bridge --effective-config multiagent_config.max_concurrency=<count>
```

For a profile that evaluates parent-runtime settings, passing `multiagent_config.max_concurrency` without `--multi-agent-runtime-owner codex-bridge` and `verified-bridge` provenance is an error. Explicit runtime claims still require their existing provenance and ownership checks. An unrelated backend config value does not block a profile that does not use parent-runtime settings.

Static native V2 accepts both `[features] multi_agent_v2 = true` and `[features.multi_agent_v2] enabled = true`. When the profile evaluates parent-runtime settings or explicit runtime facts are supplied, native V2 cannot be combined with `agents.max_threads`. `agents.max_depth` applies to V1 only and is not required for V2. A runtime version and cap without verified ownership cannot satisfy a blocking requirement. When runtime version, ownership, or capacity remains unknown, the helper returns `incomplete` only when a blocking requirement needs that fact and omits unsafe concurrency patches.

The helper reads the routed capability profile from `../preflight/capability-profiles.toml`, discovers the applicable Codex config paths from `--cwd`, applies documented defaults where the registry provides them, and prints one JSON result.

Use the helper result as the preflight source of truth. Do not independently reinterpret profile requirements or compare raw config text for exact equality.

Interpret requirement severities this way:

- `block`: the requested workflow cannot be claimed honestly when unmet
- `warn`: the workflow can continue only with the documented degraded path
- `suggest`: the workflow can continue, but Codex should mention the improvement when it materially affects long-running scan quality or resumability

When a requirement is config-backed, compare the effective resolved value when the runtime exposes it. When the runtime does not expose an effective value, fall back to the loaded config value and documented Codex default from the profile when one is present.

When the profile includes remediation patches, present the concrete config delta. In an interactive session, ask before editing persistent user config. If the user approves, edit only the helper's `user_config_path`; never infer `~/.codex/config.toml` or another Codex home. A conflicting value from a higher-precedence project or profile layer must be resolved in the source reported by the helper rather than hidden with a lower-precedence edit. In a non-interactive session, follow the narrow automatic-remediation path below instead of waiting for an answer the runtime cannot provide. Never rewrite config beyond the helper's concrete patches.

Some remediation patches have `kind = "host_setting"`. Present those as host-level setup guidance, not as edits to persistent Codex config.

Deep Security Scan uses MCP-owned SDK sessions rather than the parent thread's worker pool. Its preflight does not require a particular parent delegation runtime, ownership, capacity, or depth. Discovery workers inherit the scan's model and run under the verified read-only worker sandbox.

Do not warn merely because a user's value differs from the profile's suggested patch. Warn or block only when the evaluated capability requirement is unmet.

If a blocking runtime capability is `unknown`, establish it from the current tool surface and rerun the helper with an explicit `--runtime-check`. An unknown `warn` or `suggest` capability does not block a `ready` scan; continue on the documented degraded path without claiming that capability is available.

## Durable scan handoff

After a native handoff or direct conversation start provides a `scanId`, use its authoritative scan context and run this preflight for the validated target and selected scan mode. The dedicated preflight worker described above should finish before goal setup, threat modeling, scan/discovery worker creation, or other substantive analysis.

For standard and diff scans, the app handoff starts preflight without an item count. After every structured helper result, call `update_codex_security_scan_progress` without changing phase and set `preflightChecks` to every entry from the helper's `results` array, projecting each entry to only `capability`, `reason`, `severity`, and `status`. Do not send `phaseItemsTotal`, `phaseItemsCompleted`, or `phaseProgressUnit` with `preflightChecks`: the server derives the total from the array length, counts `pass` and `fail` as completed, excludes `unknown` from completed, and derives the visible `block` or `warn` attention items. Send the full fresh results array after a clean rerun so stale issues disappear. Do not interpret item-count completion as readiness: remain in preflight for every blocked, incomplete, or error result while remediation or retry remains pending, even when every returned check was evaluated. Only after a `ready` result has published its fresh `preflightChecks` should a separate progress call advance to `threat_model`. These counts and issues belong to the current scan rather than the legacy setup-time workspace preflight, and remain visible after the scan advances. Deep Scan preflight and discovery progress remain owned by `start_codex_security_deep_scan`.

Continue after a `ready` result. Explain warn or suggest issues when they materially affect scan quality, capacity, or resumability, and use the documented degraded path. If the result is `blocked` or `incomplete`, follow the remediation handling below. If the helper cannot run or returns its top-level `status: "error"` envelope, report the exact blocker and retry the documented recovery path when possible. Do not call `fail_codex_security_scan` merely because the helper is temporarily unavailable or errors; leave the durable scan running and hand off for a later retry while recovery may still be possible.

When blocked or incomplete preflight includes actionable remediation, first classify the current session before choosing a remediation control. Treat `codex exec`, headless runs, automation runs, and any host that cannot actually pause for a human reply as non-interactive even if `request_user_input` or `request_codex_security_user_input` is named in this document or appears callable. In a non-interactive session, never call either user-input tool and never fall back to a chat question; go directly to the automatic-remediation path below. Only after the session is confirmed interactive, present the exact reasons and config delta in the Codex thread and optimistically call the native `request_user_input` tool so the paused scan is visibly waiting for the user's decision instead of asking only in plain chat prose:

```text
request_user_input(
  questions=[
    {
      "header": "Preflight?",
      "id": "apply_preflight_remediation",
      "question": "Apply the recommended remediation and retry the preflight?",
      "options": [
        {
          "label": "Apply and retry (Recommended)",
          "description": "Apply the approved remediation, then rerun the capability preflight."
        },
        {
          "label": "Leave paused",
          "description": "Keep the scan running for a later retry without changing configuration."
        },
        {
          "label": "Cancel scan",
          "description": "Cancel this scan without applying the remediation."
        }
      ]
    }
  ]
)
```

Do not set `autoResolutionMs`; in an interactive session, an explicit answer is required before persistent configuration changes or scan continuation. If native `request_user_input` is unavailable or errors, call `request_codex_security_user_input` with the same `questions` payload. This MCP fallback is interactive and must remain prohibited in non-interactive sessions. If it returns `accepted`, follow its answer. If it is unavailable or errors, ask the same choices in chat. If it returns `declined` or `cancelled`, do not infer a choice; preserve the running scan, stop, and state that an explicit answer is still required. In every interactive waiting case, stop for the user's answer before creating or adopting a scan goal. Do not call `fail_codex_security_scan` while waiting for that answer. Apply only the approved remediation after `Apply and retry`, preserve the running scan and stop after `Leave paused`, and call `cancel_codex_security_scan` after `Cancel scan`.

In a non-interactive Codex session, do not leave the run waiting for an answer it cannot receive. After showing the exact blocker and config delta, automatically apply only the helper's concrete Codex config patches with ordinary `value` or `remove` operations to the active writable user config, preserving unrelated settings. Never automatically apply `host_setting` remediation or invent a patch. Rerun the same preflight once with the same verified runtime facts and any newly observable effective config. Continue only after that rerun returns `ready`; do not create or adopt scan goals or start substantive scan work earlier. If the new config needs a fresh session before the active runtime can use it, the rerun remains blocked or incomplete, remediation is unavailable, or the helper errors, do not loop, call `fail_codex_security_scan`, or cancel automatically. Preserve an app-generated durable scan and hand it off for a later retry; in CLI or another host without a durable scan, report the exact remaining blocker and end without claiming that a scan is paused.

For any non-ready result, do not fail automatically. If an interactive chat fallback declines required remediation without choosing whether to cancel or leave the scan running, ask that follow-up before taking either action. If remediation is unavailable, the helper cannot run, the helper returns an error envelope, or a rerun remains blocked or incomplete, preserve a durable running scan and retry or hand off while recovery may still be possible. Call `fail_codex_security_scan` with the exact reasons only after the documented recovery path is exhausted and the blocker is confirmed unrecoverable. When the user explicitly cancels, call `cancel_codex_security_scan`.

Present applicable remediation in the Codex thread. Ask before editing persistent user configuration in interactive sessions; use the narrow automatic-remediation path above in non-interactive sessions.

Codex CLI and other hosts use the same prompt-based preflight before substantive work. Explain the exact reasons and remediation in chat. Interactive CLI sessions ask before editing persistent config; non-interactive CLI sessions use the narrow automatic-remediation path above and continue only after a `ready` rerun.

## TAC Status Advisory

After capability preflight is `ready` and immediately before the workflow's first substantive scan action, use the hosted Codex Security Access app [$codex-security-access](app://connector_openai_codex_security_access) to call its `get_tac_status` action exactly once as the automatic pre-scan advisory. For Deep Security Scan, make this call immediately before `start_codex_security_deep_scan`. If this scan already performed the automatic advisory in an earlier continuation, reuse that result instead of calling it again. Report its exact `status` and TAC grant levels. When `status` is `not_granted`, before any other scan-start progress, present a separate, prominent warning that TAC access is not granted for this account and protected scan outputs may not be displayable. Include the returned `enrollmentUrl` as a clickable application link; if that field is absent, use `https://chatgpt.com/cyber`. Do not bury this warning in a routine status summary. When `status` is `unknown`, or the app or action is unavailable, instead warn that TAC access could not be verified and protected scan outputs may not be displayable. Then continue regardless. This result is advisory and must never authorize or gate the scan. Do not poll it or repeat it between scan phases. If the user explicitly asks to re-check after an account or TAC access change, call the action again for a fresh result; this user-requested refresh is the only repeat.
