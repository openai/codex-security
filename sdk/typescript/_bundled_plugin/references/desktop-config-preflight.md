# Codex Desktop Capability Preflight

Read this reference only after the host explicitly identifies itself as the Codex desktop app. The shared helper invocation, runtime checks, remediation limits, and non-interactive fallback remain in `config-preflight.md`.

Run preflight only after the scan has authoritative target and scan context.

After an app-backed Standard or diff scan has its authoritative `scanId`, publish every structured preflight result through `update_codex_security_scan_progress` without changing phase. Set `preflightChecks` to all current results, keeping only `capability`, `reason`, `severity`, and `status`; do not send separate phase totals. The server derives completed and total checks. Stay in preflight until the helper returns `ready`, then advance in a separate progress update. Deep discovery owns its own preflight and progress.

When an interactive desktop scan needs remediation, present the exact helper-provided config changes and offer **Apply and retry (Recommended)**, **Leave paused**, and **Cancel scan**. Prefer native `request_user_input`; if it is unavailable or errors, use `request_codex_security_user_input` with the same choices, and fall back to chat only when that tool is unavailable or errors. Never set automatic resolution or infer a choice from a declined or cancelled input request. Wait without creating a goal, then apply only explicitly approved changes, leave the durable scan running, or cancel only when the user explicitly selects cancellation.

Never use desktop input tools from a headless or non-interactive session.
