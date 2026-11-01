# Scan Runtime

Use the current tool surface for Standard and diff scan delegation. If delegation tools are deferred and `tool_search` is available, discover them once before deciding that workers are unavailable. Use only successful spawn calls and their returned worker IDs as evidence that workers started. Configured capacity is a maximum, not a required number of workers.

When delegation is unavailable or a worker cannot start, continue the assigned review in the parent. Account for every authorized file and security question, and report actual coverage gaps. Do not inspect or edit persistent Codex configuration to enable optional workers or goal tools. Apply relevant `SECURITY.md` guidance and use available goal tools when the task authorizes them; their absence does not block source review.

For a host-backed diff scan, use its authoritative scan context and advance to `threat_model` before starting architecture mapping. The host still validates ownership, target, scope, authentication, and sandbox permissions. Deep Scan's coordinator owns its worker setup and progress; it does not depend on this thread's delegation tools.

## Daybreak Access Advisory

Standard receives any account advisory at launch. For a diff scan, read `access-advisory.md` before the first substantive scan action. It does not gate the scan or change runtime setup.
