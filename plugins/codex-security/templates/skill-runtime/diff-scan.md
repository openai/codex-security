# Native diff scan

Continue a supplied `scanId` with `get_codex_security_scan_context`, passing its `handoffClaimToken` when present. For a new scan, call `start_codex_security_prompt_only_scan` once with `mode: "diff"`, the authorized `targetPath`, `scope: "."`, exact `diffTarget` and optional `userContext`. Preserve the returned revisions. Report an unsupported baseline before creating canonical artifacts.

After completion, read `get_codex_security_completed_scan` and return the generated results.
