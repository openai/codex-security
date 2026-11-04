# Native Standard scan

Continue a supplied `scanId` with `get_codex_security_scan_context`, passing its `handoffClaimToken` when present. For a new scan, call `start_codex_security_prompt_only_scan` once with `mode: "standard"`, the authorized `targetPath`, `scope`, and optional exact `userContext`. Preserve the returned scan identity and context.

Report meaningful completed-review batches. Increase the investigator total before dispatching a new assignment and exclude the independent baseline auditor from that total. Capture completed source-backed investigations as coverage surfaces before increasing `review_receipts`. Use actual findings and artifact completion for later counts. Model-only checkpoints preserve the current phase. Checkpoints with findings or reviewed surfaces advance to at least discovery, and the final draft advances to reporting. Publish earlier transitions when they occur.
