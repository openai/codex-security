# Headless Standard scan

Continue a supplied `scanId` with `get_codex_security_scan_context`, passing its `handoffClaimToken` when present. For a new scan, call `start_codex_security_standard_scan` once with the authorized `targetPath`, `scope`, and optional exact `userContext`. Use the returned authoritative context in this terminal or chat session.
