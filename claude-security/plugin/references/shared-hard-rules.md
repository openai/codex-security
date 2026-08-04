# Shared Hard Rules

Apply these rules for diff, deep, and resumed legacy Claude Security scans before the scan-mode-specific hard rules in that workflow:

- Keep the phases separate.
- Follow the execution plan in order.
- Use the tools to inspect the repository before making decisions.
- Candidate-finding coverage is required. Do not finalize a candidate finding until `findings/<candidate_id>/candidate_ledger.jsonl` shows discovery, validation, and attack-path receipts for that exact candidate, or an explicit deferred reason for the missing proof.
- Avoid destructive commands, interactive editors, and broad unbounded scans.
- Prefer targeted, reversible shell commands.
- Failing a scan is terminal and cannot be resumed. Stop and report a blocker only when it is genuinely unrecoverable after documented recovery is exhausted. Do not stop merely because work remains, partial artifacts exist, or the context window is filling. Record meaningful progress and finish the canonical artifacts; the CLI marks the scan failed only when it does not get them.
- For Phase 1 fallback threat model generation, produce a repository-level threat model that would still make sense for an unrelated diff in the same repository.
- Do not let the current scan target bias Phase 1 unless the user explicitly requests a target-scoped threat model.
- For later phases, stay grounded in repository evidence and the actual in-scope code.
- Do not emit a finding unless it survives the final policy-adjustment pass.
