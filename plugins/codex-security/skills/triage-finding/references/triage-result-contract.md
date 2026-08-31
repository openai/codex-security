# Triage Result Contract

Use this contract for `$triage-finding` first-pass output. The skill performs static, inline triage of supplied findings. It does not use a queue or deep triage mode.

## Schema Fit

`../../../schemas/findings.schema.json` is not the normalization shape for triage inputs.

That schema is for completed Codex Security scan artifacts. It requires scan metadata, generated finding ids, occurrence ids, fingerprints, severity,
remediation, provenance, and locations. Triage inputs often arrive as incomplete claims from SARIF snippets, CVEs, advisories, scanner tickets, bug bounty reports, or pasted text. The normalization step should preserve those claims without inventing completed-scan fields.

If the user supplies a valid `codex-security.findings` artifact, use it as an input source and map its fields into this triage contract. Preserve `findingId`, `occurrenceId`, and `ruleId` as source identifiers; do not require new triage inputs to conform to the completed-scan schema.

## Top-Level JSON

```json
{
  "schema_version": "triage-finding/v0",
  "repository": {
    "path": "/path/to/repo",
    "revision": "optional git sha"
  },
  "findings": []
}
```

## Per-Finding JSON

Each entry in `findings` must use this shape:

```json
{
  "triage_item_id": "triage-001",
  "input_id": "scanner-or-user-id",
  "source_type": "sarif",
  "title": "finding title",
  "normalized_input": {
    "vulnerable_component": "package, file, API, route, function, service, or unknown",
    "claimed_source": "attacker-controlled input or unknown",
    "claimed_sink": "sink or broken control or unknown",
    "claimed_control": "missing or bypassed guard, sanitizer, auth check, or unknown",
    "affected_version_or_path": "affected version, path, config, or unknown",
    "preconditions": ["required condition"],
    "impact": "claimed impact or unknown",
    "references": ["source-provided reference"]
  },
  "verdict": "confirmed",
  "confidence": "high",
  "affected_locations": [
    {
      "label": "entrypoint",
      "path": "relative/path",
      "lines": "12-18",
      "detail": "why this location matters"
    }
  ],
  "reachable_path": ["step 1", "step 2"],
  "boundary_assessment": {
    "product_surface": "hosted service, CLI, library API, local developer UI, MCP/tooling, example/demo, test/fixture, docs, generated, vendored, or unknown",
    "source_trust": "untrusted, trusted_operator, trusted_developer_config, local_only, or unknown",
    "boundary_crossed": true,
    "policy_basis": "SECURITY.md, package/deploy evidence, product docs, code comments, or unknown"
  },
  "exploitability_stack_rank": {
    "rank_queue": "confirmed",
    "rank": 1,
    "rationale": "why this finding is more or less exploitable than other findings with the same verdict",
    "drivers": ["attacker reachability", "privilege required", "preconditions", "source-to-sink control", "guard strength"]
  },
  "evidence": ["static evidence observed"],
  "counterevidence": ["static evidence that weakens or defeats the claim"],
  "proof_gaps": ["missing evidence or reason for human review"],
  "recommended_next_step": "fix-finding",
  "fix_finding_handoff": "prompt-ready summary for confirmed findings"
}
```

Required source type values:

- `sarif`
- `cve`
- `advisory`
- `scanner_ticket`
- `bug_bounty`
- `codex_security_finding`
- `freeform`
- `unknown`

Allowed verdicts:

- `confirmed`
- `not_actionable`
- `needs_review`

Allowed confidence values:

- `high`
- `medium`
- `low`

`boundary_assessment` records whether the source crosses a supported product security boundary, not just whether dataflow reaches a sink. Use `unknown`
strings and `null` for `boundary_crossed` when the surface or policy is unclear;
prefer `needs_review` for unclear boundary cases.

`exploitability_stack_rank` records priority within the result set. Use separate queues for `confirmed` and `needs_review`. Assign unique positive integer ranks contiguously from `1` inside each queue. Rank `1` is the most exploitable finding in its queue; use `rank_queue` rather than the number alone to identify the queue. For `not_actionable`, set `rank_queue` and `rank` to `null`, use an empty `drivers`
array, and set `rationale` to a short explanation such as `not actionable`.

Use empty arrays for unavailable optional evidence lists. Use `null` for `fix_finding_handoff` unless the verdict is `confirmed`.
