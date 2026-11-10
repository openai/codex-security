# SARIF Adapter

Use SARIF to send saved findings to a code scanning tool. Keep the [sealed scan bundle](scan-contract.md#canonical-documents) for complete finding records.

The adapter:

- reads the sealed semantic bundle without mutating its manifest
- stores SARIF separately from the canonical seal
- emits SARIF 2.1.0
- uses stable `ruleId` values
- derives stable, readable rule names from `ruleId`
- includes categories, CWE tags, and canonical remediation in rule help and result messages
- emits repository-relative POSIX paths
- keeps the root-control location first for GitHub annotation when available and emits every distinct affected or code-evidence location in `locations`, so vulnerable sinks remain matchable
- preserves the semantic fingerprint under `codexSecurity/v1`
- emits GitHub's source-line `primaryLocationLineHash` when it can safely hash a bounded regular non-symlink source file inside the available source root
- captures optional source-line hashes in one eager pass and reuses those captured values; later source-root changes do not trigger rereads
- maps categorical severity to SARIF `level`
- sets GitHub's rule-level `security-severity` to the highest finding score. Unscored critical, high, medium, low, and informational findings use 9.5, 8.0, 5.0, 2.0, and 0.0. A rule with no positive score omits this field. These defaults are display values, not calculated CVSS scores.
- preserves a deep scan's canonical `candidateId` under each child result's properties so consumers can group results without changing the original SARIF result presentation

Lifecycle, rich validation evidence, attack-path context, and coverage are lossy or omitted in SARIF. Preserve them in semantic JSON.

SARIF `executionSuccessful` reflects whether the scan reached a successful terminal status. Stopped scans retain findings and include their concrete limitations as warnings. Coverage describes scope and follow-up work; neither successful execution nor an empty finding set certifies exhaustive review.

When your pipeline requires SARIF, export it explicitly and check the exit status. The command writes the file on success and exits with code `2` on an export error. The scan remains available if automatic SARIF generation failed during finalization.

```bash
codex-security export /path/to/scan-results --export-format sarif --output results.sarif
```

See [Export findings](https://github.com/openai/codex-security/blob/main/sdk/typescript/docs/cli.md#export-findings) for the scan selector and source-root options.

References:

- [GitHub SARIF support for code scanning](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support-for-code-scanning)
- [OASIS SARIF 2.1.0 JSON Schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json)
