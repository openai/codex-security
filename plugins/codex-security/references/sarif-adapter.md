# SARIF Adapter

SARIF is a deterministic export, not the Codex Security source of truth.

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
- maps categorical severity to SARIF `level`
- sets GitHub's rule-level `security-severity` to the highest finding score. Unscored critical, high, medium, low, and informational findings use 9.5, 8.0, 5.0, 2.0, and 0.0. A rule with no positive score omits this field. These defaults are display values, not calculated CVSS scores.
- preserves a deep scan's canonical `candidateId` under each child result's properties so consumers can group results without changing the original SARIF result presentation

Lifecycle, rich validation evidence, attack-path context, and coverage are lossy or omitted in SARIF. Preserve them in semantic JSON.

SARIF `executionSuccessful` reflects whether the scan reached a successful terminal status, not whether coverage is complete. Incomplete scans retain findings, set `codexSecurityCoverageCompleteness`, and include warnings. Integrations must read the coverage file referenced by `scan.coverageRef` before treating the results as exhaustive.

Automatic SARIF export during finalization is best-effort so projection errors cannot invalidate a canonical seal. Use the strict adapter entry point when a consumer requires SARIF and should surface export errors.

References:

- [GitHub SARIF support for code scanning](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support-for-code-scanning)
- [OASIS SARIF 2.1.0 JSON Schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json)
