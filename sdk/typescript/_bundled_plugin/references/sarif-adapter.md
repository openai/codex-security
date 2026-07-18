# SARIF Adapter

SARIF is a deterministic export, not the Codex Security source of truth.

The adapter:

- reads the sealed semantic bundle without mutating its manifest
- stores SARIF separately from the canonical seal
- emits SARIF 2.1.0
- uses stable `ruleId` values
- keeps rule descriptors stable across scans
- emits repository-relative POSIX paths
- uses one root-control location for GitHub annotation when available and keeps remaining evidence locations under `relatedLocations`
- preserves the semantic fingerprint under `codexSecurity/v1`
- emits GitHub's source-line `primaryLocationLineHash` when it can safely hash a bounded regular non-symlink source file inside the available source root
- maps categorical severity to SARIF `level`
- preserves a deep scan's canonical `candidateId` under each child result's properties so consumers can group results without changing the original SARIF result presentation

Lifecycle, rich validation evidence, attack-path context, and coverage are lossy or omitted in SARIF. Preserve them in semantic JSON.

Automatic SARIF export during finalization is best-effort so projection errors cannot invalidate a canonical seal. Use the strict adapter entry point when a consumer requires SARIF and should surface export errors.

References:

- [GitHub SARIF support for code scanning](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support-for-code-scanning)
- [OASIS SARIF 2.1.0 JSON Schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json)
