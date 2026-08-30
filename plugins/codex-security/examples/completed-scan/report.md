# Security Review: example/repo

## Scope

The scan reviewed the canonical include paths and exclusions listed below.

- Scan mode: repository
- Target kind: git_worktree
- Target ID: target_sha256_example
- Revision: deadbeef
- Snapshot digest: codex-security-snapshot/v1:sha256:ed88f96a4c1a06603a41b3f261f59c3de2555c367ef6ad3bb8b9e483495d34eb
- Inventory strategy: repository
- Included paths: .
- Excluded paths: none
- Runtime or test status: not recorded

### Scan Summary

| Field | Value |
| --- | --- |
| Reportable findings | 1 |
| Severity mix | high: 1 |
| Confidence mix | high: 1 |
| Coverage | complete |
| Validation mode | not recorded |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

No explicit canonical threat-model summary was recorded.

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [Unsafe archive extraction can escape the output directory](#finding-1) | high | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Unsafe archive extraction can escape the output directory

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | Direct source trace reaches the filesystem write without a containment check. |
| Category | path-traversal |
| CWE | CWE-22 |
| Affected lines | src/extract.py:41-44 |

#### Summary

An attacker-controlled path reaches a filesystem write without containment validation.

#### Validation

Direct source trace reaches the filesystem write without a containment check. Validation details were not recorded separately.

#### Dataflow

The canonical finding records the affected path at src/extract.py:41-44, but no expanded source-to-sink narrative was recorded.

#### Reachability

Reachability was not recorded beyond the canonical finding summary and affected locations.

#### Severity

**High** — The scan assigned high severity; no separate canonical severity rationale was recorded.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Normalize destinations and reject entries that escape the extraction root.

Tests:
- Assert that extracting an archive entry named `../escape.txt` fails without writing outside the extraction root.

Preventive controls:
- Route all archive extraction through one helper that normalizes and validates destination paths.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Archive extraction | not recorded | Reported | No additional canonical notes were recorded. |
