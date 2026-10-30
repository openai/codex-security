# Wiz import reference

## Finding formats

The importer reads JSON, normalized JSONL, and the repository package-vulnerability CSV profile below, with gzip supported for each format. Direct CSV support covers repository package vulnerabilities (SCA) only. It does not fetch from Wiz or accept other CSV profiles, scan events, workload secrets, cloud configuration, or external network exports. Complete the requested pages; for an explicit subset, preserve the selection and its named collection.

Keep raw source records unchanged in `source_data`. Use the vendor occurrence ID, not a rule, CVE, title, or location. Missing IDs, severity, revisions, and locations must not be invented.

### Package vulnerabilities

Supported inputs include a vulnerability finding, an array, `data.vulnerabilityFindings.nodes`, a downloaded vulnerability report, and JSONL package records. Keep `id`, `name`, `detailedName`, `vendorSeverity` (or `severity`), and `vulnerableAsset.id`, with available package and source metadata. Existing package occurrence IDs are unchanged.

For a UI export, use **Vulnerability Findings → Save as → Report**, retaining repository and finding filters. Select **Repository Branch** instead of the default Virtual Machine selection, **JSON** or comma-separated **CSV**, and **Detailed** columns. Pass supported CSV reports directly to the command. Download the completed report; gzip is supported regardless of the filename extension. **Raw Event** on Code & Build Scans contains scan metadata, not findings. Do not create scheduled reports, notifications, or external storage unless requested.

The CSV profile requires `ID`, `Name`, `DetailedName`, `AssetID`, `WizURL`, `CloudPlatform`, and `CloudProviderURL`. `CloudPlatform` must identify GitHub, and `CloudProviderURL` must be a repository-branch URL. Its repository must match the selected Cloud repository or, for local import, a Git remote when parseable remotes are available. The importer uses the reported `ID` as occurrence identity and retains every original cell, including unknown columns, in `source_data.row`. It does not derive a branch or revision from the tree URL. Review excluded rows in the preview before importing.

### SAST, repository secrets, and IaC

Retain the named collection; bare arrays cannot identify these finding families.

| Family             | Collection                   | Occurrence ID |
| ------------------ | ---------------------------- | ------------- |
| SAST               | `data.sastFindings.nodes`    | `sast:<id>`   |
| Repository secrets | `data.secretInstances.nodes` | `secret:<id>` |
| IaC                | `data.iacFindings.nodes`     | `iac:<id>`    |

Supply a verified `repository.url` in the source repository metadata or matching `repository.id` and `repository.url` in `data.versionControlResources.nodes`. For secrets, the repository is `resource.typedProperties.repository` and the resource type must be `REPOSITORY_BRANCH`. Keep inventory `platform`: explicit `GITHUB` enables case-insensitive matching on custom GitHub Enterprise hosts.

Resolve conflicting platform or URL metadata for a repository ID before publishing. Names, inventory node IDs, `providerID`, and Wiz UUIDs are not Cloud repository IDs. The importer checks source URLs against the selected destination; fix missing or conflicting mappings before upload.

### Normalized JSONL and CSV conversion

Normalized JSONL has one record per line with `source_finding_id` and `evidence` containing `title`, `severity`, and the original record in `source_data`. For SAST, secrets, and IaC, also set `evidence.details.kind` to `sast`, `secret`, or `iac` and set the verified `evidence.details.repository.url`. Use the same prefixed occurrence IDs as raw API imports.

SAST, repository-secret, and IaC CSV reports still require a reviewed mapping of their actual headers into that profile. Preserve these family-specific details when present:

| Family             | Evidence to retain                                                                                                                 |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| SAST               | Rule/CWE, source range and snippet, scanner origin and verdict, remediation instructions                                           |
| Repository secrets | Source path and line, detector rule, type and confidence, vendor validation status, encryption/management flags, introduced commit |
| IaC                | Rule IDs/name, source range and matched content, platform, expected/actual content, file link, remediation instructions            |

Select source paths and line numbers explicitly for secret reports; the standard metadata query lacks them. Preserve empty IaC comparison strings. Vendor status, AI verdicts, and secret validation remain vendor evidence, not Codex assessments. An introduced commit is not a scanned revision, and a logical IaC resource does not prove runtime deployment.

## Deployment settings

For staging or another Cloud deployment, set `CODEX_SECURITY_CLOUD_BASE_URL` to its API root before preview and upload. Use that deployment's login and an isolated state directory for tests. If the user or Cloud page supplies an app URL, also set `CODEX_SECURITY_CLOUD_WEB_URL` to that full URL. This setting controls the returned UI link, not API routing or authentication.

Verify preview `cloudApiUrl` and any `cloudUrl` against the intended deployment: the former is the API endpoint, the latter the UI link. Saved retries are separated by deployment. `CODEX_SECURITY_CLOUD_PUBLISH_URL` routes native scan publication only, not vendor imports. Never fall back to production when staging is unavailable.

## Results and recovery

For Cloud publication, read the structured result even when the process exits nonzero; stderr progress does not replace it.

| Status        | Exit code | Meaning                                                                              |
| ------------- | --------- | ------------------------------------------------------------------------------------ |
| `empty`       | 0         | The report contained no records. No Cloud destination was checked or changed.        |
| `complete`    | 0         | All selected records were acknowledged and read back.                                |
| `partial`     | 1         | Local exclusions or final item failures remain.                                      |
| `interrupted` | 2         | Upload, verification, or receipt persistence stopped; acknowledged work is retained. |
| `failed`      | 2         | Preparation failed before upload.                                                    |

Cancellation retains the normal signal exit code. Report `failures` by vendor source ID, distinguish `verified` from `unacknowledged`, and retain `savedSubmission` and recovery errors.

Retry with unchanged input and destination. The publisher resends only unacknowledged requests using saved IDs and bodies. Existing findings retain their original Cloud environment even if the repository default changes. After a repository reset, stop and show the error; fresh discovery and confirmation are required before a new publication.
