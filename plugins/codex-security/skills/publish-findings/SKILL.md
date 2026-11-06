---
name: publish-findings
description: Requires explicit opt-in with CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1. Preview and import scanner findings, including issues selected in the SonarQube plugin, into the local workbench or Codex Security Cloud.
---

# Publish external findings

Before acquiring or importing findings, check for `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1` in the command environment. If it is unset or has another value, stop and ask the user to enable imports.

Use `codex-security import sonar` for [live SonarQube Cloud issues](references/sonar.md) or a capture saved by that command. Use `codex-security publish findings` for native scanner exports, including Sonar `/api/issues/search` pages with `--provider sonar`. Select the requested destination. The CLI owns source mapping, persistence, and Cloud authentication and retries. Do not implement another store or uploader or put credentials in command arguments.

## Select the evidence

Use a supplied report, connected tool or signed-in CLI that provides the requested native records for the selected account, repository and ref. Follow the [scanner import guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/README.md) to narrow broader reports and verify the selection in the JSON preview. Use a direct API only when the provider guide supports its response for the selected destination. Otherwise ask for a supported report. A fresh scan produces new findings. Keep the original records and complete the requested pagination. A JSON summary or a different product's API response is not interchangeable with the documented report. Use SARIF or CSV only when the installed provider reader supports that profile and native JSON is unavailable or the user supplies that format. Do not convert a richer JSON report to SARIF for import.

Use the same acquisition format for repeated imports. Check the provider's identity rules before switching formats: another format can create a separate record or replace a richer snapshot with less detail. Importing findings does not reconcile equivalent vulnerabilities across formats. `--format json` controls command output, not the input report format; readers detect their supported inputs.

## Import locally

Use a local repository path with `--repository`. No Cloud login is required.

```sh
codex-security publish findings /path/to/selected-wiz-findings.json \
  --to local --repository /path/to/project --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

Show the repository, source namespace, normalized evidence, and exclusions. For a zero-record preview, report whether the input is empty or failed and stop. After confirmation, repeat without `--dry-run`, adding `--yes`. Keep approval when the user already approved this preview and the input and destination are unchanged.

Read the stored evidence with `codex-security findings imported /path/to/project --format json`; the repository defaults to the current directory. Report created, updated, unchanged, and excluded counts, including exclusion reasons when the command exits 1.

Local records remain unassessed source evidence, separate from `findings list` and completed scans. Repeated imports use the same repository/provider/source-key/source-ID identity; omitted records remain stored. When a source repository URL and local Git remotes are available, the URL must match a remote. Local import does not publish to Cloud or automatically investigate or patch findings.

## Provider instructions

Before acquiring or importing evidence, read the instructions for the selected provider.

- [Trivy dependency vulnerabilities](references/trivy.md)
- [Amazon Inspector repository findings](references/inspector.md)
- [AWS Continuum code findings](references/continuum.md)
- [Black Duck SCA project-version vulnerabilities](references/blackduck.md)
- [Checkmarx SAST](references/checkmarx.md)
- [Veracode Static Analysis policy findings](references/veracode.md)
- [Endor Labs findings](references/endor.md)
- [Wiz findings](references/wiz.md)
- [Snyk findings](references/snyk.md)
- [Semgrep Code](references/semgrep.md)
- [OpenGrep](references/opengrep.md)
- [SonarQube Cloud issues](references/sonar.md)
- [GitHub alerts and advisories](references/github.md)

## Publish to Cloud

Resolve the user's destination to a connected GitHub or GitHub Enterprise repository URL or Cloud repository ID, including custom Enterprise hosts. Confirm the intended Cloud account and authorized repository environment before running a preview that can contact Cloud. Use the existing file-backed ChatGPT login; explain a missing or incompatible login rather than changing credential storage automatically.

For staging or another Cloud deployment, configure the [deployment settings](#deployment-settings) before previewing. Keep the selected deployment and login throughout the upload.

### Preview and approve

```sh
codex-security publish findings /path/to/selected-wiz-findings.json \
  --to cloud --repository https://github.com/example/project --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

When the preview returns `status: "empty"`, report that there is nothing to upload, then stop. For a nonempty preview, show the Cloud API endpoint, account, repository, environments, source namespace, severity counts, and exclusions. Identify the evidence file and make the complete JSON preview available for inspection without pasting a large report into the conversation. Explain that vendor evidence is not a Codex assessment.

Obtain explicit confirmation for this concrete upload, including skipped records. Then run the same command without `--dry-run`, adding `--yes`. Authorization to inspect or assess findings alone does not authorize sending them to Cloud. Keep approval when the user already approved this preview and the input and destination are unchanged.

### Upload and report

Read the structured result even when the process exits nonzero. Progress appears on stderr.

| Status        | Exit code | Meaning                                                 |
| ------------- | --------- | ------------------------------------------------------- |
| `complete`    | 0         | All selected records were acknowledged and read back.   |
| `partial`     | 1         | Some records were excluded or have final item failures. |
| `interrupted` | 2         | Upload, verification, or receipt persistence stopped.   |
| `failed`      | 2         | Preparation failed before upload.                       |

Cancellation uses the normal signal exit code. Report verified, unacknowledged, excluded, and failed records separately. Include source IDs from `failures`, any `savedSubmission` path, and recovery errors. Receipts and readback confirm stored vendor evidence. Assessment and visibility in the shared Cloud Findings view require separate verification. Link to the returned `cloudUrl` when available.

### Resume an interrupted upload

After a lost response or retryable failure, repeat the command with the same input and destination. Cloud may already have accepted some records. The publisher reuses saved request IDs and bodies, resends only requests without a saved receipt, and verifies the acknowledged records. Existing findings keep their original Cloud environment when the repository default changes.

If the repository was reset, stop and report the error. Rediscover the repository and get fresh confirmation before starting a new publication.

### Deployment settings

Set `CODEX_SECURITY_CLOUD_BASE_URL` to the deployment's API root for preview and upload. Use its login and an isolated state directory for tests. If the user or Cloud page supplies an app URL, set `CODEX_SECURITY_CLOUD_WEB_URL` to that full URL. This setting controls the returned UI link. The API root and login still determine routing and authentication.

Check the preview's `cloudApiUrl` and any `cloudUrl` against the intended API endpoint and app. Saved retries are scoped to the deployment. `CODEX_SECURITY_CLOUD_PUBLISH_URL` applies only to native scan publication. If staging is unavailable, stop before uploading.
