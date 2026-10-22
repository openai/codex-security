---
name: publish-findings
description: Import selected Wiz package vulnerabilities, SAST, repository secrets, and IaC findings locally or to Codex Security Cloud after previewing the destination and evidence. Supports plain or gzip-compressed JSON and normalized JSONL; does not import workload secrets or cloud configuration, run a scan, or assess findings.
---

# Publish external findings

Use the installed `codex-security publish findings` command for preview and import. It owns source mapping and local persistence or Cloud publication. Select `--to local` for the local workbench SQLite database or `--to cloud` for Cloud. Do not implement another store or uploader or put credentials in a command argument.

For `--to cloud`, destinations currently support connected GitHub and GitHub Enterprise repositories, including custom Enterprise hostnames. Resolve the user's destination to its repository URL or Cloud repository ID; the command accepts either. Confirm that the repository is connected in the intended Cloud account and has an authorized environment. Use the existing file-backed ChatGPT login; explain a missing or incompatible login rather than changing credential storage automatically.

## Choose the source report

Prefer the provider's supported native JSON from its authenticated CLI, plugin, or API. Keep the original records and complete the requested pagination. A JSON summary or a different product's API response is not interchangeable with the documented report. Use SARIF or CSV only when the installed provider reader supports that profile and native JSON is unavailable or the user supplies that format. Do not convert a richer JSON report to SARIF for import.

Use the same acquisition format for repeated imports. Check the provider's identity rules before switching formats: another format can create a separate record or replace a richer snapshot with less detail. Importing findings does not reconcile equivalent vulnerabilities across formats. `--format json` controls command output, not the input report format; readers detect their supported inputs.

## Local imports

For local storage, use a repository path with `--repository`. No Cloud login is required. Preview the same selected evidence before importing:

```sh
codex-security publish findings /path/to/selected-wiz-findings.json \
  --to local --repository /path/to/project --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

Show the repository, source namespace, normalized evidence, and exclusions. After confirmation, repeat without `--dry-run`, adding `--yes`. Read the persisted result with `codex-security findings imported /path/to/project --format json`. The readback repository defaults to the current directory.

Local records remain unassessed source evidence, separate from `findings list` and completed scans. Retain unknown metadata without inventing scanner revisions, assessment fields, or patch results. Report the created, updated, unchanged, and excluded counts. Repeated imports use the same repository/provider/source-key/source-ID identity; omitted records remain stored. When a source repository URL and local Git remotes are available, the source URL must match one of those remotes. Local import does not publish to Cloud or automatically investigate or patch findings.

## Wiz findings

Prefer the user's configured Wiz plugin or authorized [Wiz MCP](https://www.wiz.io/blog/introducing-wiz-mcp) connection to read selected findings. Use an authorized Wiz API connection when the required records are not exposed by MCP. Save the actual selected records locally with their original occurrence IDs and evidence. Inspect the returned fields: a summary, Wiz Issue, or local Wiz CLI scan result is not automatically a supported finding record. Do not invent fields to make a response fit the mapper.

Finish the requested pagination; for an explicit subset, retain that selection and its named collection. The publisher reads plain or gzip-compressed JSON and normalized JSONL with `source_finding_id` and `evidence` as documented in the CLI guide. A supplied export can use the same path. The command does not fetch from Wiz or accept CSV, scan events, workload secrets, cloud configuration, or external network exports.

Use a stable Wiz tenant/finding namespace as `--source-key`. A project filter is selection context, not a new identity. Confirm the selected assets or builds belong to the destination repository; do not infer a scanner branch or revision from the current checkout. Do not publish vendor credentials, unrelated records, or local assessments as original scanner evidence.

For package vulnerability UI exports, use **Vulnerability Findings → Save as → Report**, keeping the repository and finding filters. Select **Repository Branch** (remove the default Virtual Machine selection), **JSON**, and **Detailed** columns. Download the completed report; default gzip compression is supported, even with a `.json` filename. **Raw Event** on Code & Build Scans contains scan metadata and cannot supply findings. Do not create a scheduled report or enable notifications or external storage unless requested.

For SAST, repository secrets, and IaC, retain the explicit `data.sastFindings.nodes`, `data.secretInstances.nodes`, or `data.iacFindings.nodes` collection. Bare arrays cannot identify these finding families. Include a verified URL on the source repository metadata or supply `data.versionControlResources.nodes` with matching `repository.id` and `repository.url`. Retain the documented inventory `platform` field; explicit `GITHUB` establishes case-insensitive matching on custom GitHub Enterprise hosts. Resolve conflicting platform or URL metadata for a repository ID before publishing. For secrets, the repository is `resource.typedProperties.repository` and resource type must be `REPOSITORY_BRANCH`. Do not map names, inventory node IDs, `providerID`, or Wiz UUIDs directly to Cloud repository IDs. The importer verifies source URLs against the selected destination; resolve a missing or conflicting mapping before uploading.

Keep raw source records unchanged in `source_data`. New raw occurrence IDs are prefixed `sast:`, `secret:`, or `iac:`; existing package IDs are unchanged. For CSV report conversion, use a reviewed mapping of the actual header names into the documented normalized JSONL profile, set `evidence.details.kind` and the verified `details.repository.url`, and use the same prefixed occurrence ID. The command does not parse CSV directly. Select source paths and line numbers explicitly in secret reports; the standard metadata query lacks them. Preserve rule/CWE, range/snippet, detector validation, and IaC comparison fields in the typed details described in the CLI docs. Preserve empty comparison strings. Do not invent missing IDs, severity, revisions, or locations, retrieve credential values, test credentials, or apply suggested fixes. Vendor status, AI verdict, secret validation, introduced commits, and logical IaC resources are evidence, not Codex assessment or proof of runtime deployment.

When publishing to staging or another Cloud deployment, set `CODEX_SECURITY_CLOUD_BASE_URL` to its API root before both preview and upload. If the Cloud page or user supplies its app URL, also set `CODEX_SECURITY_CLOUD_WEB_URL` to that full URL so the command can return a repository link. The UI setting does not change API routing or authentication. Use that deployment's login and an isolated state directory for tests. Verify `cloudApiUrl` and any `cloudUrl` in the preview against the intended deployment; the former is the API endpoint and the latter is the UI link. Saved retries are separated by deployment. The native scan setting `CODEX_SECURITY_CLOUD_PUBLISH_URL` does not route vendor imports. Never fall back to production when staging is unavailable.

```sh
codex-security publish findings /path/to/selected-wiz-findings.json \
  --to cloud --repository https://github.com/example/project --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

Show a concise preview of the Cloud API endpoint, account, repository, environments, source namespace, severity counts, and exclusions. Identify the saved evidence file and let the user inspect the complete JSON preview; do not paste an entire large report into the conversation. Explain that imported vendor evidence is not a Codex assessment. Obtain explicit confirmation for this upload, including any skipped records, then run the same command without `--dry-run`, adding `--yes`. Existing authorization to inspect or assess findings alone does not authorize sending them to Cloud. A user who already approved the concrete preview need not approve it again.

After a lost response or retryable failure, repeat the same command with unchanged input and destination. The publisher resends only unacknowledged requests, using their saved IDs and bodies. Existing findings keep their original Cloud environment even if the repository’s default changes. After a repository reset, stop and show the error; require fresh discovery and confirmation before a new publication. Report partial failures and retain their explanations. Successful receipts and source-record readback confirm stored vendor evidence. They do not establish a Codex assessment or visibility in the shared Cloud Findings view. Include the returned `cloudUrl` as a clickable repository link when available; do not derive a UI URL from the API endpoint or invent a link.

Read the result even when the process exits nonzero. Local imports exit 1 when records were excluded; report their exclusion reasons alongside the stored counts. For Cloud publication, `complete` exits 0, `partial` exits 1 for exclusions or final item failures, and `interrupted` exits 2 while preserving acknowledged counts and receipts. Report `failures` by vendor source ID, distinguish `verified` from `unacknowledged`, and retain `savedSubmission` and the recovery error. A lost response does not mean that no findings reached Cloud. Preparation failures use `failed`; cancellation keeps the normal signal exit code. Terminal progress goes to stderr and does not replace the JSON result.
