---
name: publish-findings
description: Requires explicit opt-in with CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1. Preview and import scanner findings into the local workbench or Codex Security Cloud. Use the selected provider's documented export format.
---

# Publish external findings

Before acquiring or importing findings, check for `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1` in the command environment. If it is unset or has another value, stop and ask the user to enable imports.

Use the installed `codex-security publish findings` command for preview and import. Select `--to local` for the local workbench or `--to cloud` for Cloud. The command owns source mapping, persistence, and Cloud authentication and retries. Do not implement another store or uploader or put credentials in command arguments.

## Select the evidence

Prefer the provider's supported native JSON from its authenticated CLI, plugin, or API. Keep the original records and complete the requested pagination. A JSON summary or a different product's API response is not interchangeable with the documented report. Use SARIF or CSV only when the installed provider reader supports that profile and native JSON is unavailable or the user supplies that format. Do not convert a richer JSON report to SARIF for import.

Use the same acquisition format for repeated imports. Check the provider's identity rules before switching formats: another format can create a separate record or replace a richer snapshot with less detail. Importing findings does not reconcile equivalent vulnerabilities across formats. `--format json` controls command output, not the input report format; readers detect their supported inputs.

## Import locally

Use a local repository path with `--repository`. No Cloud login is required.

```sh
codex-security publish findings /path/to/selected-wiz-findings.json \
  --to local --repository /path/to/project --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

Show the repository, source namespace, normalized evidence, and exclusions. For a zero-record preview, report any scanner diagnostics and stop. After confirmation, repeat without `--dry-run`, adding `--yes`. Keep approval when the user already approved this preview and the input and destination are unchanged.

Read the stored evidence with `codex-security findings imported /path/to/project --format json`; the repository defaults to the current directory. Report created, updated, unchanged, and excluded counts, including exclusion reasons when the command exits 1.

Local records remain unassessed source evidence, separate from `findings list` and completed scans. Repeated imports use the same repository/provider/source-key/source-ID identity; omitted records remain stored. When a source repository URL and local Git remotes are available, the URL must match a remote. Local import does not publish to Cloud or automatically investigate or patch findings.

## Amazon Inspector repository findings

Use `--provider inspector` and `--source-repository-url` with a complete Inspector2 ListFindings export for one Code Security repository. If it contains only a project ARN and name, pass the full `--inspector-project-arn ARN` verified for that Git URL in the SCM integration. Supply the same ARN when resuming a pending Cloud submission. Self-managed GitLab is supported locally.

## Endor Labs findings

For Endor Labs imports, prefer native Finding JSON from authenticated `endorctl`, scoped to one project and context. Omit `--field-mask` and fetch all pages with `--list-all`:

```sh
endorctl api list --resource Finding --namespace "YOUR_NAMESPACE" \
  --filter 'context.type==CONTEXT_TYPE_MAIN and spec.project_uuid=="PROJECT_UUID"' \
  --list-all --output-type json > endor-findings.json
codex-security publish findings endor-findings.json --to local \
  --provider endor --repository /path/to/project \
  --source-key "YOUR_NAMESPACE/PROJECT_UUID/main" --dry-run --format json
```

Choose a project that corresponds to the selected local checkout or Cloud repository. To publish the same export to Cloud, use `--to cloud --repository "CLOUD_REPOSITORY_ID"`. For a different branch or scan context, change the Endor filter and keep a distinct, stable source key. The [official Endor Labs Agent Kit for Codex](https://github.com/endorlabs/ai-plugins/tree/main/plugins/codex/endor-labs-agent-kit) can help with setup and investigation; its summaries, counts and field-masked results do not replace complete Finding objects. The [CLI API](https://docs.endorlabs.com/developers-api/cli/commands/api) supplies the export. The importer reads that saved file; it does not maintain an Endor API connection or write changes back to Endor.

Native JSON retains severity, scanned commit, package and advisory data, and primary SAST/AI SAST locations. Existing self-contained endorctl SARIF is a lossy compatibility format that retains finding UUIDs and links; unavailable severity or revisions stay unknown. Both formats use the Endor UUID within the selected repository and source key as identity. Importing SARIF after native JSON updates the same record by replacing its evidence snapshot, not merging it: native detail absent from SARIF is removed from that snapshot. Use native JSON consistently for ongoing imports. Keep the original evidence and inspect exclusions. Imported records remain unassessed source evidence. For local imports, use the preview and readback procedure above; for Cloud, use the publication procedure below.

## Wiz findings

Read [Wiz import formats](references/wiz-import.md#finding-formats) before preparing input. Use an authorized [Wiz MCP](https://www.wiz.io/blog/introducing-wiz-mcp) or Wiz API connection; a configured plugin may provide it, but do not assume an official Codex plugin is available. Prefer supported native JSON. Inspect actual records, finish the requested pagination, and save only the selected evidence with its original occurrence IDs. A supplied export is also supported. Summaries, Wiz Issues, and local CLI scan results are not automatically supported finding records.

Validate the acquisition path against actual responses from an authorized Wiz tenant; local parser checks do not establish that qualification. Direct CSV input covers repository package vulnerabilities (SCA) only, not SAST or cloud posture findings, and does not provide a complete Wiz code-to-cloud integration.

Use a stable Wiz tenant/finding namespace as `--source-key`; a project filter does not create a new identity. Confirm the selected assets or builds belong to the destination repository. Do not infer source branches or revisions from the current checkout, invent missing evidence, or import vendor credentials, unrelated records, or local assessments as original scanner evidence. Do not retrieve or test credentials or apply suggested fixes.

## Snyk Open Source

Prefer the [official Snyk Codex plugin](https://github.com/snyk/studio-recipes/tree/main/plugins/codex) when available. Ask its `snyk-findings-export` skill for **SCA only from the repository’s Git root** and save the `snyk-findings-export/v1` bundle. It scans the current workspace through local MCP; it cannot list existing platform projects or retrieve earlier findings. Do not substitute a fresh scan for a request to read a platform backlog. Authentication, relevant Snyk access and the project's package tooling are required.

Import the bundle with `--provider snyk`, choosing `--to local --repository /path/to/project` or `--to cloud --repository https://github.com/example/project`. Use a stable repository/branch/scan-target/acquisition namespace such as `github.com/example/project/main/root/plugin-sca`. Check the bundle's scan outcomes, collection completeness and limitations alongside the preview. Only Open Source SCA vulnerability records are supported; other categories are explicit exclusions. Preserve the native MCP record and unavailable fields. MCP descriptions may be shortened and alternate dependency paths omitted; do not reconstruct missing evidence. Plugin v1 paths are target-relative without a Git-root offset, so the importer keeps them in original evidence instead of repository locations. Use a distinct source key for each scan target. Ignore status is a source policy decision, not a Codex assessment or a fix.

For CLI automation, prefer `snyk test --file=package.json --json-file-output=snyk-open-source.json` from the selected repository root. Exit 1 means vulnerabilities were found; stop on other nonzero exits instead of importing a stale file. The existing `--provider snyk` autodetects native JSON (one project or an `--all-projects` array), plugin JSON and Open Source SARIF. Native JSON preserves per-dependency-path records and remediation fields; do not use `--group-issues`. Project errors stop import. Native JSON paths also lack a Git-root offset and stay in original evidence. Only **Open Source SCA vulnerabilities** are imported: licenses, Code, Container, IaC and platform backlog ingestion are outside this adapter.

Use one format consistently per repository, branch and scan target, with a stable source key such as `github.com/example/project/main/root/native-sca`. Plugin, native JSON and SARIF have distinct identities; use separate keys when switching, without claiming cross-format deduplication or removal of older records. Existing `snyk test --sarif-file-output=snyk-open-source.sarif` reports remain a compatibility path. SARIF groups advisory occurrences and exposes one package coordinate, so prefer JSON for acquisition. Its target-relative manifest paths lack a Git-root offset and stay in original evidence with synthetic line numbers, without being projected as repository locations or package manifest paths.

Retain package versions, reported fixed versions, provenance and original evidence without claiming a fix was applied. Known repository claims must match the selected Cloud repository or, when available, a configured local Git remote. Resolve an unknown repository with the user; never infer that an export belongs to the current checkout. Follow [local imports](#import-locally) for preview, confirmation and readback or [Cloud publication](#publish-to-cloud) for upload authorization. All three Snyk formats support either destination.

## Semgrep Code

Prefer native Code/SAST CLI or CI JSON for this reader; use self-contained SARIF 2.1.0 as a compatibility path. JSON retains the original severity better than SARIF. The reader does not accept Platform API, Guardian or MCP response envelopes, or a general Supply Chain or Secrets feed. Select SAST rules or Code-only CI output; identifiable non-SAST records are excluded, but SARIF may omit the product metadata needed to distinguish Secrets.

For a user-requested new scan, use the installed Semgrep CLI from the source repository root with the selected SAST rules: `semgrep scan --config /path/to/sast-rules.yaml --json-output /path/to/semgrep.json .`. Existing CI jobs can produce the same artifact using `--json-output`; authenticated `semgrep ci --code` follows the job's policy and baseline scope. Explain that this generates fresh scan findings, and do not substitute it for a request to retrieve existing Platform findings.

For existing findings, the official [Semgrep Guardian Codex plugin](https://docs.semgrep.dev/semgrep-guardian/ide-setup/codex) can help select and inspect them. Importing its output needs a separate qualified response mapping and complete pagination for the selected repository/ref. The local `semgrep_findings` MCP tool and Platform REST API also use contracts distinct from CLI reports. Do not reshape a summary into a scan report or claim that a limited tool response is a complete export.

Import the native report with `--provider semgrep`, a stable organization/project/branch `--source-key`, and `--source-repository-url` identifying the actual source repository. Use `--to local --repository /path/to/project` for local storage or `--to cloud --repository URL_OR_ID` for Cloud. The source URL is checked against configured local Git remotes or the Cloud destination. Preview with `--dry-run --format json` before confirming the import.

Keep supplied fingerprints. Reimporting the same fingerprint after code moves updates the existing source record with the new range. If the fingerprint is absent or `requires login`, the fallback uses rule, literal path and range: movement creates a second retained record, and the earlier record remains stored. Do not infer a merge or deletion. Read the persisted evidence with `codex-security findings imported /path/to/project --format json` before assessment. Source rule, CWE, snippets, traces and status are vendor evidence, not Codex assessments. Do not infer a report revision from the current checkout. Resolve scan errors and review all exclusions before uploading; do not remove error metadata to force acceptance.

## OpenGrep

Import native OpenGrep JSON with `--provider opengrep`, `--source-repository-url`, and a stable OpenGrep-specific `--source-key`. Preview the destination and scan diagnostics before importing. Local and Cloud imports use the Semgrep provider and retain OpenGrep as the scanner origin.

## GitHub alerts and advisories

Acquire code-scanning findings with `codex-security import github OWNER/REPO --format json` and save its complete JSON output for local import or Cloud publication. This existing collector completes pagination, fetches alert details, and retains the selected ref's instance. In Codex, use the official [GitHub Codex plugin](https://github.com/openai/plugins/tree/main/plugins/github) for discovery and selecting alerts, then pass that selection to the collector. Its GitHub MCP server paginates each list call separately. Do not ask the user to download JSON from a website or reconstruct a code-scanning import envelope from MCP summaries. Use the saved collector output for code-scanning alerts.

The importer uses the user's GitHub CLI authentication and `GH_HOST`; plugin authentication is separate. It defaults to open alerts on the default branch. Use repeated `--github-alert NUMBER` for exact alerts or `--github-ref REF` for another ref. Save complete output without field/token filters or `--full-output`. Reading code-scanning alerts requires a token with Code scanning alerts read permission (classic: `security_events`, or `public_repo` for public repositories), along with repository access.

For Dependabot, follow the [repository alert export guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/github-dependabot.md) to save the native REST alert records from one repository. The read-only export requires Dependabot alerts read permission. Preview the file with `publish findings FILE --provider github`, the intended destination and a separate source key such as `github.com/example/project/dependabot`.

**GHSA import stages advisory evidence for investigation; it does not establish an installed dependency or applicability to the destination repository.** Keep advisories separate from code scanning. `codex-security import github-advisories OWNER/REPO --format json` reads published repository disclosures by default. Repeated `--github-advisory GHSA-xxxx-xxxx-xxxx` selects exact IDs; `--github-state draft|triage|closed` explicitly selects an unpublished list and cannot be combined with exact IDs. Add `--github-advisory-source global` for exact public database IDs. This does not enumerate the global database. Private advisory access needs Repository security advisories read permission and access to those records. Stop on a read failure instead of publishing an incomplete selection.

```sh
codex-security import github example/project --format json > /path/to/alerts.json
codex-security publish findings /path/to/alerts.json \
  --to local --repository /path/to/project --provider github \
  --source-key github.com/example/project/code-scanning --dry-run --format json
codex-security publish findings /path/to/alerts.json \
  --to cloud --repository https://github.com/example/project --provider github \
  --source-key github.com/example/project/code-scanning --dry-run --format json

codex-security import github-advisories example/project \
  --github-advisory-source global --github-advisory GHSA-2345-6789-cfgh \
  --format json > /path/to/advisories.json
codex-security publish findings /path/to/advisories.json \
  --to cloud --repository https://github.com/example/project --provider github \
  --source-key github.com/example/project/security-advisories --dry-run --format json
```

Choose the local or Cloud preview for the intended destination. GHSA input supports the same choice: use `--to local --repository /path/to/project` with the advisory file and source key. Follow [local imports](#import-locally) for confirmation and readback or [Cloud publication](#publish-to-cloud) for upload review.

Use a separate stable source key for each GitHub finding family. Code-scanning identities include the ref; repository alerts and advisories must match the selected Cloud repository or, when available, a configured local Git remote. Global advisories omit source-repository provenance and are bound to the explicit local or Cloud destination for investigation. Preserve original evidence, package ranges and patches; do not infer installed packages or source locations from an advisory. Missing security severity stays `unknown`. Dismissal, resolution and withdrawal are source state, not Codex assessment. Secret-scanning alerts and writeback to GitHub are outside this workflow.

## Publish to Cloud

Resolve the user's destination to a connected GitHub or GitHub Enterprise repository URL or Cloud repository ID, including custom Enterprise hosts. Confirm the intended Cloud account and authorized repository environment before running a preview that can contact Cloud. Use the existing file-backed ChatGPT login; explain a missing or incompatible login rather than changing credential storage automatically.

For another Cloud deployment, read [Deployment settings](references/wiz-import.md#deployment-settings) before previewing. Keep the selected deployment and login throughout the upload.

### Preview and approve

```sh
codex-security publish findings /path/to/selected-wiz-findings.json \
  --to cloud --repository https://github.com/example/project --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

When the preview returns `status: "empty"`, report that there is nothing to upload and stop. For a nonempty preview, show the Cloud API endpoint, account, repository, environments, source namespace, severity counts, and exclusions. Identify the evidence file and make the complete JSON preview available for inspection without pasting a large report into the conversation. Explain that vendor evidence is not a Codex assessment.

Obtain explicit confirmation for this concrete upload, including skipped records. Then run the same command without `--dry-run`, adding `--yes`. Authorization to inspect or assess findings alone does not authorize sending them to Cloud. Keep approval when the user already approved this preview and the input and destination are unchanged.

### Upload and report

Read [Results and recovery](references/wiz-import.md#results-and-recovery), including when the process exits nonzero. After a lost response or retryable failure, repeat the command with unchanged input and destination so the publisher resumes saved requests. A lost response does not mean nothing reached Cloud. A repository reset requires fresh discovery and confirmation before a new publication.

Report verified, unacknowledged, excluded, and failed records distinctly, retaining source IDs and recovery details. Receipts and source-record readback confirm stored vendor evidence; they do not establish a Codex assessment or visibility in the shared Cloud Findings view. Include the returned `cloudUrl` as a clickable repository link when available; do not invent a UI link from the API endpoint.
