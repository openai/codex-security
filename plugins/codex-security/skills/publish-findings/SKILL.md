---
name: publish-findings
description: Import selected Snyk Open Source findings, Semgrep Code CLI/CI reports, Endor Labs findings, GitHub code-scanning alerts or GHSA advisories, or Wiz package vulnerabilities, SAST, repository secrets, and IaC findings locally or to Codex Security Cloud after previewing the destination and evidence. Prefers native JSON; also supports Snyk plugin SCA bundles, Snyk Open Source and Semgrep Code SARIF, endorctl SARIF, saved GitHub JSON/JSONL, Wiz normalized JSONL and repository package-vulnerability CSV, and gzip; does not import workload secrets or cloud configuration, run a scan, assess findings, or synchronize triage decisions.
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

Use an authorized [Wiz MCP](https://www.wiz.io/blog/introducing-wiz-mcp) or Wiz API connection to acquire selected findings and save the supported native JSON with its original occurrence IDs and evidence. A configured plugin may provide that connection; do not assume an official Codex plugin is available. Inspect the returned fields: a summary, Wiz Issue, or local Wiz CLI scan result is not automatically a supported finding record. Do not invent fields to make a response fit the mapper.

Finish the requested pagination; for an explicit subset, retain that selection and its named collection. Prefer the supported native JSON. Normalized JSONL with `source_finding_id` and `evidence` and the documented repository package-vulnerability CSV profile are compatibility inputs; gzip is supported for each format. **CSV support covers repository package vulnerabilities (SCA) only, not SAST or cloud posture findings.** It does not provide a complete Wiz code-to-cloud integration. The command does not fetch from Wiz or accept other CSV profiles, scan events, workload secrets, cloud configuration, or external network exports. The acquisition path still needs validation against actual responses from an authorized Wiz tenant; local parser checks do not establish that qualification.

Use a stable Wiz tenant/finding namespace as `--source-key`. A project filter is selection context, not a new identity. Confirm the selected assets or builds belong to the destination repository; do not infer a scanner branch or revision from the current checkout. Do not publish vendor credentials, unrelated records, or local assessments as original scanner evidence.

For an existing package vulnerability report or when a UI export is needed, use **Vulnerability Findings → Save as → Report**, keeping the repository and finding filters. Select **Repository Branch** (remove the default Virtual Machine selection), **JSON** or comma-separated **CSV**, and **Detailed** columns. Pass supported CSV reports directly to the command; their GitHub `CloudProviderURL` must identify the destination repository branch. The importer retains every original cell in `source_data.row` and uses the reported `ID` as occurrence identity. Download the completed report; gzip compression is supported regardless of the filename extension. **Raw Event** on Code & Build Scans contains scan metadata and cannot supply findings. Do not create a scheduled report or enable notifications or external storage unless requested.

For SAST, repository secrets, and IaC, retain the explicit `data.sastFindings.nodes`, `data.secretInstances.nodes`, or `data.iacFindings.nodes` collection. Bare arrays cannot identify these finding families. Include a verified URL on the source repository metadata or supply `data.versionControlResources.nodes` with matching `repository.id` and `repository.url`. Retain the documented inventory `platform` field; explicit `GITHUB` establishes case-insensitive matching on custom GitHub Enterprise hosts. Resolve conflicting platform or URL metadata for a repository ID before importing. For secrets, the repository is `resource.typedProperties.repository` and resource type must be `REPOSITORY_BRANCH`. Do not map names, inventory node IDs, `providerID`, or Wiz UUIDs directly to Cloud repository IDs. Source URLs must match the selected Cloud repository or, for local import when Git remotes are configured, one of those remotes. Resolve a missing or conflicting source mapping before importing.

Keep raw source records unchanged in `source_data`. New raw occurrence IDs are prefixed `sast:`, `secret:`, or `iac:`; existing package IDs are unchanged. SAST, repository-secret, and IaC CSV reports still require a reviewed mapping of the actual header names into the documented normalized JSONL profile: set `evidence.details.kind` and the verified `details.repository.url`, and use the same prefixed occurrence ID. Select source paths and line numbers explicitly in secret reports; the standard metadata query lacks them. Preserve rule/CWE, range/snippet, detector validation, and IaC comparison fields in the typed details described in the CLI docs. Preserve empty comparison strings. Do not invent missing IDs, severity, revisions, or locations, retrieve credential values, test credentials, or apply suggested fixes. Vendor status, AI verdict, secret validation, introduced commits, and logical IaC resources are evidence, not Codex assessment or proof of runtime deployment.

## Snyk Open Source

Prefer the [official Snyk Codex plugin](https://github.com/snyk/studio-recipes/tree/main/plugins/codex) when available. Ask its `snyk-findings-export` skill for **SCA only from the repository’s Git root** and save the `snyk-findings-export/v1` bundle. It scans the current workspace through local MCP; it cannot list existing platform projects or retrieve earlier findings. Do not substitute a fresh scan for a request to read a platform backlog. Authentication, relevant Snyk access and the project's package tooling are required.

Import the bundle with `--provider snyk`, choosing `--to local --repository /path/to/project` or `--to cloud --repository https://github.com/example/project`. Use a stable repository/branch/scan-target/acquisition namespace such as `github.com/example/project/main/root/plugin-sca`. Check the bundle's scan outcomes, collection completeness and limitations alongside the preview. Only Open Source SCA vulnerability records are supported; other categories are explicit exclusions. Preserve the native MCP record and unavailable fields. MCP descriptions may be shortened and alternate dependency paths omitted; do not reconstruct missing evidence. Plugin v1 paths are target-relative without a Git-root offset, so the importer keeps them in original evidence instead of repository locations. Use a distinct source key for each scan target. Ignore status is a source policy decision, not a Codex assessment or a fix.

For CLI automation, prefer `snyk test --file=package.json --json-file-output=snyk-open-source.json` from the selected repository root. Exit 1 means vulnerabilities were found; stop on other nonzero exits instead of importing a stale file. The existing `--provider snyk` autodetects native JSON (one project or an `--all-projects` array), plugin JSON and Open Source SARIF. Native JSON preserves per-dependency-path records and remediation fields; do not use `--group-issues`. Project errors stop import. Native JSON paths also lack a Git-root offset and stay in original evidence. Only **Open Source SCA vulnerabilities** are imported: licenses, Code, Container, IaC and platform backlog ingestion are outside this adapter.

Use one format consistently per repository, branch and scan target, with a stable source key such as `github.com/example/project/main/root/native-sca`. Plugin, native JSON and SARIF have distinct identities; use separate keys when switching, without claiming cross-format deduplication or removal of older records. Existing `snyk test --sarif-file-output=snyk-open-source.sarif` reports remain a compatibility path. SARIF groups advisory occurrences and exposes one package coordinate, so prefer JSON for acquisition. Its target-relative manifest paths lack a Git-root offset and stay in original evidence with synthetic line numbers, without being projected as repository locations or package manifest paths.

Retain package versions, reported fixed versions, provenance and original evidence without claiming a fix was applied. Known repository claims must match the selected Cloud repository or, when available, a configured local Git remote. Resolve an unknown repository with the user; never infer that an export belongs to the current checkout. Follow [local imports](#local-imports) for preview, confirmation and readback or [Cloud publication](#review-and-publish-to-cloud) for upload authorization. All three Snyk formats support either destination.

## Semgrep Code

Prefer native Code/SAST CLI or CI JSON for this reader; use self-contained SARIF 2.1.0 as a compatibility path. JSON retains the original severity better than SARIF. The reader does not accept Platform API, Guardian or MCP response envelopes, or a general Supply Chain or Secrets feed. Select SAST rules or Code-only CI output; identifiable non-SAST records are excluded, but SARIF may omit the product metadata needed to distinguish Secrets.

For a user-requested new scan, use the installed Semgrep CLI from the source repository root with the selected SAST rules: `semgrep scan --config /path/to/sast-rules.yaml --json-output /path/to/semgrep.json .`. Existing CI jobs can produce the same artifact using `--json-output`; authenticated `semgrep ci --code` follows the job's policy and baseline scope. Explain that this generates fresh scan findings, and do not substitute it for a request to retrieve existing Platform findings.

For existing findings, the official [Semgrep Guardian Codex plugin](https://docs.semgrep.dev/semgrep-guardian/ide-setup/codex) can help select and inspect them. Importing its output needs a separate qualified response mapping and complete pagination for the selected repository/ref. The local `semgrep_findings` MCP tool and Platform REST API also use contracts distinct from CLI reports. Do not reshape a summary into a scan report or claim that a limited tool response is a complete export.

Import the native report with `--provider semgrep`, a stable organization/project/branch `--source-key`, and `--source-repository-url` identifying the actual source repository. Use `--to local --repository /path/to/project` for local storage or `--to cloud --repository URL_OR_ID` for Cloud. The source URL is checked against configured local Git remotes or the Cloud destination. Preview with `--dry-run --format json` before confirming the import.

Keep supplied fingerprints. Reimporting the same fingerprint after code moves updates the existing source record with the new range. If the fingerprint is absent or `requires login`, the fallback uses rule, literal path and range: movement creates a second retained record, and the earlier record remains stored. Do not infer a merge or deletion. Read the persisted evidence with `codex-security findings imported /path/to/project --format json` before assessment. Source rule, CWE, snippets, traces and status are vendor evidence, not Codex assessments. Do not infer a report revision from the current checkout. Resolve scan errors and review all exclusions before uploading; do not remove error metadata to force acceptance.

## GitHub alerts and advisories

Acquire code-scanning findings with `codex-security import github OWNER/REPO --format json` and save its complete JSON output for local import or Cloud publication. This existing collector completes pagination, fetches alert details, and retains the selected ref's instance. In Codex, use the official [GitHub Codex plugin](https://github.com/openai/plugins/tree/main/plugins/github) for discovery and selecting alerts, then pass that selection to the collector. Its GitHub MCP server paginates each list call separately. Do not ask the user to download JSON from a website or reconstruct an import envelope from MCP summaries; raw MCP/API responses are not accepted by `--provider github`.

The importer uses the user's GitHub CLI authentication and `GH_HOST`; plugin authentication is separate. It defaults to open alerts on the default branch. Use repeated `--github-alert NUMBER` for exact alerts or `--github-ref REF` for another ref. Save complete output without field/token filters or `--full-output`. Reading code-scanning alerts requires a token with Code scanning alerts read permission (classic: `security_events`, or `public_repo` for public repositories), along with repository access.

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

Choose the local or Cloud preview for the intended destination. GHSA input supports the same choice: use `--to local --repository /path/to/project` with the advisory file and source key. Follow [local imports](#local-imports) for confirmation and readback or [Cloud publication](#review-and-publish-to-cloud) for upload review.

Use separate stable source keys for the two families. Code-scanning identities include the ref; repository alerts and advisories must match the selected Cloud repository or, when available, a configured local Git remote. Global advisories omit source-repository provenance and are bound to the explicit local or Cloud destination for investigation. Preserve original evidence, package ranges and patches; do not infer installed packages or source locations from an advisory. Missing security severity stays `unknown`. Dismissal, resolution and withdrawal are source state, not Codex assessment. This path does not import Dependabot or secret-scanning alerts or write back to GitHub.

## Review and publish to Cloud

When publishing to staging or another Cloud deployment, set `CODEX_SECURITY_CLOUD_BASE_URL` to its API root before both preview and upload. If the Cloud page or user supplies its app URL, also set `CODEX_SECURITY_CLOUD_WEB_URL` to that full URL so the command can return a repository link. The UI setting does not change API routing or authentication. Use that deployment's login and an isolated state directory for tests. Verify `cloudApiUrl` and any `cloudUrl` in the preview against the intended deployment; the former is the API endpoint and the latter is the UI link. Saved retries are separated by deployment. The native scan setting `CODEX_SECURITY_CLOUD_PUBLISH_URL` does not route vendor imports. Never fall back to production when staging is unavailable.

```sh
codex-security publish findings /path/to/selected-wiz-findings.json \
  --to cloud --repository https://github.com/example/project --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

Show a concise preview of the Cloud API endpoint, account, repository, environments, source namespace, severity counts, and exclusions. Identify the saved evidence file and let the user inspect the complete JSON preview; do not paste an entire large report into the conversation. Explain that imported vendor evidence is not a Codex assessment. Obtain explicit confirmation for this upload, including any skipped records, then run the same command without `--dry-run`, adding `--yes`. Existing authorization to inspect or assess findings alone does not authorize sending them to Cloud. A user who already approved the concrete preview need not approve it again.

After a lost response or retryable failure, repeat the same command with unchanged input and destination. The publisher resends only unacknowledged requests, using their saved IDs and bodies. Existing findings keep their original Cloud environment even if the repository’s default changes. After a repository reset, stop and show the error; require fresh discovery and confirmation before a new publication. Report partial failures and retain their explanations. Successful receipts and source-record readback confirm stored vendor evidence. They do not establish a Codex assessment or visibility in the shared Cloud Findings view. Include the returned `cloudUrl` as a clickable repository link when available; do not derive a UI URL from the API endpoint or invent a link.

Read the result even when the process exits nonzero. Local imports exit 1 when records were excluded; report their exclusion reasons alongside the stored counts. For Cloud publication, `complete` exits 0, `partial` exits 1 for exclusions or final item failures, and `interrupted` exits 2 while preserving acknowledged counts and receipts. Report `failures` by vendor source ID, distinguish `verified` from `unacknowledged`, and retain `savedSubmission` and the recovery error. A lost response does not mean that no findings reached Cloud. Preparation failures use `failed`; cancellation keeps the normal signal exit code. Terminal progress goes to stderr and does not replace the JSON result.
