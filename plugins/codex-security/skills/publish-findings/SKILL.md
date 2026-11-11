---
name: publish-findings
description: Preview and import scanner findings, including issues selected in the SonarQube plugin, into the local workbench or Codex Security Cloud.
---

# Publish external findings

Use `codex-security import sonar` for [live SonarQube Cloud issues](#sonarqube-cloud-issues) or a capture saved by that command. Use `codex-security publish findings` for native scanner exports, including Sonar `/api/issues/search` pages with `--provider sonar`. Select the requested destination. The CLI owns source mapping, persistence, and Cloud authentication and retries. Do not implement another store or uploader or put credentials in command arguments.

## Select the evidence

Use a supplied report, connected tool or signed-in CLI that provides the requested native records for the selected account, repository and ref. Follow the [scanner import guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/README.md) to narrow broader reports and verify the selection in the JSON preview. Use a direct API only when the provider guide supports its response for the selected destination. Otherwise ask for a supported report. A fresh scan produces new findings. Keep the original records and complete the requested pagination. A JSON summary or a different product's API response is not interchangeable with the documented report. Use SARIF or CSV only when the installed provider reader supports that profile and native JSON is unavailable or the user supplies that format. Do not convert a richer JSON report to SARIF for import.

Use the same acquisition format for repeated imports. Check the provider's identity rules before switching formats: another format can create a separate record or replace a richer snapshot with less detail. Importing findings does not reconcile equivalent vulnerabilities across formats. `--format json` controls command output, not the input report format; readers detect their supported inputs.

## Import locally

Use the checkout path with `--repository`. A saved report can be imported locally offline. Use this destination for Tenable One Code Repository captures and CrowdStrike FCS reports. [Supported inputs by provider](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/README.md#choose-your-scanner)

```sh
codex-security publish findings /path/to/selected-wiz-findings.json \
  --to local --repository /path/to/project --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

Show the repository, source namespace, normalized evidence, and exclusions. For a zero-record preview, report whether the input is empty or failed and stop. After confirmation, repeat without `--dry-run`, adding `--yes`. Keep approval when the user already approved this preview and the input and destination are unchanged.

Read the stored evidence with `codex-security findings imported /path/to/project --format json`; the repository defaults to the current directory. Report created, updated, unchanged, and excluded counts, including exclusion reasons when the command exits 1.

Local records remain unassessed source evidence, separate from `findings list` and completed scans. Repeated imports use the same repository/provider/source-key/source-ID identity; omitted records remain stored. When a source repository URL and local Git remotes are available, the URL must match a remote. Local import does not publish to Cloud or automatically investigate or patch findings.

## Trivy dependency vulnerabilities

Use `--provider trivy` with a saved schema-v2 repository or filesystem report (JSON or gzip). Preview with a stable project/branch source key and `--trivy-scan-root` relative to the checkout (`.` for the whole checkout). Omit the root only when the report's Git metadata corroborates a remote repository scan. Check the source, package paths and exclusions before importing. Trivy's `fixed` status identifies an available upstream fix. [Trivy import guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/trivy.md)

## CrowdStrike FCS IaC findings

Use `--provider crowdstrike` with a saved FCS CLI 4.x `fcs scan iac` JSON report, such as one supplied by the user or a CI artifact from the [FCS GitHub Action](https://github.com/CrowdStrike/fcs-action). For a user-requested new scan, run the installed `fcs` CLI from the directory to import into: `fcs scan iac --path . --report-formats json --output-path /path/to/private/fcs-report`. FCS writes detection paths relative to its working directory. A nonzero exit can mean that detections matched `--fail-on` or that the scan failed; import only the `*-scan-results.json` file that the run reports in `Results saved to file`. If `fcs` is not on `PATH`, do not download or install it, and do not pass Falcon credentials in command arguments. Ask for a saved report, or for the user to install and configure the FCS CLI.

Import with `--to local` and `--repository` set to the scanned directory; it does not need to be a Git checkout. Every detection's file must exist there with the content that FCS scanned. If the import names a changed file, scan again or select the scanned commit. Add `--source-repository-url` only for a verified repository URL. It adds typed IaC and secret details, and it must match a fetch remote when the directory is a Git checkout. Use a stable project/branch source key. Image scan reports and Cloud publication are not supported. [CrowdStrike import guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/crowdstrike.md)

## Amazon Inspector repository findings

Use `--provider inspector` and `--source-repository-url` with a complete Inspector2 ListFindings export for one Code Security repository. If it contains only a project ARN and name, pass the full `--inspector-project-arn ARN` verified for that Git URL in the SCM integration. Supply the same ARN when resuming a pending Cloud submission. Self-managed GitLab is supported locally.

## AWS Continuum code findings

Use `--provider continuum` and `--source-repository-url` for an AWS Continuum for Code Vulnerabilities export. Verify which repository owns each selected finding. Use `aws continuum get-code-finding` for a selected ID, or `list-code-findings` with automatic pagination when every row belongs to the requested repository. Reuse the same source key for that environment and repository. [Continuum import guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/continuum.md)

## Black Duck SCA project-version vulnerabilities

Use `--provider blackduck` for a BOM-6 vulnerable-components export from one project version. Supply `--source-repository-url` after verifying the project version maps to that repository. Keep the same source key on replay and preview the destination before importing.

## Checkmarx SAST

Use `--provider checkmarx` for a Checkmarx One CLI JSON or self-managed CxSAST XML report. To retrieve a completed scan, follow the [Checkmarx collection instructions](references/checkmarx-import.md). Collection retrieves the full scan. If the user wants a subset, ask for a filtered vendor export. Before fetching CxSAST XML, verify the scan ID, project and owning team on the selected server.

Preview the report for the verified repository and ref with `--dry-run --format json`. After confirmation, use the same report path and source key for the import and any retries.

## Veracode Static Analysis policy findings

Use `--provider veracode` with all Findings API pages for one application’s STATIC policy findings. Verify that the application maps to the repository named by `--source-repository-url`. Keep the source key stable for that application and preview the import before writing.

## Endor Labs findings

Use authenticated `endorctl` for one verified project and context. Omit `--field-mask` to keep complete native Finding objects. Replace `/path/to/private/reports` with a private directory outside the checkout.

```sh
out=$(mktemp -d "/path/to/private/reports/endor.XXXXXX") &&
  endorctl api list --resource Finding --namespace "YOUR_NAMESPACE" \
    --filter 'context.type==CONTEXT_TYPE_MAIN and spec.project_uuid=="PROJECT_UUID"' \
    --list-all --output-type json > "$out/findings.tmp" &&
  mv "$out/findings.tmp" "$out/endor-findings.json" &&
  printf '%s\n' "$out/endor-findings.json"
```

Preview the completed file with `--provider endor` and a stable source key such as `YOUR_NAMESPACE/PROJECT_UUID/main`. Match the project to the destination repository. For another branch or scan context, change the filter and use a distinct source key. The [official Endor Labs Agent Kit for Codex](https://github.com/endorlabs/ai-plugins/tree/main/plugins/codex/endor-labs-agent-kit) can help with setup and investigation; its summaries, counts and field-masked results do not replace complete Finding objects. The [CLI API](https://docs.endorlabs.com/developers-api/cli/commands/api) supplies the export. The importer reads that saved file; it does not maintain an Endor API connection or write changes back to Endor.

Native JSON retains severity, scanned commit, package and advisory data, and primary SAST/AI SAST locations. Existing self-contained endorctl SARIF is a lossy compatibility format that retains finding UUIDs and links; unavailable severity or revisions stay unknown. Both formats use the Endor UUID within the selected repository and source key as identity. Importing SARIF after native JSON updates the same record by replacing its evidence snapshot, not merging it: native detail absent from SARIF is removed from that snapshot. Use native JSON consistently for ongoing imports. Keep the original evidence and inspect exclusions. Imported records remain unassessed source evidence. Follow the [local](#import-locally) or [Cloud](#publish-to-cloud) workflow for the chosen destination.

## Wiz findings

Read [Wiz import formats](references/wiz-import.md#finding-formats) before preparing input. Use an authorized [Wiz MCP](https://www.wiz.io/blog/introducing-wiz-mcp) or Wiz API connection; a configured plugin may provide it, but do not assume an official Codex plugin is available. Prefer supported native JSON. Inspect actual records, finish the requested pagination, and save only the selected evidence with its original occurrence IDs. A supplied export is also supported. Summaries, Wiz Issues, and local CLI scan results are not automatically supported finding records.

Validate the acquisition path against actual responses from an authorized Wiz tenant; local parser checks do not establish that qualification. Direct CSV input covers repository package vulnerabilities (SCA) only, not SAST or cloud posture findings, and does not provide a complete Wiz code-to-cloud integration.

Use a stable Wiz tenant/finding namespace as `--source-key`; a project filter does not create a new identity. Confirm the selected assets or builds belong to the destination repository. Do not infer source branches or revisions from the current checkout, invent missing evidence, or import vendor credentials, unrelated records, or local assessments as original scanner evidence. Do not retrieve or test credentials or apply suggested fixes.

## Snyk findings

For an existing monitored Open Source or Code project, follow the [Snyk Issues API import guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/snyk.md#existing-issues-from-snyk). With a read-authorized `SNYK_TOKEN`, run `codex-security import snyk PROJECT_ID --snyk-org ORG_ID --source-repository-url URL --format json`. Add `--snyk-product code` for a Code project and `--snyk-api-origin` for a regional deployment. Save the complete successful JSON output, preview with `publish findings --provider snyk` and the requested `--to local` or `--to cloud` destination, then confirm the import.

Prefer the [official Snyk Codex plugin](https://github.com/snyk/studio-recipes/tree/main/plugins/codex) when available. Ask its `snyk-findings-export` skill for **SCA only from the repository’s Git root** and save the `snyk-findings-export/v1` bundle. It scans the current workspace through local MCP; it cannot list existing platform projects or retrieve earlier findings. Do not substitute a fresh scan for a request to read a platform backlog. Authentication, relevant Snyk access and the project's package tooling are required.

Import the bundle with `--provider snyk`, choosing `--to local --repository /path/to/project` or `--to cloud --repository https://github.com/example/project`. Use a stable repository/branch/scan-target/acquisition namespace such as `github.com/example/project/main/root/plugin-sca`. Check the bundle's scan outcomes, collection completeness and limitations alongside the preview. Only Open Source SCA vulnerability records are supported; other categories are explicit exclusions. Preserve the native MCP record and unavailable fields. MCP descriptions may be shortened and alternate dependency paths omitted; do not reconstruct missing evidence. Plugin v1 paths are target-relative without a Git-root offset, so the importer keeps them in original evidence instead of repository locations. Use a distinct source key for each scan target. Ignore status is a source policy decision, not a Codex assessment or a fix.

For CLI automation, prefer `snyk test --file=package.json --json-file-output=snyk-open-source.json` from the selected repository root. Exit 1 means vulnerabilities were found; stop on other nonzero exits instead of importing a stale file. The existing `--provider snyk` autodetects native JSON (one project or an `--all-projects` array), plugin JSON and Open Source SARIF. Native JSON preserves per-dependency-path records and remediation fields; do not use `--group-issues`. Project errors stop import. Native JSON paths also lack a Git-root offset and stay in original evidence. These workspace scan formats import Open Source SCA vulnerabilities.

Use one format consistently per repository, branch and scan target, with a stable source key such as `github.com/example/project/main/root/native-sca`. Plugin, native JSON and SARIF have distinct identities; use separate keys when switching, without claiming cross-format deduplication or removal of older records. Existing `snyk test --sarif-file-output=snyk-open-source.sarif` reports remain a compatibility path. SARIF groups advisory occurrences and exposes one package coordinate, so prefer JSON for acquisition. Its target-relative manifest paths lack a Git-root offset and stay in original evidence with synthetic line numbers, without being projected as repository locations or package manifest paths.

Retain package versions, reported fixed versions, provenance and original evidence without claiming a fix was applied. Known repository claims must match the selected Cloud repository or, when available, a configured local Git remote. Resolve an unknown repository with the user; never infer that an export belongs to the current checkout. Follow [local imports](#import-locally) for preview, confirmation and readback or [Cloud publication](#publish-to-cloud) for upload authorization. Snyk workspace reports and monitored-project exports support local and Cloud import.

## Semgrep Code

Prefer native Code/SAST CLI or CI JSON for this reader; use self-contained SARIF 2.1.0 as a compatibility path. JSON retains the original severity better than SARIF. Use the selected Guardian workflow below for existing Code or Supply Chain findings. Select SAST rules or Code-only CI output; identifiable non-SAST records are excluded, but SARIF may omit the product metadata needed to distinguish Secrets.

For a user-requested new scan, use the installed Semgrep CLI from the source repository root with the selected SAST rules: `semgrep scan --config /path/to/sast-rules.yaml --json-output /path/to/semgrep.json .`. Existing CI jobs can produce the same artifact using `--json-output`; authenticated `semgrep ci --code` follows the job's policy and baseline scope. Explain that this generates fresh scan findings, and do not substitute it for a request to retrieve existing Platform findings.

For a selection of existing Code or Supply Chain findings in Codex, use the signed-in [Semgrep Guardian plugin](https://docs.semgrep.dev/semgrep-guardian/quickstart). Call its `get_semgrep_sast_findings` or `get_semgrep_supply_chain_findings` tool with the selected `deployment_name`, `repository_name` and full `ref`. Preserve any state and severity filters used for that selection. Reuse an existing successful tool result when its scope is explicit. If a selected ID is missing, report it and check the query scope and filters with the user. A project-wide fetch is a separate request.

Save a private JSON capture outside the checkout with `format: "semgrep-guardian-selection/v1"`, the verified `sourceRepositoryUrl`, the MCP `request` (tool `name` and `arguments`), the exact selected string `findingIds`, and `structuredContent: { findings: [...] }` containing the original selected tool rows. Match IDs exactly and keep the tool's repository, ref and evidence. Guardian returns a repository name, so verify its SCM URL for the local checkout or selected Cloud repository. Use the [Guardian preview command](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/semgrep.md#import-selected-guardian-findings) for the intended destination and confirm after reviewing the selection. Guardian handles sign-in for this workflow. Guardian and Web API IDs remain separate even when the strings match.

For a whole project and ref, use the [Web API collector](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/semgrep.md#collect-a-platform-project-and-branch) with its read-capable token. If the user supplies [saved Web API responses](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/semgrep.md#existing-platform-findings), use the IDs from those records. Preview Web API findings against the requested local or Cloud repository.

Import the native report with `--provider semgrep`, a stable organization/project/branch `--source-key`, and `--source-repository-url` identifying the actual source repository. Use `--to local --repository /path/to/project` for local storage or `--to cloud --repository URL_OR_ID` for Cloud. The source URL is checked against configured local Git remotes or the Cloud destination. Preview with `--dry-run --format json` before confirming the import.

Keep supplied fingerprints. Reimporting the same fingerprint after code moves updates the existing source record with the new range. If the fingerprint is absent or `requires login`, the fallback uses rule, literal path and range: movement creates a second retained record, and the earlier record remains stored. Do not infer a merge or deletion. Read the persisted evidence with `codex-security findings imported /path/to/project --format json` before assessment. Source rule, CWE, snippets, traces and status are vendor evidence, not Codex assessments. Do not infer a report revision from the current checkout. Resolve scan errors and review all exclusions before uploading; do not remove error metadata to force acceptance.

## OpenGrep

Import native OpenGrep JSON with `--provider opengrep`, `--source-repository-url`, and a stable OpenGrep-specific `--source-key`. Preview the destination and scan diagnostics before importing. Local and Cloud imports use the Semgrep provider and retain OpenGrep as the scanner origin.

## SonarQube Cloud issues

For “import these Sonar findings,” carry over the Sonar project, branch or PR, and the exact issue keys selected in the [SonarQube plugin for Codex](https://www.sonarsource.com/blog/now-available-sonarqube-plugin-for-codex/). Use the keys from the underlying Sonar result. If only a formatted table remains, resolve the selected rows against the same project and ref and ask about ambiguous matches. A rule can occur more than once. Never turn a selection into a project-wide import.

From the intended checkout, preview the selection using the developer's authenticated `sonar` CLI. Use `--sonar-pull-request` in place of `--sonar-branch` for a PR. Omit `--sonar-issue` only when the user wants the project's open security issues. If the project has no verified SCM binding, confirm the repository URL that belongs to the project and pass it with `--source-repository-url`.

```sh
codex-security import sonar --sonar-project example_project --sonar-branch main \
  --sonar-issue ISSUE_A --sonar-issue ISSUE_B --dry-run --format json
```

Pass `--to cloud` at preview time if the user also requested Cloud publication. Show the selected issues and exclusions, the local repository, and any Cloud destination as described under [Publish to Cloud](#publish-to-cloud). The preview returns a private evidence file in `capture`. After confirmation, run `codex-security import sonar CAPTURE --yes` for local import. For Cloud, use the exact `capture` from the successful Cloud preview and add `--to cloud`. If the account, repository, or environment changes, show a fresh preview and ask for confirmation. If Cloud is unavailable, finish the requested local import and report the Cloud error. For a request to publish an existing import, start with its capture. Report the saved path so the developer can resume.

Sonar authentication is required only for a live fetch. If the local CLI lacks a login, direct the user to `sonar auth login` and keep the selection. A hosted MCP connection can help identify issues, but its issue summaries omit flow evidence. Use the signed-in CLI or a saved Codex Security Sonar capture to complete the import. If `codex-security` is absent, ask the user to install it from a trusted directory and invoke that installed executable in the checkout.

## GitHub alerts and advisories

Acquire code-scanning findings with `codex-security import github OWNER/REPO --format json` and save its complete JSON output for local import or Cloud publication. This existing collector completes pagination, fetches alert details, and retains the selected ref's instance. In Codex, use the official [GitHub Codex plugin](https://github.com/openai/plugins/tree/main/plugins/github) for discovery and selecting alerts, then pass that selection to the collector. Its GitHub MCP server paginates each list call separately. Do not ask the user to download JSON from a website or reconstruct a code-scanning import envelope from MCP summaries. Use the saved collector output for code-scanning alerts.

The importer uses the user's GitHub CLI authentication and `GH_HOST`; plugin authentication is separate. It defaults to open alerts on the default branch. Use repeated `--github-alert NUMBER` for exact alerts or `--github-ref REF` for another ref. Save complete output without field/token filters or `--full-output`. Reading code-scanning alerts requires a token with Code scanning alerts read permission (classic: `security_events`, or `public_repo` for public repositories), along with repository access.

For Dependabot, follow the [repository alert export guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/github-dependabot.md) to save the native REST alert records from one repository. The read-only export requires Dependabot alerts read permission. Preview the file with `publish findings FILE --provider github`, the intended destination and a separate source key such as `github.com/example/project/dependabot`.

**GHSA import stages advisory evidence for investigation; it does not establish an installed dependency or applicability to the destination repository.** Keep advisories separate from code scanning. `codex-security import github-advisories OWNER/REPO --format json` reads published repository disclosures by default. Repeated `--github-advisory GHSA-xxxx-xxxx-xxxx` selects exact IDs; `--github-state draft|triage|closed` explicitly selects an unpublished list and cannot be combined with exact IDs. Add `--github-advisory-source global` for exact public database IDs. This does not enumerate the global database. Private advisory access needs Repository security advisories read permission and access to those records. Stop on a read failure instead of publishing an incomplete selection.

Save the selected collector’s output in a private file outside the checkout. After collection succeeds, use `--provider github` and the [local](#import-locally) or [Cloud](#publish-to-cloud) workflow for the requested destination. Keep a separate stable source key for each family, such as `github.com/example/project/code-scanning` or `github.com/example/project/security-advisories`.

Code-scanning identities include the ref; repository alerts and advisories must match the selected Cloud repository or, when available, a configured local Git remote. Global advisories omit source-repository provenance and are bound to the explicit local or Cloud destination for investigation. Preserve original evidence, package ranges and patches; do not infer installed packages or source locations from an advisory. Missing security severity stays `unknown`. Dismissal, resolution and withdrawal are source state, not Codex assessment. Secret-scanning alerts and writeback to GitHub are outside this workflow.

## Publish to Cloud

Resolve the user's destination to a connected GitHub or GitHub Enterprise repository URL or Cloud repository ID, including custom Enterprise hosts. Confirm the intended Cloud account and authorized repository environment before running a preview that can contact Cloud. Use the existing file-backed ChatGPT login; explain a missing or incompatible login rather than changing credential storage automatically.

For an alternate Cloud deployment, configure the [deployment settings](#deployment-settings) before previewing. Keep the selected deployment and login throughout the upload.

### Preview and approve

```sh
codex-security publish findings /path/to/selected-wiz-findings.json \
  --to cloud --repository https://github.com/example/project --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

When the preview returns `status: "empty"`, report that there is nothing to upload. For a nonempty preview, show the endpoint, account, repository, source key, severity counts and exclusions. The `privateImport` entry describes the report for the user’s private inbox. For the repository publisher, `requests` identifies the environments that will receive the records. Identify the evidence file and make the complete JSON preview available for inspection without pasting a large report into the conversation. Explain that vendor evidence is not a Codex assessment.

Obtain explicit confirmation for this concrete upload, including skipped records. Then run the same command without `--dry-run`, adding `--yes`. Authorization to inspect or assess findings alone does not authorize sending them to Cloud. Keep approval when the user already approved this preview and the input and destination are unchanged.

### Upload and report

Read the structured result even when the process exits nonzero. Progress appears on stderr. For a private inbox import, check `privateJob.status`, the job counts, errors and unprocessed records. A completed job can have `verified: 0`.

For the repository publisher, report `verified` for findings the CLI confirmed by readback and `unacknowledged` for records without a receipt. Use `failures` to identify records the publisher rejected. For either destination, include exclusions and any `savedSubmission` checkpoint. [Result fields and exit codes](https://github.com/openai/codex-security/blob/main/sdk/typescript/docs/cli.md#results-and-exit-codes)

A private finding can be assessed against the repository and published to shared Findings. Link to the returned `cloudUrl` when available.

### Resume an interrupted upload

Preview the original file again with the same source key, repository, account, endpoint and state directory. If `resumed` is true, the CLI reuses the saved submission. If a reset or changed destination requires a new submission, review the new preview before confirming. [Retry a Cloud submission](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/schema-guide.md#retry-a-cloud-submission)

### Deployment settings

Set `CODEX_SECURITY_CLOUD_BASE_URL` to the deployment's API root for preview and upload. Use its login and an isolated state directory for tests. If the user or Cloud page supplies an app URL, set `CODEX_SECURITY_CLOUD_WEB_URL` to that full URL. This setting controls the returned UI link. The API root and login still determine routing and authentication.

Check the preview's `cloudApiUrl` and any `cloudUrl` against the intended API endpoint and app. Saved retries are scoped to the deployment. `CODEX_SECURITY_CLOUD_PUBLISH_URL` applies only to native scan publication.
