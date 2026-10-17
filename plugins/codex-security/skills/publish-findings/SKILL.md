---
name: publish-findings
description: Import selected Wiz findings, GitHub code-scanning alerts, or GHSA security advisories to Codex Security Cloud after previewing the destination and evidence. Supports saved JSON/JSONL, Wiz Code repository vulnerability CSV, and gzip; does not run a scan, assess applicability, or synchronize triage decisions.
---

# Publish external findings

Use the installed `codex-security publish findings` command for both preview and upload. It owns source mapping, Cloud authentication, source versions, and saved request retries. Do not implement another HTTP uploader or put credentials in a command argument.

Cloud destinations currently support connected GitHub and GitHub Enterprise repositories, including custom Enterprise hostnames. Resolve the user's destination to its repository URL or Cloud repository ID; the command accepts either. Confirm that the repository is connected in the intended Cloud account and has an authorized environment. Use the existing file-backed ChatGPT login; explain a missing or incompatible login rather than changing credential storage automatically.

## Wiz findings

Read selected Wiz findings through the user's configured connection or supplied export. Save the actual selected records locally, retaining their IDs and evidence. Finish the requested pagination; if the user selected a subset, save that explicit subset and retain its named collection. The command accepts Wiz Code repository package-vulnerability CSV directly, as well as JSON and normalized JSONL records with `source_finding_id` and `evidence` as described in the CLI documentation. It does not fetch from Wiz or accept other CSV profiles, scan events, workload secrets, cloud configuration, or external network exports.

Use a stable Wiz tenant/finding namespace as `--source-key`. A project filter is selection context, not a new identity. Confirm the selected assets or builds belong to the destination repository; do not infer a scanner branch or revision from the current checkout. Do not publish vendor credentials, unrelated records, or local assessments as original scanner evidence.

For package vulnerability UI exports, use **Vulnerability Findings → Save as → Report**, keeping the repository and finding filters. Select **Repository Branch** (remove the default Virtual Machine selection), **JSON** or comma-separated **CSV**, and **Detailed** columns. Pass supported CSV reports directly to the command; their GitHub `CloudProviderURL` must identify the destination repository branch. The importer retains every original cell in `source_data.row` and uses the reported `ID` as occurrence identity. Download the completed report; gzip compression is supported regardless of the filename extension. **Raw Event** on Code & Build Scans contains scan metadata and cannot supply findings. Do not create a scheduled report or enable notifications or external storage unless requested.

For SAST, repository secrets, and IaC, retain the explicit `data.sastFindings.nodes`, `data.secretInstances.nodes`, or `data.iacFindings.nodes` collection. Bare arrays cannot identify these finding families. Include a verified URL on the source repository metadata or supply `data.versionControlResources.nodes` with matching `repository.id` and `repository.url`. Retain the documented inventory `platform` field; explicit `GITHUB` establishes case-insensitive matching on custom GitHub Enterprise hosts. Resolve conflicting platform or URL metadata for a repository ID before publishing. For secrets, the repository is `resource.typedProperties.repository` and resource type must be `REPOSITORY_BRANCH`. Do not map names, inventory node IDs, `providerID`, or Wiz UUIDs directly to Cloud repository IDs. The importer verifies source URLs against the selected destination; resolve a missing or conflicting mapping before uploading.

Keep raw source records unchanged in `source_data`. New raw occurrence IDs are prefixed `sast:`, `secret:`, or `iac:`; existing package IDs are unchanged. SAST, repository-secret, and IaC CSV reports still require a reviewed mapping of the actual header names into the documented normalized JSONL profile: set `evidence.details.kind` and the verified `details.repository.url`, and use the same prefixed occurrence ID. Select source paths and line numbers explicitly in secret reports; the standard metadata query lacks them. Preserve rule/CWE, range/snippet, detector validation, and IaC comparison fields in the typed details described in the CLI docs. Preserve empty comparison strings. Do not invent missing IDs, severity, revisions, or locations, retrieve credential values, test credentials, or apply suggested fixes. Vendor status, AI verdict, secret validation, introduced commits, and logical IaC resources are evidence, not Codex assessment or proof of runtime deployment.

## GitHub alerts and advisories

Keep code-scanning alerts and GHSA advisories as separate source families. Read code-scanning alerts with the existing `codex-security import github OWNER/REPO --format json` command. It defaults to open alerts on the default branch; use `--github-alert NUMBER` repeatedly for exact alerts or `--github-ref REF` for a selected ref. Save the complete output without field or token filters. The mapper retains the selected instance's ref, revision, detection state, rule, scanner, location and original evidence. Typed source status honors an alert-wide dismissal; otherwise it uses the selected instance's open/fixed state. Dismissal is not a Codex assessment. Missing security severity remains `unknown`; do not turn SARIF error/warning/note into vulnerability ratings.

Read advisories with `codex-security import github-advisories OWNER/REPO --format json`. It defaults to published repository advisories. `--github-advisory GHSA-xxxx-xxxx-xxxx` selects exact repository advisory IDs and may include private drafts only when the user selects them. To list private repository advisories, require the user's explicit state selection using `--github-state draft|triage|closed`. Do not combine a nondefault state with exact IDs. For public database records, use `--github-advisory-source global` with one or more explicit `--github-advisory` IDs; never enumerate or mirror the global database. Both readers are read-only and use the user's GitHub CLI authentication and `GH_HOST` when configured. Stop on a read failure instead of publishing an incomplete selection.

Publish the saved reader output with `--provider github`. Use a stable namespace such as `HOST/OWNER/REPO/code-scanning` or `HOST/OWNER/REPO/security-advisories` as `--source-key`, with separate keys for the two families. Code-scanning identities include the ref; GHSA records retain their advisory identity. Code-scanning and repository advisories must match the selected Cloud repository. Global advisory evidence omits source-repository provenance; the explicit Cloud destination selects where to investigate it. Preserve affected package ranges and patched versions without claiming an installed vulnerable dependency or inventing source locations. The original GHSA/CVE IDs remain evidence, not cross-provider source identities. GitHub dismissal, resolution and advisory withdrawal are not Codex assessments. Do not write back to GitHub or include Dependabot alerts without a separately supported ingestion path.

```sh
codex-security import github example/project --format json > /path/to/alerts.json
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

## Review and publish

For staging or another Cloud deployment, set `CODEX_SECURITY_CLOUD_BASE_URL` to its API root before both preview and upload. If the Cloud page or user supplies its app URL, also set `CODEX_SECURITY_CLOUD_WEB_URL` to that full URL so the command can return a repository Findings link. The UI setting does not change API routing or authentication. Use that deployment's login and an isolated state directory for tests. Verify `cloudApiUrl` and any `cloudUrl` in the preview against the intended deployment; the former is the API endpoint and the latter is the UI link. Saved retries are separated by deployment. The native scan setting `CODEX_SECURITY_CLOUD_PUBLISH_URL` does not route vendor imports. Never fall back to production when staging is unavailable.

```sh
codex-security publish findings /path/to/selected-wiz-findings.json \
  --to cloud --repository https://github.com/example/project --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

Show a concise preview of the Cloud API endpoint, account, repository, environments, source namespace, severity counts, and exclusions. Identify the saved evidence file and let the user inspect the complete JSON preview; do not paste an entire large report into the conversation. Explain that imported vendor evidence is not a Codex assessment. Obtain explicit confirmation for this upload, including any skipped records, then run the same command without `--dry-run`, adding `--yes`. Existing authorization to inspect or assess findings alone does not authorize sending them to Cloud. A user who already approved the concrete preview need not approve it again.

After a lost response or retryable failure, repeat the same command with unchanged input and destination. The publisher resends only unacknowledged requests, using their saved IDs and bodies. Existing findings keep their original Cloud environment even if the repository’s default changes. After a repository reset, stop and show the error; require fresh discovery and confirmation before a new publication. Report partial failures and retain their explanations. A successful import stores vendor evidence; it does not establish that Codex assessed the finding or that the vulnerability is exploitable. Include the returned `cloudUrl` as a clickable Findings link. If it is absent, direct the user to Findings in their intended Cloud app; do not derive a UI URL from the API endpoint or invent a link.

Read the result even when the process exits nonzero. `complete` exits 0, `partial` exits 1 for local exclusions or final item failures, and `interrupted` exits 2 while preserving acknowledged counts and receipts. Report `failures` by vendor source ID, distinguish `verified` from `unacknowledged`, and retain `savedSubmission` and the recovery error. A lost response does not mean that no findings reached Cloud. Preparation failures use `failed`; cancellation keeps the normal signal exit code. Terminal progress goes to stderr and does not replace the JSON result.
