---
name: publish-findings
description: Import selected Wiz package vulnerabilities to Codex Security Cloud after previewing the destination and evidence. Supports plain or gzip-compressed vulnerability JSON and normalized JSONL; does not import raw SAST, secrets, or IaC findings, run a scan, or assess findings.
---

# Publish external findings

Use the installed `codex-security publish findings` command for both preview and upload. It owns source mapping, Cloud authentication, source versions, and saved request retries. Do not implement another HTTP uploader or put credentials in a command argument.

Resolve the user's destination to its repository URL or Cloud repository ID; the command accepts either. Confirm that the repository is connected in the intended Cloud account and has an authorized environment. Use the existing file-backed ChatGPT login; explain a missing or incompatible login rather than changing credential storage automatically. Read selected Wiz package vulnerabilities through the user's configured connection or supplied export. Save the actual selected JSON records locally, retaining their IDs and evidence. Finish the requested pagination; if the user selected a subset, save that explicit subset as an array. The command does not fetch from Wiz or accept CSV, SAST, secrets, IaC, or external network exports. The publisher also accepts JSONL records with `source_finding_id` and `evidence` as described in the CLI documentation.

Use a stable Wiz tenant/finding namespace as `--source-key`. A project filter is selection context, not a new identity. Confirm the selected assets or builds belong to the destination repository; do not infer a scanner branch or revision from the current checkout. Do not publish vendor credentials, unrelated records, or local assessments as original scanner evidence.

For Wiz UI exports, use **Vulnerability Findings → Save as → Report**, keeping the repository and finding filters. Select **Repository Branch** (remove the default Virtual Machine selection), **JSON**, and **Detailed** columns. Download the completed report; default gzip compression is supported, even with a `.json` filename. **Raw Event** on Code & Build Scans contains scan metadata and cannot supply findings. Do not create a scheduled report or enable notifications or external storage unless requested.

For staging or another Cloud deployment, set `CODEX_SECURITY_CLOUD_BASE_URL` to its API root before both preview and upload. Use that deployment's login and an isolated state directory for tests. Verify `cloudApiUrl` in the preview; it is the API endpoint, not a Cloud UI link. Saved retries are separated by deployment. The native scan setting `CODEX_SECURITY_CLOUD_PUBLISH_URL` does not route vendor imports. Never fall back to production when staging is unavailable.

```sh
codex-security publish findings /path/to/selected-wiz-findings.json \
  --to cloud --repository https://github.com/example/project --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

Show a concise preview of the Cloud API endpoint, account, repository, environments, source namespace, severity counts, and exclusions. Identify the saved evidence file and let the user inspect the complete JSON preview; do not paste an entire large report into the conversation. Explain that imported vendor evidence is not a Codex assessment. Obtain explicit confirmation for this upload, including any skipped records, then run the same command without `--dry-run`, adding `--yes`. Existing authorization to inspect or assess findings alone does not authorize sending them to Cloud. A user who already approved the concrete preview need not approve it again.

After a lost response or retryable failure, repeat the same command with unchanged input and destination. The publisher resends only unacknowledged requests, using their saved IDs and bodies. Existing findings keep their original Cloud environment even if the repository’s default changes. After a repository reset, stop and show the error; require fresh discovery and confirmation before a new publication. Report partial failures and retain their explanations. A successful import stores vendor evidence; it does not establish that Codex assessed the finding or that the vulnerability is exploitable. Direct the user to the main Findings view in the Codex Security Cloud app to find the repository’s imported Wiz findings; do not invent a direct Findings URL.

Read the result even when the process exits nonzero. `complete` exits 0, `partial` exits 1 for local exclusions or final item failures, and `interrupted` exits 2 while preserving acknowledged counts and receipts. Report `failures` by vendor source ID, distinguish `verified` from `unacknowledged`, and retain `savedSubmission` and the recovery error. A lost response does not mean that no findings reached Cloud. Preparation failures use `failed`; cancellation keeps the normal signal exit code. Terminal progress goes to stderr and does not replace the JSON result.
