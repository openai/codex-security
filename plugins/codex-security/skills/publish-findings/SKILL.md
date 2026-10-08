---
name: publish-findings
description: Publish selected external scanner findings to Codex Security Cloud after previewing the destination and evidence. Supports saved Wiz vulnerability findings and normalized JSONL; does not run a scan or assess findings.
---

# Publish external findings

Use the installed `codex-security publish findings` command for both preview and upload. It owns source mapping, Cloud authentication, source versions, and saved request retries. Do not implement another HTTP uploader or put credentials in a command argument.

Obtain the Cloud repository ID from the user's destination. Read selected Wiz vulnerability findings through the user's configured connection or supplied export. Save the actual selected JSON records locally, retaining their IDs and evidence. Finish the requested pagination; if the user selected a subset, save that explicit subset as an array. The publisher also accepts JSONL records with `source_finding_id` and `evidence` as described in the CLI documentation.

Use a stable Wiz tenant/finding namespace as `--source-key`. A project filter is selection context, not a new identity. Confirm the selected assets or builds belong to the destination repository; do not infer a scanner branch or revision from the current checkout. Do not publish vendor credentials, unrelated records, or local assessments as original scanner evidence.

```sh
codex-security publish findings /path/to/selected-wiz-findings.json \
  --to cloud --repository REPOSITORY_ID --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

Show the destination, selected findings, exclusions, and evidence to the user. Obtain explicit confirmation for this upload, then run the same command without `--dry-run`, adding `--yes`. Existing authorization to inspect or assess findings alone does not authorize sending them to Cloud. A user who already approved the concrete preview need not approve it again.

After a lost response or retryable failure, repeat the same command with unchanged input and destination. The publisher resends its saved request IDs and bodies. After a repository reset, stop and show the error; require fresh discovery and confirmation before a new publication. Report partial failures and retain their explanations. A successful import stores vendor evidence; it does not establish that Codex assessed the finding or that the vulnerability is exploitable.
