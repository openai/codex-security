# Check a scanner import on staging

Use a disposable connected repository and a staging login with permission to import. Record the API revision and, for workspace imports, the worker revision. Keep the report, account ID, preview and receipt in the private QA record.

Build the CLI from the checkout under test. For a Tenable smoke test, make this synthetic report. For another scanner, use its [documented fixture and reader options](README.md).

```bash
pnpm --dir sdk/typescript run build
qa_dir=$(mktemp -d)
asset=10000000-0000-4000-8000-000000000001
printf 'asset_id,asset_class,asset_name\n%s,CODE_REPOSITORY,staging-smoke\n' "$asset" > "$qa_dir/assets.csv"
printf 'asset_id,finding_id,finding_name,severity,state\n%s,00017,Synthetic QA finding,High,ACTIVE\n' "$asset" > "$qa_dir/findings.csv"
python3 examples/tenable-one/capture.py --assets "$qa_dir/assets.csv" \
  --findings "$qa_dir/findings.csv" --asset-id "$asset" \
  --repository-url "${QA_REPOSITORY_URL:?set the staging clone URL}" --output "$qa_dir/selection.json"

publish=(env "CODEX_SECURITY_CLOUD_BASE_URL=${QA_API_ROOT:?set the nonproduction API root}"
  node sdk/typescript/bin/codex-security.mjs publish findings "$qa_dir/selection.json"
  --to cloud --provider tenable --repository "$QA_REPOSITORY_URL"
  --source-repository-url "$QA_REPOSITORY_URL" --source-key "qa/tenable/${qa_dir##*/}" --format json)
"${publish[@]}" --dry-run > "$qa_dir/preview.json"
```

Check that the preview names the expected account, endpoint, destination and source key. Confirm one high-severity finding with native ID `00017` and no exclusions. A workspace preview identifies a private upload of `security.findings.v1`. A personal repository preview includes a request for the selected connector and repository.

Run `"${publish[@]}" > "$qa_dir/receipt.json"` and approve the matching preview. The receipt should be `complete`, with one processed finding and no errors or unacknowledged findings. For a workspace, check the private job completed and open the finding in the signed-in user's private import history. For a personal repository, check `verified: 1` and open the imported finding to verify its source ID, title and initial `not_assessed` state. Follow the [retry instructions](schema-guide.md#retry-a-cloud-submission) after an interrupted write.
