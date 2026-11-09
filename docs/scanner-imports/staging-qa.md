# Check a scanner import on staging

Use a synthetic report and a disposable, connected QA repository. Ask the Cloud deployment owner for the **nonproduction** API root, account ID, repository clone URL and expected route (`repository` or `private`). Confirm that the account can write to the selected destination. For a private import, record both the API and worker revisions. A UI preview can run against a different worker.

These Bash commands test one Tenable Code Repository finding with no Tenable login. They exercise the writer in the checked-out PR. For another file reader, use its [documented report format and options](README.md) and change the fixture settings below. Record each reader and route separately; a passing Tenable run does not verify another writer.

## Make a synthetic report and preview it

Run these commands in one Bash session from the PR checkout, with its SDK dependencies and a staging-only login. Keep the staging login’s configured credential and state directories for the entire check. Set `QA_API_ROOT`, `QA_ACCOUNT_ID`, `QA_REPOSITORY_URL`, and `QA_ROUTE` to the values from the deployment owner. Use the canonical repository URL as listed by Cloud. The check below refuses the public production host; for a custom deployment, verify the endpoint with its owner. Do not substitute a production destination when staging is unavailable.

```bash
set -euo pipefail
git rev-parse HEAD
pnpm --dir sdk/typescript run build
node sdk/typescript/bin/codex-security.mjs --version

qa_api=$(node -e '
  const url = new URL(process.argv[1]);
  const host = url.hostname.replace(/\.$/, "");
  if (url.protocol !== "https:" || host === "chatgpt.com" || host.endsWith(".chatgpt.com") ||
      url.username || url.password || url.search || url.hash)
    throw Error("Expected the approved nonproduction HTTPS API root.");
  console.log(url.href.replace(/\/+$/, ""));
' "${QA_API_ROOT:?set the approved staging API root}")
qa_dir=$(mktemp -d)
asset=10000000-0000-4000-8000-000000000001
printf 'asset_id,asset_class,asset_name\n%s,CODE_REPOSITORY,staging-smoke\n' "$asset" > "$qa_dir/assets.csv"
printf 'asset_id,finding_id,finding_name,severity,state\n%s,00017,Synthetic QA finding,High,ACTIVE\n' "$asset" > "$qa_dir/findings.csv"
python3 examples/tenable-one/capture.py --assets "$qa_dir/assets.csv" \
  --findings "$qa_dir/findings.csv" --asset-id "$asset" \
  --repository-url "${QA_REPOSITORY_URL:?set the QA repository URL}" --output "$qa_dir/selection.json"

# Fixture settings: change these together for a different scanner.
qa_file="$qa_dir/selection.json"
qa_reader=tenable
qa_provider=tenable     # Stored provider; the opengrep reader uses semgrep.
qa_id=00017
qa_severity=high
qa_private_format=security.findings.v1
qa_key="qa/$qa_reader/$asset/${qa_dir##*/}"
qa_reader_options=(--source-repository-url "$QA_REPOSITORY_URL")

qa_command=(env "CODEX_SECURITY_CLOUD_BASE_URL=${qa_api:?invalid staging API root}"
  node sdk/typescript/bin/codex-security.mjs publish findings "$qa_file"
  --to cloud --provider "$qa_reader" --repository "$QA_REPOSITORY_URL"
  "${qa_reader_options[@]}" --source-key "$qa_key" --format json)
"${qa_command[@]}" --dry-run > "$qa_dir/preview.json"
```

## Confirm the destination and verify the receipt

Inspect the preview privately. The following command requires `jq` and only prompts to submit if the preview matches the expected account, endpoint, route, repository and synthetic finding. Keep stdin and stderr attached to the terminal. Confirm only if the CLI shows the same destination and selection again.

```bash
jq -se --arg api "${qa_api:?}" --arg route "${QA_ROUTE:?set private or repository}" \
  --arg account "${QA_ACCOUNT_ID:?set the staging account ID}" --arg repo "$QA_REPOSITORY_URL" --arg key "$qa_key" \
  --arg provider "$qa_provider" --arg id "$qa_id" --arg severity "$qa_severity" --arg fmt "$qa_private_format" '
  length == 1 and (.[0] |
    .dryRun == true and .resumed == false and .accountId == $account and .destination.url == $repo and
    .source == {provider:$provider, source_key:$key} and .read == 1 and .excluded == [] and
    [.findings[].source_finding_id] == [$id] and .findings[0].evidence.severity == $severity and
    (if $route == "private" then
       .cloudApiUrl == ($api + "/finding-imports") and .privateImport.format == $fmt
     elif $route == "repository" then
       .cloudApiUrl == ($api + "/external") and (.requests | length == 1) and
       .requests[0].source == .source and .requests[0].repository.id == .destination.id and
       .requests[0].repository.repo_connector_id == .destination.repo_connector_id and
       [.requests[].items[].source_finding_id] == [$id]
     else false end))' "$qa_dir/preview.json" &&
  "${qa_command[@]}" > "$qa_dir/receipt.json"
```

Check the saved result. A private import has job counts; a repository import also reads the stored evidence back and counts it as verified. Either check must fail for a declined, empty, partial or interrupted run.

```bash
jq -se --slurpfile preview "$qa_dir/preview.json" '
  $preview[0] as $p | length == 1 and (.[0] |
    .cloudApiUrl == $p.cloudApiUrl and .status == "complete" and .read == 1 and .ready == 1 and
    .excluded == [] and .failures == [] and .unacknowledged == 0 and .counts.error == 0 and
    (.counts.created + .counts.updated + .counts.unchanged == 1) and
    (if $p.privateImport then .privateJob |
       .status == "completed" and .error == null and .source == $p.source and
       .default_targets == [{type:"repository", repo_id:$p.destination.id, repo_connector_id:$p.destination.repo_connector_id}] and
       .input.format == $p.privateImport.format and .counts.total == 1 and .counts.discovered == 1 and
       .counts.error == 0 and .counts.unprocessed == 0 and (.counts.created + .counts.updated + .counts.unchanged == 1)
     else .verified == 1 and (.receipts | length == 1) and (.receipts[0] |
       .source == $p.source and .repository == $p.requests[0].repository and .item_count == 1 and
       [.results[].client_id] == [$p.requests[0].items[0].client_id] and
       (.results[0].outcome | IN("created","updated","unchanged")))
     end))' "$qa_dir/receipt.json"
```

For a private job, open the staging account's private import history and confirm the source key and expected native finding ID appear. This proves intake, not publication to shared findings. For the repository route, inspect the QA repository's source report and confirm the synthetic title and initial `not_assessed` state. Keep account identifiers, raw previews and receipts in the private QA record. Record the tested revisions, route, counts and readback outcome; if access or provider support is missing, record the blocker.

For an interrupted write, keep the file, source key and state directory unchanged and follow [retrying a Cloud submission](schema-guide.md#retry-a-cloud-submission). Have the owner retire the test data under the workspace's retention policy. Removing the local directory does not delete a Cloud finding.
