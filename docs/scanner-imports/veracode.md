# Import Veracode Static Analysis findings

Import the Findings API policy backlog for one Veracode application that maps
to one source repository. Choose the application context and `scan_type=STATIC`.
An application that aggregates multiple repositories or binary modules cannot
establish a mapping to one checkout.

## Quick start

With read access to the application and Results API,
[export the complete Findings API pages](#export-findings-api-pages) to a private
file outside the checkout. From the verified checkout root, replace the file path,
Git URL, and source key with values for your application.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings /private/path/policy-findings.json \
  --to local --repository . --provider veracode \
  --source-repository-url https://github.com/example/project \
  --source-key veracode/region/application-guid/static \
  --dry-run --format json
```

## Import and verify

Check the destination, count, and exclusions. The preview includes original
evidence and any annotations in the selected rows. Remove `--dry-run` to
import, then read the stored findings.

```sh
codex-security findings imported . --format json
```

Reuse the source key for exports from the same application and context. Local
import compares the source URL with the checkout’s Git remotes when comparable
remotes are configured. The application GUID alone cannot identify a Git URL.

For Cloud, replace `--to local --repository .` with
`--to cloud --repository CLOUD_REPOSITORY_ID` for the authorized GitHub
repository on a deployment that accepts `veracode`. Preview again before
confirming. For interrupted uploads, follow the
[Cloud retry procedure](schema-guide.md#retry-a-cloud-submission).

## Reference

### Identity and evidence

The API origin, application and context, and native `issue_id` identify one
policy flaw. Build number, source line, CWE, and Pipeline flaw ID are separate
fields. The original record retains numeric severity, CWE, flaw description,
status, mitigation, and resolution. Location evidence includes the reported
static analysis path, line, and module. The importer does not verify that the
path exists in the checkout or infer a column or Git commit.

Imported findings start unassessed. Replaying an upstream resolution does not
verify a fix. Omitted findings remain stored. Pipeline Scan JSON, sandbox
findings, SCA, DAST, policy pass/fail summaries, and the findings converter’s
SARIF output use other formats.

For SDK replay with the Veracode provider, keep each finding’s original
`source_finding_id` and `evidence.source_data` so the SDK can verify its
application and repository.

### Export Findings API pages

Set `VERACODE_APPLICATION_GUID` to the application GUID and `api` to the API
origin for its region. This example uses HTTPie with the Veracode HMAC plugin
and `jq`. It writes `policy-findings.json` in the temporary directory `$out`.

```bash
set -eu
umask 077
out=$(mktemp -d)
: "${VERACODE_APPLICATION_GUID:?Set the intended application GUID}"
api=https://api.veracode.com
guid=$(jq -ner --arg guid "$VERACODE_APPLICATION_GUID" '$guid | ascii_downcase |
  select(test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))')
application="$api/appsec/v1/applications/$guid"
page=0
while :; do
  http --ignore-stdin --check-status --body --timeout 20 --auth-type veracode_hmac GET \
    "$api/appsec/v2/applications/$guid/findings" \
    scan_type==STATIC page=="$page" size==100 > "$out/page.tmp"
  pages=$(jq -er --arg app "$application" --argjson n "$page" '
    select(._links.application.href == $app and .page.number == $n) |
    .page.total_pages | numbers' "$out/page.tmp")
  cat "$out/page.tmp" >> "$out/pages.stream"
  page=$((page + 1))
  [ "$page" -lt "$pages" ] || break
done
jq -s '.' "$out/pages.stream" > "$out/policy-findings.json"
```

Keep each page intact. Apply any Findings API filters when downloading the
pages and use the same selection throughout. The importer checks page counts,
application scope, and the selection reported in the HAL links. If the backlog
changes during pagination, collect it again. See the
[Veracode Findings API](https://docs.veracode.com/r/c_findings_v2_intro) and
[policy and Pipeline conversion examples](https://github.com/veracode/veracode-pipeline-scan-results-to-sarif).
