# Import Veracode Static Analysis findings

Import Findings API policy flaws from one Veracode application that maps to
one source repository. Use the application context and `scan_type=STATIC`.

## Quick start

[Enable external imports](README.md#preview-a-report) and
[export the complete Findings API pages](#export-findings-api-pages) with read
access to the application and Results API. From the matching checkout root,
preview the file with its verified Git URL and a source key for this application.

```sh
codex-security publish findings /private/path/policy-findings.json \
  --to local --repository . --provider veracode \
  --source-repository-url https://github.com/example/project \
  --source-key veracode/region/application-guid/static \
  --dry-run --format json
```

## Import and verify

Verify the application represents the destination repository. An application
GUID or a backlog aggregated from several repositories cannot establish the
mapping. [Save or publish and verify](README.md#save-or-publish-and-verify)
using the same source key for repeat exports from this application and context.

## Reference

### Identity and evidence

The API origin, application and context, and native `issue_id` identify one
policy flaw. Build number, source line, CWE, and Pipeline flaw ID are separate
fields. The original record retains numeric severity, CWE, flaw description,
status, mitigation, and resolution. Location evidence includes the reported
static analysis path, line, and module. The importer does not verify that the
path exists in the checkout or infer a column or Git commit.

Imported findings start unassessed. Replaying an upstream resolution does not
verify a fix. Omitted findings remain stored. `veracode static scan <package>`
runs a new Pipeline Scan with different flaw IDs. Retrieve existing policy
flaws with the Findings API export below. Sandbox, SCA, DAST, policy summaries,
and converted SARIF also use other formats. [Veracode static scan](https://docs.veracode.com/r/veracode_static_scan)

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
    scan_type==STATIC page=="$page" size==100 > "$out/page.tmp" || exit "$?"
  pages=$(jq -er --arg app "$application" --argjson n "$page" '
    select(._links.application.href == $app and .page.number == $n) |
    .page.total_pages | numbers' "$out/page.tmp") || exit "$?"
  cat "$out/page.tmp" >> "$out/pages.stream" || exit "$?"
  page=$((page + 1))
  [ "$page" -lt "$pages" ] || break
done
jq -s '.' "$out/pages.stream" > "$out/report.tmp" &&
  mv "$out/report.tmp" "$out/policy-findings.json"
```

Keep each page intact. Apply any Findings API filters when downloading the
pages and use the same selection throughout. The importer checks page counts,
application scope, and the selection reported in the HAL links. If the backlog
changes during pagination, collect it again. See the
[Veracode Findings API](https://docs.veracode.com/r/c_findings_v2_intro) and
[policy and Pipeline conversion examples](https://github.com/veracode/veracode-pipeline-scan-results-to-sarif).
