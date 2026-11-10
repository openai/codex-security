# Import Veracode Static Analysis findings

Import existing policy flaws from Findings API pages for one Veracode
application. Use the application context and `scan_type=STATIC`.

## Quick start

Verify that the application maps to a single Git repository and open its checkout.

**Saved report.** Set `report` to the complete Findings API page or array of
pages for your selection. Preserve each page's HAL links and pagination fields.

```sh
report=/private/path/policy-findings.json
```

**Export from Veracode.** You need Bash, `jq`, HTTPie with the Veracode HMAC
plugin, and Veracode credentials with read access to the application and
Results API. Configure the [export script](#export-findings-api-pages), then
capture the path it prints when the export succeeds.

```sh
report=$(bash "/private/path/export-veracode.sh")
```

**Preview the report.** Use the verified Git URL and a source key for your
region, application and scan context. The URL must match a comparable local
remote when available, or the selected Cloud repository.

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider veracode --source-repository-url https://github.com/example/project \
  --source-key veracode/region/application-guid/static \
  --dry-run --format json
```

In each finding's `evidence.source_data`, check `applicationUrl` and the
native `row.issue_id`. Review any excluded flaws. Reuse this key for exports
from the same application and context.
[Save locally or publish to Cloud and verify the result](README.md#save-or-publish-and-verify).

## Identity and evidence

The API origin, application, context and native `issue_id` identify a policy
flaw. Build number, source line, CWE and Pipeline flaw ID are separate fields.
The finding title uses the category name, then the CWE name or ID when a name
is missing. The description and status come from the flaw. The original
row retains the Veracode severity (0–5), CWE, mitigation and resolution.
The reader accepts numeric CWEs and category names as well as expanded CWE
and category objects in HAL exports. [Findings API schema](https://api.swaggerhub.com/apis/Veracode/veracode-findings_api_specification/2.1)

If you export with a numeric category filter, the rows must include category
IDs so the reader can verify the selection. To locate a flaw, use its
`issue_id` in the application identified by `applicationUrl`. The module,
file path and line in `row.finding_details` refer to the analyzed artifact.
Check that path against the checkout before citing a source location.

A Veracode resolution records upstream status. Assess the fix separately.
The workbench keeps flaws omitted from later exports.
`veracode static scan <package>` runs a new Pipeline Scan with different
flaw IDs. Sandbox, SCA, DAST, policy summaries, converted SARIF and
multi-repository backlogs fall outside this import.
[Veracode static scan](https://docs.veracode.com/r/veracode_static_scan)

For SDK replay, use the `veracode` provider and keep each finding's original
`source_finding_id` and `evidence.source_data`. The SDK uses them to check the
application and repository.

## Export Findings API pages

Save this Bash script outside the checkout as `export-veracode.sh`. Export
`VERACODE_APPLICATION_GUID` in your shell and set `api` in the script to the
API origin for the application's region. The script uses HTTPie with the
Veracode HMAC plugin and `jq`. Apply any Findings API filters in the request
and keep the same selection on every page.

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
  mv "$out/report.tmp" "$out/policy-findings.json" &&
  printf '%s\n' "$out/policy-findings.json"
```

Keep every page intact. The importer checks page counts, the application and
the selection in the HAL links. If the backlog changes during pagination,
collect the pages again.
[Veracode Findings API](https://docs.veracode.com/r/c_findings_v2_intro) · [Policy and Pipeline conversion examples](https://github.com/veracode/veracode-pipeline-scan-results-to-sarif)
