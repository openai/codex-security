# Import Veracode Static Analysis policy findings

Use `--provider veracode` for the **Findings API** backlog of one Veracode
application mapped to one source repository. This importer handles
`scan_type=STATIC` in the application context. A Veracode application may
aggregate multiple repositories or binary modules: do not bind that aggregate
to a single checkout. Pipeline Scan JSON, sandboxes, SCA, DAST, policy pass/fail
summaries and the findings converter's SARIF output are not this format.

## Export unmodified Findings API pages

Set `VERACODE_APPLICATION_GUID` to the application you intend to import. Use a
client with read access to that application and the Results API. This example
uses HTTPie with the Veracode HMAC plugin and `jq`. Set `api` to the hostname
for your region. Store the exported pages outside the checkout.

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

Collect every page from the configured API host and keep each page intact.
Apply any Findings API filters when downloading the pages and use the same
selection throughout. The importer checks page counts, application scope and
the selection reported in the HAL links. Its preview includes the returned
rows with their original evidence, including any annotations. If the backlog
changes during pagination, collect it again.

## Preview and import

```bash
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings "$out/policy-findings.json" \
  --to local --repository ./project --provider veracode \
  --source-repository-url https://github.com/example/project \
  --source-key veracode/region/application-guid/static \
  --dry-run --format json
```

Review the destination, count and exclusions. Remove `--dry-run` to import.
Use the same source key for later exports from the same application and
context; an application GUID is not evidence of a Git URL. For Cloud use an
authorized GitHub repository and a deployment that accepts provider `veracode`.

Local import compares the source with the checkout’s Git remotes when
comparable remotes are configured.

If an interrupted Cloud upload reports `result.savedSubmission`, keep its
checkpoint and use the same build, state directory, account and import settings.
Preview the original export with `--dry-run --format json`. Check `accountId`
and `destination`. When `resumed` is false, review the new upload before approving it.
For `prepareNormalizedExternalPublication`, pass your original normalized
`ExternalFindings` and check `preview.resumed` before calling `publish()`.
Passing different normalized findings prepares a new upload. Save each finding
with its original `source_finding_id` and `evidence.source_data` so the SDK can
verify its application and repository when replayed with the Veracode provider.

| Veracode evidence                              | What Codex Security tracks                                                                                                            |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| API origin, application/context and `issue_id` | A stable policy flaw occurrence. Build number, line, CWE and the separate Pipeline flaw ID are not its identity.                      |
| Native severity, CWE and flaw description      | SAST evidence, preserving the original numeric severity, description and status in the raw record.                                    |
| Static analysis path, line and module          | Reported evidence, not proof that a similarly named file exists in the checkout. No fabricated column or Git commit.                  |
| Finding status, mitigation and resolution      | Upstream workflow history, not a Codex assessment. Replaying an update does not mark a fix verified; omissions do not delete records. |

References: [Veracode Findings API](https://docs.veracode.com/r/c_findings_v2_intro),
[vendor-supported policy and Pipeline conversion examples](https://github.com/veracode/veracode-pipeline-scan-results-to-sarif).
