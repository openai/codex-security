# Import Endor Labs findings

Prefer Endor's native Finding JSON. It keeps the scanned commit,
severity, package and advisory details, and primary SAST or AI SAST locations
that Endor reports. You can also import self-contained `endorctl` SARIF 2.1.0
with finding UUIDs.

## Quick start

[Enable external imports](README.md#preview-a-report). In Endor, verify that
the project and scan context match your checkout. A project UUID alone doesn't
establish that link. From the checkout root, set the namespace and project
UUID for this default-branch example.

```sh
namespace=YOUR_NAMESPACE
project=PROJECT_UUID
source_key="$namespace/$project/main"
```

For repeat imports, reuse the previous preview's exact source key. Choose a
saved report or export one in the same shell.

**Saved report.** Set `report` to a private file outside the checkout. It can
contain one Finding, an array of Findings, or a complete JSON response with
`list.objects`. For selected UUIDs, save just those complete Findings in an array.

```sh
report=/private/path/endor-findings.json
```

**Export from Endor.** Sign in to your namespace with `endorctl`. Use a
private temporary directory outside the checkout. For another scan context,
change both the filter and the source key. The Endor Labs Agent Kit can find
UUIDs for a selection.
[Agent Kit](https://github.com/endorlabs/ai-plugins/tree/main/plugins/codex/endor-labs-agent-kit) · [Filter syntax](https://docs.endorlabs.com/developers-api/rest-api/using-the-rest-api/filters#values)

```sh
filter="context.type==CONTEXT_TYPE_MAIN and spec.project_uuid==\"$project\""
# For selected UUIDs, uncomment and replace the example IDs.
# filter="$filter"' and uuid in ["UUID_A","UUID_B"]'
report=
out=$(mktemp -d) &&
  endorctl api list --resource Finding --namespace "$namespace" \
    --filter "$filter" --list-all --output-type json > "$out/endor-findings.tmp" &&
  mv "$out/endor-findings.tmp" "$out/endor-findings.json" &&
  report="$out/endor-findings.json"
```

Keep `--list-all` to fetch every page. Omit `--field-mask` to keep every field.
[Endor CLI API](https://docs.endorlabs.com/developers-api/cli/commands/api)

The importer accepts a single Finding, an array, or a `ListFindingsResponse`
containing `list.objects`. An empty response can omit the `objects` field.
An unfinished paginated response is rejected. Native
JSON retains the complete Finding and maps severity, dependency and advisory
details, scanned commit SHA, and primary SAST or AI SAST locations when
available. See the [Endor CLI API](https://docs.endorlabs.com/developers-api/cli/commands/api)
and [Finding model](https://github.com/endorlabs/endorlabs-sdk/blob/8a41756890c2dee3bb089fee881cae4f2adbde03/src/endorlabs/generated/models/finding_service.py).

**Preview the report.**

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider endor --source-key "$source_key" --dry-run --format json
```

Check the repository, source key, findings and exclusions. For selected UUIDs,
verify that `findings[].source_finding_id` lists each requested UUID once and
no others, and that `excluded` is empty. If the preview matches,
[save locally or publish to Cloud and verify the result](README.md#save-or-publish-and-verify).
New findings start as `not_assessed`. Upgrade recommendations, reachability
and dismissals come from Endor.

## SARIF and repeat imports

Both formats identify findings by UUID. Importing SARIF after native JSON
with the same destination and source key replaces the earlier evidence. You
can lose the scanned commit, package and advisory details, and severity can
become `unknown`. The local workbench keeps findings omitted from later exports.
[Imported finding identity and evidence](schema-guide.md)

SARIF keeps finding links, direct repository paths and reported SAST or
Secrets lines. Look in the original evidence for diagnostic levels, CVSS and
indexed or base-relative artifact references. If the report includes repository
URLs, they must match a comparable local Git remote when available, or the
selected repository for a new Cloud submission.
