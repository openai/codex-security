# Import Endor Labs findings

Prefer Endor's native Finding JSON. It keeps the scanned commit,
severity, package and advisory details, and primary SAST or AI SAST locations
that Endor reports. You can also import self-contained `endorctl` SARIF 2.1.0
with finding UUIDs. A later SARIF import for the same UUID, destination
and source key can replace the stored commit, package and
advisory details, and leave severity `unknown`. Use native JSON for updates
when you need those fields. Local and Cloud imports retain unscored findings.

Native JSON keeps vulnerability and malware advisory IDs and aliases. When
Endor supplies only the fully qualified dependency name, the import preserves
that name, including its ecosystem and version. A branch scan uses its REF
context ID. The source version's ref can also identify a tag or commit. If
optional package or advisory details exceed Cloud's field or finding size
limits, private imports use `security.findings.v1` to upload the reviewed
fields and original Endor record together. The service must support that
format for these findings. Retrying a saved import reuses its original upload.

## Quick start

In Endor, verify that the project and scan context match your checkout. A project UUID alone doesn't
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

The local workbench keeps findings omitted from later exports. Use a separate
source key if you want to retain both formats' evidence for a finding.
[Imported finding identity and evidence](schema-guide.md)

For SARIF, `source_finding_id` is the Endor finding UUID and `evidence.url`
is the vendor's `finding-url` when supplied. Use the URL to open the finding in
Endor. Use `locations` for direct repository paths and reported SAST or
Secrets lines. Look in the original evidence for diagnostic levels, CVSS and
indexed or base-relative artifact references. If the report includes repository
URLs, they must match a comparable local Git remote when available, or the
selected repository for a new Cloud submission.
