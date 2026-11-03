# Import Endor Labs findings

Use native Finding JSON for ongoing imports. It preserves the scanned commit,
severity, package and advisory details, and primary SAST or AI SAST locations
when Endor reports them. A self-contained `endorctl` SARIF report also works
if it includes finding UUIDs.

## Quick start

From the checkout root, verify in Endor that the project and scan context
belong to this repository. The importer retains the project UUID without
looking up its Git repository. Set the namespace and project UUID below. The
example uses the project's default branch.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
namespace=YOUR_NAMESPACE
project=PROJECT_UUID
source_key="$namespace/$project/main"
```

For a repeat import, reuse the exact source key from the previous preview.
Choose one way to get the report, then preview it in the same shell.

**Use a saved report.** Set `report` to the private file outside the checkout.
Native JSON can contain one Finding, an array of Findings, or a complete list
response with `list.objects`. For selected UUIDs, save an array containing
only their complete native objects.

```sh
report=/private/path/endor-findings.json
```

**Export from Endor.** Authenticate `endorctl` for the namespace. Use a private
temporary directory outside the checkout. To export specific findings, supply
their UUIDs in the optional filter line. The Endor Labs Agent Kit can help find
them. For another scan context, change both the filter and the source key.
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

Keep `--list-all` and omit `--field-mask` to collect every page with complete
Finding objects.
[Endor CLI API](https://docs.endorlabs.com/developers-api/cli/commands/api)

**Preview and save.** Review the repository, source key, findings and exclusions.
For a selection, check that `findings[].source_finding_id` contains each
requested UUID exactly once and no others, and that `excluded` is empty.

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider endor --source-key "$source_key" --dry-run --format json
```

After review, [save locally or publish to Cloud and verify the result](README.md#save-or-publish-and-verify).
Endor's upgrade, reachability and dismissal data remain source evidence. New
imports start with a Codex assessment of `not_assessed`.

## SARIF and repeat imports

Both formats use the Endor finding UUID. For the same destination and source
key, importing SARIF after native JSON replaces the evidence for that UUID.
The stored finding can lose commit, package and advisory details, and its
severity can become `unknown`. Local records omitted from a later export stay
in the workbench. [Imported finding identity and evidence](schema-guide.md)

Self-contained `endorctl` SARIF 2.1.0 retains finding links, direct repository
paths and reported SAST or Secrets lines. Diagnostic levels, CVSS and indexed
or base-relative artifact references remain in the original evidence. Declared
repository URLs must match a comparable local Git remote when available, or
the selected repository for a new Cloud submission.
