# Import AWS Continuum code findings

Use `GetCodeFinding` JSON to import selected findings with their locations,
mitigation, and AWS validation evidence. Use `ListCodeFindings` JSON for
summaries from an environment dedicated to one repository.

## Quick start

Open the matching checkout. Set `ENVIRONMENT_ID` to the Continuum environment ID. Verify which
repository supplied the scanned code, including the archive for an S3 source.
For a finding from another scanner, you can also check its repository in that
scanner. [AWS Continuum code sources](https://docs.aws.amazon.com/continuum/latest/userguide/cv-getting-started.html)

**Saved report.** Set `report` to a native detail response, an array of detail responses, or a complete list response with its `items` array. Then [preview the report](#preview-and-import).

```sh
report=/private/path/continuum.json
```

### Export findings for one repository

To create a report, sign in to the environment's AWS account and Region with
an AWS CLI that supports `continuum`. Choose one export.

**One finding.** Set `FINDING_ID` to the Continuum ID of the finding you
verified. In an environment with several repositories, use this command to
export one verified finding at a time. [AWS CLI get-code-finding](https://docs.aws.amazon.com/cli/latest/reference/continuum/get-code-finding.html)

```sh
report=
out=$(mktemp -d) &&
  aws continuum get-code-finding --environment-id "$ENVIRONMENT_ID" \
    --finding-id "$FINDING_ID" --output json > "$out/continuum.tmp" &&
  mv "$out/continuum.tmp" "$out/continuum.json" &&
  report="$out/continuum.json"
```

**Selected findings.** Fetch one detail response per finding ID. Verify each
belongs to the same environment and Git repository. To publish them together,
combine the saved objects into a JSON array with `jq`.

```sh
report=
out=$(mktemp -d) &&
  jq -s '.' first-detail.json second-detail.json > "$out/selected.json" &&
  report="$out/selected.json"
```

**All summaries.** Verify that the environment contains findings from just
this repository. Start on the first page and let the AWS CLI fetch every
page. [AWS CLI list-code-findings](https://docs.aws.amazon.com/cli/latest/reference/continuum/list-code-findings.html)

```sh
report=
out=$(mktemp -d) &&
  aws continuum list-code-findings --environment-id "$ENVIRONMENT_ID" \
    --output json > "$out/continuum.tmp" &&
  mv "$out/continuum.tmp" "$out/continuum.json" &&
  report="$out/continuum.json"
```

### Preview and import

Preview the report with the verified Git URL and a source key for this
environment and repository.

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider continuum --source-repository-url https://github.com/example/project \
  --source-key "continuum/$ENVIRONMENT_ID/example/project" \
  --dry-run --format json
```

Check the repository, finding ARNs, paths, and exclusions. In a
multi-repository environment, a customer-supplied path can begin with a
repository name. The reader keeps that prefix. For local repeat imports, a summary replaces richer evidence already saved for the same ARN and source key. Use the detail export to keep locations, mitigation and validation evidence. To save locally, remove `--dry-run` and confirm.

<a id="publish-to-your-cloud-inbox"></a>

### Publish to Cloud

If you need locations, mitigation, or validation evidence, publish the detailed
`get-code-finding` export first. For private inbox imports, a later upload
with changed evidence for the same ARN can return `source_order_unknown`.
Preview the file and source key using your connected repository URL.

```sh
repo=https://github.com/example/project
codex-security publish findings "$report" --to cloud --repository "$repo" \
  --provider continuum --source-repository-url "$repo" \
  --source-key "continuum/$ENVIRONMENT_ID/example/project" \
  --dry-run --format json
```

Check the account, repository and finding ARNs. The preview identifies the inbox
(`privateImport`) or repository environments (`requests`) that will receive them.
Remove `--dry-run` and confirm. Match the resulting source IDs to the Continuum ARNs. [Verify the import](README.md#verify-the-import)

## Detail, summaries, and repeat imports

Both formats use the finding ARN. In the local workbench, importing a detail
response under the same source key updates the existing summary. In a private Cloud inbox,
retrying identical evidence under the same source key preserves the finding.

The importer uses `statusUpdatedAt` for the source update time when available.
Dependency findings expose affected package names and concrete versions.
Cloud can show up to 100 structured packages per finding. The full list,
including version ranges, remains in `evidence.source_data.finding` alongside
the AWS status and validation results. [AWS detail fields](https://docs.aws.amazon.com/continuum/latest/APIReference/API_GetCodeFinding.html)
