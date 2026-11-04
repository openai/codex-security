# Import AWS Continuum code findings

Use `GetCodeFinding` JSON to investigate one finding with its locations,
description, mitigation, and AWS validation evidence when available. Use
`ListCodeFindings` JSON for summaries from an environment dedicated to one
repository.

## Quick start

[Enable external imports](README.md#preview-a-report) and open the matching
checkout. Set `ENVIRONMENT_ID` to the Continuum environment ID. Verify which
repository supplied the scanned code, including the archive for an S3 source.
For a finding from another scanner, you can also check its repository in that
scanner. [AWS Continuum code sources](https://docs.aws.amazon.com/continuum/latest/userguide/cv-getting-started.html)

**Saved report.** Set `report` to a native detail response or a complete list
response with its `items` array, then skip to the preview.

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
repository name. The reader keeps that prefix. If the preview matches,
[save locally or publish to Cloud and verify the result](README.md#save-or-publish-and-verify).
For Cloud, the deployment must accept the `continuum` provider.

## Detail, summaries, and repeat imports

Both formats use the finding ARN. With the same source key, importing a
detail response after its summary updates the existing finding. A later
summary replaces the richer evidence, so use `get-code-finding` for updates
when you need those details.

For both scanner-generated and customer-supplied findings,
`evidence.source_data.finding` keeps the original AWS fields, including any
Continuum status and validation results.
