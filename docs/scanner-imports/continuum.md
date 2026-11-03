# Import AWS Continuum code findings

Import a saved JSON response from AWS Continuum for Code Vulnerabilities.
Use a detailed finding for investigation or a list of summaries for an
overview of one repository.

## Export findings for one repository

Use an AWS CLI with the `continuum` commands, signed in to the account and
Region where the environment lives. Set `ENVIRONMENT_ID` to that environment.
Check its code sources against the repository you intend to import into. For
an S3 source, verify which repository supplied the scanned archive.
[AWS Continuum code sources](https://docs.aws.amazon.com/continuum/latest/userguide/cv-getting-started.html)

**One finding.** Check the finding against its scanned code source, then set
`FINDING_ID` to its Continuum finding ID. For a finding from another scanner,
you can also verify the repository in the originating scanner. The detail
response can include code locations, descriptions, mitigation and AWS
validation evidence.
[AWS CLI get-code-finding](https://docs.aws.amazon.com/cli/latest/reference/continuum/get-code-finding.html)

```sh
out=$(mktemp -d) &&
  aws continuum get-code-finding --environment-id "$ENVIRONMENT_ID" \
    --finding-id "$FINDING_ID" --output json > "$out/continuum.tmp" &&
  mv "$out/continuum.tmp" "$out/continuum.json"
```

**All summaries.** For bulk import, use an environment dedicated to one
repository and verify that the export belongs to that repository. Start on
the first page with automatic pagination enabled. Keep the JSON object with
its `items` array. In a mixed environment, export verified findings with
`get-code-finding`.
[AWS CLI list-code-findings](https://docs.aws.amazon.com/cli/latest/reference/continuum/list-code-findings.html)

```sh
out=$(mktemp -d) &&
  aws continuum list-code-findings --environment-id "$ENVIRONMENT_ID" \
    --output json > "$out/continuum.tmp" &&
  mv "$out/continuum.tmp" "$out/continuum.json"
```

## Preview and import

[Enable external imports](README.md#preview-a-report). From the matching
checkout, preview the export with the verified Git URL and a stable source key
for the environment and repository.

```sh
codex-security publish findings "$out/continuum.json" \
  --to local --repository . --provider continuum \
  --source-repository-url https://github.com/example/project \
  --source-key "continuum/$ENVIRONMENT_ID/example/project" \
  --dry-run --format json
```

Check the destination, finding ARNs, reported paths and exclusions. In
multi-repository environments, customer-supplied paths can start with a
repository name. The reader preserves that prefix. Follow
the shared steps to save locally or publish to a Cloud deployment that
accepts the `continuum` provider. [Save or publish and verify](README.md#save-or-publish-and-verify)

The finding ARN identifies the same occurrence in either export. With the
same source key, importing a detail response after its summary updates the
existing record. A subsequent summary replaces that richer evidence. Reuse
`get-code-finding` for updates when you need the details.
Both scanner-generated and customer-supplied code findings retain their AWS
fields in `evidence.source_data.finding`. Continuum status and validation
are vendor evidence. New findings start with a Codex assessment of
`not_assessed`.
