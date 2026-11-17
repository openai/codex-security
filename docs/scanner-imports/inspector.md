# Import Amazon Inspector findings

Import Inspector2 `ListFindings` JSON for one Code Security repository.
Package and code vulnerabilities are supported. EC2, ECR, Lambda, and network
findings are excluded.

## Quick start

Open the matching checkout. Verify the repository's Git URL in your SCM integration. If
the report identifies the repository only by an Inspector project ARN, verify
that full ARN against the same URL in the SCM integration before importing.

**Saved report.** Use a complete repository export or select full native rows
by ARN within its `findings` array. Set `report` and skip to the preview.

```sh
report=/private/path/inspector.json
```

### Export repository findings

Check the scan triggers if you see pull request findings but the export is
empty. Inspector shows results from pull-request-only or merge-request-only
configurations in the source control platform. [Inspector scan configurations](https://docs.aws.amazon.com/inspector/latest/user/code-security-assessments-create-configuration.html)

With `inspector2:ListFindings` permission, replace the account, Region, and
full repository resource ID below with values from Inspector coverage. Project
names can match several integrations.

```sh
report=
umask 077
out=$(mktemp -d) &&
  aws inspector2 list-findings --region us-east-1 --output json \
    --filter-criteria '{
      "awsAccountId":[{"comparison":"EQUALS","value":"ACCOUNT_ID"}],
      "resourceType":[{"comparison":"EQUALS","value":"CODE_REPOSITORY"}],
      "resourceId":[{"comparison":"EQUALS","value":"REPOSITORY_RESOURCE_ID"}]
    }' > "$out/inspector.json.tmp" &&
  mv "$out/inspector.json.tmp" "$out/inspector.json" &&
  report="$out/inspector.json"
```

Start on the first page and let the AWS CLI fetch all pages. Omit
`--starting-token`, `--no-paginate`, `--max-items`, and `--query`. The
importer rejects continuation tokens. A final page saved on its own can look
like a complete export. [AWS CLI export](https://docs.aws.amazon.com/cli/latest/reference/inspector2/list-findings.html) · [Inspector repository fields](https://docs.aws.amazon.com/inspector/v2/APIReference/API_CodeRepositoryDetails.html)

For selected ARNs, keep the Region, account, and repository filters. Add a
`findingArn` filter with one
`{"comparison":"EQUALS","value":"FINDING_ARN"}` per ARN, up to 10 per request.
Combine every batch's fully paginated `findings` array in one
`{"findings":[...]}` report. [AWS Codex plugin](https://github.com/aws/agent-toolkit-for-aws#codex) · [Inspector filter limits](https://docs.aws.amazon.com/inspector/v2/APIReference/API_FilterCriteria.html#inspector2-Type-FilterCriteria-findingArn)

### Import and verify

Preview the report with the verified Git URL and a source key for the repository.
This example assumes the native findings identify the repository by URL. For
ARN-only findings, add `--inspector-project-arn FULL_PROJECT_ARN` using the ARN
you independently matched to that URL.

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider inspector --source-repository-url https://github.com/example/project \
  --source-key inspector/account-alias/us-east-1/example/project \
  --dry-run --format json
```

Check the repository and finding ARNs. For a selection, verify that each
requested ARN appears once, with no other ARNs or exclusions. If the selected
rows lack repository evidence, export those ARNs again with the missing fields.
To save the selected findings in your local workbench, remove `--dry-run` and confirm.

<a id="publish-to-your-cloud-inbox"></a>

### Publish to Cloud

Preview the same file and source key using the connected repository URL.
If the local preview required a project ARN, add
`--inspector-project-arn` with the same verified ARN to the command below.

```sh
repo=https://github.com/example/project
codex-security publish findings "$report" --to cloud --repository "$repo" \
  --provider inspector --source-repository-url "$repo" \
  --source-key inspector/account-alias/us-east-1/example/project \
  --dry-run --format json
```

Check the account, repository and finding ARNs. The preview identifies the inbox
(`privateImport`) or repository environments (`requests`) that will receive them.
Remove `--dry-run` and confirm. Match the resulting source IDs to the Inspector ARNs.
Retry with the same report, source key, Git URL, and any project ARN.
A private import with changed evidence for the same ARN can return
`source_order_unknown`. [Verify the import](README.md#verify-the-import)

## Identity and repository mapping

In the local workbench, importing changed evidence for the same source key
and ARN updates the existing finding. Findings omitted from later exports
stay in the workbench. Inspector status, severity, and remediation are source
evidence. New closed or suppressed findings start as `not_assessed`.

Code findings expose detector information, CWEs, and the reported source line
range. When those fields exceed Cloud limits, you can read them in
`evidence.source_data.finding`. Package findings use the primary vulnerability ID as their advisory
and keep dependency versions. Their evidence URL opens the advisory supplied by
Inspector when available. The finding ARN identifies the occurrence in AWS.
Related vulnerability IDs remain available in
`evidence.source_data.finding.packageVulnerabilityDetails.relatedVulnerabilities`.
[AWS code findings](https://docs.aws.amazon.com/inspector/v2/APIReference/API_CodeVulnerabilityDetails.html) · [AWS package findings](https://docs.aws.amazon.com/inspector/v2/APIReference/API_PackageVulnerabilityDetails.html)

Custom GitHub hosts need a native GitHub provider hint for Cloud. For local
imports from self-managed GitLab, use the verified HTTPS clone URL if SSH
omits a web path prefix. Preserve path casing on custom hosts. For
home-relative SSH paths that omit the login, verify the account. SDK callers
can pass verified ARN-to-URL pairs through `inspectorProjectMap` for raw and
normalized imports.
