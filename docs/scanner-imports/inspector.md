# Import Amazon Inspector findings

Import package and code vulnerabilities from one Amazon Inspector Code Security
repository. Findings from EC2, ECR, Lambda, and network resources are excluded.

## Quick start

[Enable external imports](README.md#preview-a-report) and
[export the repository findings](#export-repository-findings). In your SCM
integration, verify the Inspector project ARN and set `VERIFIED_PROJECT_ARN`
to that value. From the matching checkout root, preview the file with the
verified Git URL and your source key. Omit `--inspector-project-arn` when the
findings already include the matching native Git URL.

```sh
codex-security publish findings /private/path/inspector.json \
  --to local --repository . --provider inspector \
  --source-repository-url https://github.com/example/project \
  --inspector-project-arn "$VERIFIED_PROJECT_ARN" \
  --source-key inspector/account-alias/us-east-1/example/project \
  --dry-run --format json
```

## Import and verify

Check the finding ARNs and repository in the preview, then
[save or publish and verify](README.md#save-or-publish-and-verify). For a Cloud
retry, supply the same verified ARN and Git URL used to prepare the submission.

## Reference

### Identity and repository mapping

A finding ARN identifies an occurrence within the source key. Reuse the key
across exports to update matching ARNs. Omitted findings and empty exports
leave earlier occurrences in place.

Package findings retain the advisory and reported dependency versions. Code
findings retain detector details and safe repository-relative locations when
available. Native status, severity, and remediation remain source evidence.
A closed or suppressed finding stays unassessed.

Custom GitHub hosts need a native GitHub provider hint for Cloud publication.
Self-managed GitLab is supported locally. If the GitLab web URL includes a
prefix the SSH clone URL omits, use the verified HTTPS clone URL as a checkout
remote. Keep the verified URL’s path casing on custom hosts. For home-relative
SSH paths, verify the account when the URL omits the login. SDK callers can
pass verified ARN-to-URL pairs through `inspectorProjectMap` for raw and
normalized imports.

### Export repository findings

In Inspector coverage, find the account, Region, and full resource ID for the
repository. Project names can match several integrations. With
`inspector2:ListFindings` permission, replace the example Region, account ID, and
repository resource ID in this export.

For ARNs selected with the [AWS Codex plugin](https://github.com/aws/agent-toolkit-for-aws#codex),
keep the Region, account, and repository filters below. Add a `findingArn` array
with one `{"comparison":"EQUALS","value":"FINDING_ARN"}` per ARN, up to
[10 per request](https://docs.aws.amazon.com/inspector/v2/APIReference/API_FilterCriteria.html#inspector2-Type-FilterCriteria-findingArn).
Combine the native `findings` arrays from all fully paginated batches into one
`{"findings":[...]}` report. From a saved scoped export, select those rows locally.
If the selected rows cannot establish the repository together, request a native
capture of those same ARNs with the missing evidence. Before import, verify the
preview contains each requested ARN once, no other ARNs, and no exclusions.

```bash
set -eu
umask 077
out=$(mktemp -d)
aws inspector2 list-findings --region us-east-1 --output json \
  --filter-criteria '{
    "awsAccountId":[{"comparison":"EQUALS","value":"ACCOUNT_ID"}],
    "resourceType":[{"comparison":"EQUALS","value":"CODE_REPOSITORY"}],
    "resourceId":[{"comparison":"EQUALS","value":"REPOSITORY_RESOURCE_ID"}]
  }' > "$out/inspector.json.tmp" &&
  mv "$out/inspector.json.tmp" "$out/inspector.json"
```

Start an export on the first page with AWS CLI automatic pagination enabled.
Omit `--starting-token`, `--no-paginate`, `--max-items`, and `--query`. The
importer rejects continuation tokens but cannot distinguish a final page
saved on its own from a complete export. See the
[AWS CLI export](https://docs.aws.amazon.com/cli/latest/reference/inspector2/list-findings.html)
and [Inspector repository fields](https://docs.aws.amazon.com/inspector/v2/APIReference/API_CodeRepositoryDetails.html).
