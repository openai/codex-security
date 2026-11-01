# Import Amazon Inspector repository findings

Import package and code vulnerabilities from one Amazon Inspector Code Security
repository. Each finding ARN identifies one occurrence within your source key.

## Export one repository

In Inspector coverage, find the account, Region and full resource ID for the
repository. A project name alone can match several integrations. With
`inspector2:ListFindings` permission, export the findings outside the checkout.

```bash
set -eu
umask 077
out=$(mktemp -d)
aws inspector2 list-findings --region us-east-1 --output json \
  --filter-criteria '{
    "awsAccountId":[{"comparison":"EQUALS","value":"ACCOUNT_ID"}],
    "resourceType":[{"comparison":"EQUALS","value":"CODE_REPOSITORY"}],
    "resourceId":[{"comparison":"EQUALS","value":"REPOSITORY_RESOURCE_ID"}]
  }' > "$out/inspector.json.tmp"
mv "$out/inspector.json.tmp" "$out/inspector.json"
```

Start at the first page with automatic pagination enabled. Omit
`--starting-token`, `--no-paginate`, `--max-items` and `--query`. The
importer rejects continuation tokens but cannot distinguish a final page
saved on its own from a complete export.

## Bind the Inspector project to a Git repository

Inspector often reports a project ARN and a name such as `example/project`.
That name can exist on multiple Git hosts. Verify the project ARN and its
canonical Git URL in your SCM integration setup. Set `VERIFIED_PROJECT_ARN`
to that ARN and pass the pair explicitly.
Copying an ARN from the report alone cannot verify who owns the repository.
When the findings already include a matching native Git URL, omit
`--inspector-project-arn`.

## Preview, import and read back

```bash
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings "$out/inspector.json" \
  --to local --repository ./project --provider inspector \
  --source-repository-url https://github.com/example/project \
  --inspector-project-arn "$VERIFIED_PROJECT_ARN" \
  --source-key inspector/account-alias/us-east-1/example/project \
  --dry-run --format json
```

Review the destination, ready findings and exclusions. Remove `--dry-run` to
import, then run `codex-security findings imported ./project --format json`.
Reuse the source key across exports. Reimport updates an existing ARN.
Omitted findings and empty exports leave earlier occurrences in place.

For Cloud, use `--to cloud --repository CLOUD_REPOSITORY_ID` on a deployment
that accepts the Inspector provider. Cloud checks the authorized GitHub
destination. Custom GitHub hosts need a native GitHub provider hint.
Self-managed GitLab is supported locally. If the GitLab web URL includes an
installation prefix that the SSH clone URL omits, use the verified HTTPS clone
URL as a checkout remote. Use the verified URL’s path casing on custom hosts.
For home-relative SSH paths, verify the account when a URL omits the login.

Supply the same verified ARN and URL when resuming a Cloud submission prepared
with that binding. SDK callers can pass verified ARN-to-URL pairs through the
`inspectorProjectMap` option on raw and normalized imports.

## Evidence

Package findings retain the advisory and reported dependency versions. Code
findings retain detector details and safe repository-relative locations when
available. Native status, severity and remediation remain source evidence.
A closed or suppressed finding stays unassessed. EC2, ECR, Lambda and network
findings are excluded.

[AWS CLI export](https://docs.aws.amazon.com/cli/latest/reference/inspector2/list-findings.html)
and [repository fields](https://docs.aws.amazon.com/inspector/v2/APIReference/API_CodeRepositoryDetails.html).
