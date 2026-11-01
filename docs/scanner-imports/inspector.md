# Import Amazon Inspector findings

Import package and code vulnerabilities from one Amazon Inspector Code Security
repository. Findings from EC2, ECR, Lambda, and network resources are excluded.

## Quick start

In Inspector coverage, find the account, Region, and full resource ID for the
repository. Project names can match several integrations. With
`inspector2:ListFindings` permission, run this export from the destination
checkout root. Replace the example Region, account ID, and repository resource ID.

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

Verify the Inspector project ARN and its canonical Git URL in your SCM
integration setup. Set `VERIFIED_PROJECT_ARN` to that ARN and replace the Git
URL and source key below. The ARN in a report alone does not establish the
mapping. If the findings already include the matching native Git URL, omit
`--inspector-project-arn`.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings "$out/inspector.json" \
  --to local --repository . --provider inspector \
  --source-repository-url https://github.com/example/project \
  --inspector-project-arn "$VERIFIED_PROJECT_ARN" \
  --source-key inspector/account-alias/us-east-1/example/project \
  --dry-run --format json
```

## Import and verify

Check the destination, ready findings, and exclusions. Remove `--dry-run` to
import, then read the stored evidence.

```sh
codex-security findings imported . --format json
```

For Cloud, replace `--to local --repository .` with
`--to cloud --repository CLOUD_REPOSITORY_ID` on a deployment that accepts
`inspector`. Preview again before confirming. Cloud checks the authorized
GitHub destination. Supply the same verified ARN and Git URL when resuming a
submission prepared with that binding.

## Reference

A finding ARN identifies an occurrence within the source key. Reuse the key
across exports to update matching ARNs. Omitted findings and empty exports
leave earlier occurrences in place.

Package findings retain the advisory and reported dependency versions. Code
findings retain detector details and safe repository-relative locations when
available. Native status, severity, and remediation remain source evidence.
A closed or suppressed finding stays unassessed.

Start an export on the first page with AWS CLI automatic pagination enabled.
Omit `--starting-token`, `--no-paginate`, `--max-items`, and `--query`. The
importer rejects continuation tokens but cannot distinguish a final page
saved on its own from a complete export. See the
[AWS CLI export](https://docs.aws.amazon.com/cli/latest/reference/inspector2/list-findings.html)
and [Inspector repository fields](https://docs.aws.amazon.com/inspector/v2/APIReference/API_CodeRepositoryDetails.html).

Custom GitHub hosts need a native GitHub provider hint for Cloud publication.
Self-managed GitLab is supported locally. If the GitLab web URL includes a
prefix the SSH clone URL omits, use the verified HTTPS clone URL as a checkout
remote. Keep the verified URL’s path casing on custom hosts. For home-relative
SSH paths, verify the account when the URL omits the login. SDK callers can
pass verified ARN-to-URL pairs through `inspectorProjectMap` for raw and
normalized imports.
