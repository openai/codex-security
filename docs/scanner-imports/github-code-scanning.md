# Import GitHub code scanning findings

Import code scanning alerts from one repository and Git ref. The collector
saves each alert with the instance that GitHub returned for the selected ref.

## Quick start

Sign in with `gh auth login`. A fine-grained token needs **Code scanning alerts: read**.
A classic token needs `security_events`, or `public_repo` for a public repository.
[GitHub API permissions](https://docs.github.com/en/rest/code-scanning/code-scanning#list-code-scanning-alerts-for-a-repository)
For GitHub Enterprise, set `GH_HOST` to the host you signed in to.

From the destination checkout root, set `repo` to its GitHub repository. Set
`source_key` to your existing code scanning key exactly, including case. For a
first import, choose a key for the host, repository and finding family. Replace
`/path/to/private/reports` with an existing private directory outside the checkout,
then preview the default branch’s open alerts.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
repo=OWNER/REPO
source_key=github.com/example/project/code-scanning
out=$(mktemp -d "/path/to/private/reports/github.XXXXXX") &&
  codex-security import github "$repo" --format json > "$out/alerts.json" &&
  codex-security publish findings "$out/alerts.json" \
    --to local --repository . --provider github \
    --source-key "$source_key" --dry-run --format json
```

## Import and verify

Check the ref and alert numbers in the preview. The alert repository must match
a comparable local Git remote when available or the selected Cloud repository.
Reuse the source key when you [save or publish and verify](README.md#save-or-publish-and-verify).

## Reference

- To select another ref, add `--github-ref refs/heads/BRANCH` to the collector.
  Use `--github-state all` to include fixed and dismissed alerts, or repeat
  `--github-alert NUMBER` to select exact alerts regardless of state.
- Save the collector’s complete JSON array. Omit field or token filters and
  `--full-output` when saving it for the reader.
- The GitHub host, repository, alert number and ref identify a finding, so the
  same alert on two refs retains separate evidence. Missing security severity
  stays `unknown`.
- See the [GitHub SDK examples](../../sdk/typescript/docs/cli.md#import-github-findings-locally-or-to-cloud)
  for programmatic collection and destination-specific normalization.
