# Import GitHub code scanning findings

Use the JSON array from `codex-security import github`. It includes each
alert and the instance GitHub returned for the selected ref.

## Quick start

[Enable external imports](README.md#preview-a-report). From the matching
checkout, set the repository and source key. For GitHub Enterprise, export
`GH_HOST` with your hostname first. For a repeat import, use the exact source
key from your previous preview, including case.

```sh
repo=OWNER/REPO
source_key="${GH_HOST:-github.com}/$repo/code-scanning"
```

**Saved report.** Set `report=/private/path/alerts.json` if you already have
the collector's complete JSON array.

**Export from GitHub.** Sign in to the selected host with `gh auth login`.
A fine-grained token needs **Code scanning alerts: read**. A classic token
needs `security_events`, or `public_repo` for a public repository.
[GitHub API permissions](https://docs.github.com/en/rest/code-scanning/code-scanning#list-code-scanning-alerts-for-a-repository)

This command selects open alerts on the default branch. For another branch,
add `--github-ref refs/heads/BRANCH`. Use `--github-state all` to include
fixed and dismissed alerts, or repeat `--github-alert NUMBER` to select
specific alerts across states. Omit output filters, token limits and
`--full-output` so the reader gets the complete array. Use a private
temporary directory outside the checkout.

```sh
report=
out=$(mktemp -d) &&
  codex-security import github "$repo" --format json > "$out/alerts.json" &&
  report="$out/alerts.json"
```

**Preview the report.**

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider github --source-key "$source_key" --dry-run --format json
```

Check the repository, ref and alert numbers against your selection. The alert
repository must match a comparable local Git remote when available, or the
selected Cloud repository. If the preview matches,
[save locally or publish to Cloud and verify the result](README.md#save-or-publish-and-verify).

## Identity and evidence

The host, repository, alert number and ref identify a finding. The same alert
on two refs keeps separate evidence. Missing security severity stays `unknown`.

To collect with the SDK instead of `gh`, pass `githubHost` and a `githubToken`
for that host. [GitHub SDK examples](../../sdk/typescript/docs/cli.md#import-github-findings-locally-or-to-cloud)
