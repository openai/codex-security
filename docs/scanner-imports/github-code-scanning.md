# Import GitHub code scanning findings

Use the JSON array from `codex-security import github`. It includes each
alert and the instance GitHub returned for the selected ref.

## Quick start

In the matching checkout, set the repository and source key. For GitHub Enterprise, export
`GH_HOST` with your hostname first. For a repeat import, use the exact source
key from your previous preview, including case.

```sh
repo=OWNER/REPO
source_key="${GH_HOST:-github.com}/$repo/code-scanning"
```

**Saved report.** Set `report=/private/path/alerts.json` if you already have
the collector's complete JSON array. Continue with [Preview the report](#preview-the-report).

### Export from GitHub

Sign in to the selected host with `gh auth login`.
A fine-grained token needs **Code scanning alerts: read**. A classic token
needs `security_events`, or `public_repo` for a public repository.
[GitHub API permissions](https://docs.github.com/en/rest/code-scanning/code-scanning#list-code-scanning-alerts-for-a-repository)

The command below selects open alerts on the default branch. For a different
branch, add `--github-ref refs/heads/BRANCH` to the collector command. To
include fixed and dismissed alerts, add `--github-state all`. For exact
alerts across states, repeat `--github-alert NUMBER` and omit `--github-state`.
Save the complete array without output filters, token limits or `--full-output`.
Use a private temporary directory outside the checkout.

```sh
report=
out=$(mktemp -d) &&
  codex-security import github "$repo" --format json > "$out/alerts.json" &&
  report="$out/alerts.json"
```

### Preview the report

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider github --source-key "$source_key" --dry-run --format json
```

### Save and verify

Check the repository, ref and alert numbers against your selection. The alert
repository must match a comparable local Git remote when available, or the
selected Cloud repository. If the preview matches,
[save locally or publish to Cloud and verify the result](README.md#save-or-publish-and-verify).

## Identity and evidence

The host, repository, alert number and ref identify a finding. The same alert
on two refs keeps separate evidence. Missing security severity stays `unknown`.

A GitHub dismissal applies to the entire alert, even when a selected ref's
instance is open or fixed. A GitHub connection in Codex can select records.
The CLI collector authenticates separately with `gh`.

## Use the SDK

To collect with the SDK, use credentials from `gh` or supply `githubHost` and
a `githubToken` issued for that host. This example previews a Cloud import.

```ts
import {
  importGitHubCodeScanningAlerts,
  normalizeGitHubCodeScanningAlerts,
  prepareNormalizedExternalPublication,
} from "@openai/codex-security";

const alerts = await importGitHubCodeScanningAlerts({
  repository: "example/project",
});
const prepared = await prepareNormalizedExternalPublication(
  normalizeGitHubCodeScanningAlerts(alerts, "cloud"),
  {
    provider: "github",
    repository: "https://github.com/example/project",
    sourceKey: "github.com/example/project/code-scanning",
  },
);
console.log(prepared.preview);
```

After reviewing the Cloud preview, call `await prepared.publish()` to confirm.
If you supply normalized evidence that keeps the collector record in
`source_data`, imports check its original repository against the destination.

For local storage, call `normalizeGitHubCodeScanningAlerts(alerts, "local")` on
the original alerts to retain evidence that exceeds Cloud limits. Pass the result
to `prepareNormalizedLocalImport()` with `repository: "/path/to/project"`, inspect
its preview, and call `import()`. Alternatively, pass the saved alert file directly
to `prepareLocalExternalImport()`. Read records with `listLocalExternalFindings({ repository })`.

### Validate the selected alerts

To get a disposition per alert, validate the collected records against the matching checkout.

```ts
import {
  CodexSecurity,
  importGitHubCodeScanningAlerts,
} from "@openai/codex-security";

const findings = await importGitHubCodeScanningAlerts({
  repository: "example/repository",
  alertNumbers: [12, 18], // Omit for all open alerts on the default branch.
  githubHost: "github.com",
  githubToken: process.env["GH_TOKEN"],
});

const security = new CodexSecurity();
try {
  for (const finding of findings) {
    const result = await security.validate({
      repositoryPath: "/path/to/repository",
      finding,
    });
    console.log(finding.url, result.disposition, result.outputDir);
  }
} finally {
  await security.close();
}
```

SDK options include `state` (default `"open"`), `ref`, and `signal`.
Without `gh`, pass a `githubToken` issued for the selected `githubHost`.
If you omit the token, the SDK asks the GitHub CLI for credentials, including
its supported token environment variables. `githubHost` defaults to `GH_HOST` or `github.com`.
The token needs code-scanning read access; access failures reject the import.
