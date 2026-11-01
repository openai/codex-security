# Import SonarQube Cloud findings

Import selected security issues from one SonarQube Cloud project and branch or
pull request. The live collector uses your authenticated Sonar CLI and saves the
selection in a capture you can replay locally or publish to Cloud.

## Quick start

From the matching checkout root, use a Codex Security CLI with `import sonar` and
a Sonar CLI signed in to the project's organization. Run `sonar auth login`
if needed, using an account with project browse access. Keep the same Sonar
server and organization selected while collecting.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security import sonar --sonar-project example_project --sonar-branch main \
  --sonar-issue ISSUE_A --sonar-issue ISSUE_B --dry-run --format json
```

Use the project and issue keys from Sonar's Issues view or the SonarQube
plugin for Codex. A selection by key includes the requested issues regardless
of status. To preview open and confirmed security issues for the ref, omit
the `--sonar-issue` flags. For a pull request use `--sonar-pull-request 42` in place
of `--sonar-branch main`. If both are omitted, Sonar uses the main branch.
[Sonar CLI authentication](https://docs.sonarsource.com/sonarqube-cli/quickstart-guide#step-2-authenticate)

## Import and verify

Review the repository, ref, selected issues and exclusions. The preview
returns a private `capture` file even for a file input. Pass that exact path
to confirm. Read back the unassessed records from the preview's `repository`.
A local import needs no Codex Security Cloud login.

```sh
codex-security import sonar "/path/from/local-preview.json" --yes
codex-security findings imported "/checkout/from/preview" --format json
```

To publish the same selection, sign in to a Cloud account enabled for
external imports on a deployment that accepts `sonar`. From the same checkout,
preview the saved file, review the Cloud account, repository, environments
and exclusions, then use the **new capture path from the Cloud preview** to
confirm. This command imports locally and publishes to Cloud. Check the local
counts and Cloud verification result. Replay needs no Sonar login.

```sh
codex-security import sonar "/path/from/local-preview.json" --to cloud --dry-run --format json
codex-security import sonar "/path/from/cloud-preview.json" --to cloud --yes
```

You can also start with `--to cloud` on the live preview. Preview again if
the checkout, state directory or destination changes. If an approved upload
is interrupted, retry with the same capture and destination.
[Cloud publication](../../sdk/typescript/docs/cli.md#publish-findings-to-cloud)

## Reference

### Project and repository selection

You may omit `--sonar-project` when Sonar maps the checkout's Git origin to
exactly one project in the active organization. For monorepos, pass the project
key explicitly. When a search exceeds the 10,000-result window, select issue
keys. In Codex, you can ask to import the issues you selected in the SonarQube
plugin. [SonarQube plugin](https://www.sonarsource.com/blog/now-available-sonarqube-plugin-for-codex/)
and [Codex Security import workflow](../../plugins/codex-security/skills/publish-findings/SKILL.md#sonarqube-cloud-issues)

If Sonar lacks a repository binding, the checkout uses an SSH host alias or
Cloud preview finds no usable remote, verify the project's Git URL in Sonar.
Pass it as `--source-repository-url` when previewing the capture. When the
checkout has comparable remotes, at least one must match. A changed fetch
URL needs a new preview.

Each Sonar issue key identifies one record within its source and repository.
Reimport updates its evidence. File ranges and available data-flow traces
stay in the evidence. In a monorepo, repository-relative locations also
require a verified Sonar project base directory.

### Use a native JSON export

For a saved `GET /api/issues/search` response, pass a single page object only
when it contains the entire result. Otherwise pass an array of every page, in
order, for the same project and ref. Supply the verified repository URL and
a stable source key for the Sonar instance, organization, project and ref.
Native pages can omit that context. Use the exact key from a previous import
to update the same records.

```sh
codex-security publish findings ../reports/sonar-pages.json --provider sonar \
  --to local --repository . --source-repository-url https://github.com/example/project \
  --source-key sonarcloud.io/example/example_project/branch/main --dry-run --format json
```

Review the preview, rerun without `--dry-run`, confirm and use
`codex-security findings imported . --format json` to verify the local import.
