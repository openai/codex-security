# Import SonarQube Cloud findings

Collect security issues for one project and branch or pull request. The
collector uses the authenticated Sonar CLI and saves the selection in a
capture you can import locally or publish to Cloud.

## Quick start

[Enable external imports](README.md#preview-a-report). From the matching
checkout, sign in to the project's Sonar organization with browse access
(`sonar auth login`). Preview a selection using project and issue keys from
Sonar's Issues view or the SonarQube plugin for Codex.
[Sonar CLI authentication](https://docs.sonarsource.com/sonarqube-cli/quickstart-guide#step-2-authenticate)

```sh
codex-security import sonar --sonar-project example_project --sonar-branch main \
  --sonar-issue ISSUE_A --sonar-issue ISSUE_B --dry-run --format json
```

A selection by key includes the requested security issues regardless of
status. Omit `--sonar-issue` to preview open and confirmed security issues
for the selected ref. For a pull request, replace `--sonar-branch main` with
`--sonar-pull-request 42`. Omit both to use the project's main branch.

## Import and verify

Review the repository, ref, issues and exclusions in the `import sonar`
preview. Confirm using the private `capture` path it returned.

```sh
codex-security import sonar "/path/from/local-preview.json" --yes
```

To import locally **and** publish to Cloud, start from the same checkout.
Replay needs no Sonar login. Use a separate file-backed ChatGPT login with
access to the connected Cloud repository and an authorized environment on a
deployment that accepts the `sonar` provider. Review the Cloud account,
repository and environment, then confirm with the **new Cloud capture**.

```sh
codex-security import sonar "/path/from/local-preview.json" --to cloud --dry-run --format json
codex-security import sonar "/path/from/cloud-preview.json" --to cloud --yes
```

Read back the local records in the preview's `repository` and check the Cloud
verification result if you published. Preview again if the checkout, state
directory or destination changes. To resume an interrupted upload, reuse the
approved capture and destination. [Readback and verification](README.md#save-or-publish-and-verify)

## Reference

### Project and repository selection

Omit `--sonar-project` only when the checkout's Git origin maps to exactly
one project in the active organization. For monorepos, supply the project
key. When a search exceeds 10,000 results, select issue keys.
[SonarQube plugin](https://www.sonarsource.com/blog/now-available-sonarqube-plugin-for-codex/)
and [Codex Security import workflow](../../plugins/codex-security/skills/publish-findings/SKILL.md#sonarqube-cloud-issues)

If Sonar lacks a repository binding, the checkout uses an SSH host alias or
Cloud preview finds no usable remote, verify the project's Git URL in Sonar.
Pass it as `--source-repository-url` when previewing the capture. At least
one comparable remote must match if the checkout has any. A changed fetch
URL requires a new preview.

Each Sonar issue key identifies one record within its source and repository.
Reimport updates its evidence, including file ranges and available data flows.
In a monorepo, repository-relative locations require a verified Sonar project
base directory.

### Use a native JSON export

For a saved `GET /api/issues/search` response, use a single page if it
contains the complete result. Otherwise supply an array of all pages in
order for the same project and ref. Pages can omit repository and ref context.
Run the example from the checkout root and supply its verified repository URL.
The example source key is for a new stream.

To update issues from an earlier capture, use its preview's `repository` path
for `--repository` and its exact `sourceKey` (`sonar:<hash>`) for `--source-key`.
The local `publish findings` preview shows `source.source_key`, and each stored
record has a `sourceKey`. Updating a matching issue replaces its evidence.
Native pages can omit the issue URL and repository-relative locations. Replay
the capture to preserve those fields, or use another key to store both versions.

```sh
codex-security publish findings ../reports/sonar-pages.json --provider sonar \
  --to local --repository . --source-repository-url https://github.com/example/project \
  --source-key sonarcloud.io/example/example_project/branch/main --dry-run --format json
```

[Save and verify the native file](README.md#save-or-publish-and-verify) with the
same `publish findings` command.
