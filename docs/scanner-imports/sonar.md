# Import SonarQube Cloud findings

Use `import sonar` to collect security issues for one project and branch or
pull request. A `--dry-run` with either live issues or a saved capture writes a private evidence copy and returns its path. Pass that path to confirm the reviewed selection.
Replay it without signing in to Sonar. If you already have issue-search JSON,
[preview the native export](#use-a-native-json-export).

## Quick start

From the matching checkout, run `sonar auth login` with browse access to the project's Sonar
organization. [Sonar CLI authentication](https://docs.sonarsource.com/sonarqube-cli/quickstart-guide#step-2-authenticate)

**Preview live issues.** Copy the project and issue keys from Sonar's Issues
view or the SonarQube plugin for Codex. Replace the example keys and branch.

```sh
codex-security import sonar --sonar-project example_project --sonar-branch main \
  --sonar-issue ISSUE_A --sonar-issue ISSUE_B --dry-run --format json
```

Repeated `--sonar-issue` selects the requested security issues regardless of
status. Omit it to collect open and confirmed security issues for the selected
ref. For a pull request, replace `--sonar-branch main` with
`--sonar-pull-request 42`. Omit both to use the project's main branch.

Check the repository and ref. Compare the issue keys in
`local.findings[].source_finding_id` and any `local.excluded` entries with
your selection. Keep the private path returned in `capture` to
[save locally](#save-locally) or [save locally and publish to Cloud](#save-locally-and-publish-to-cloud).

## Import and verify

### Save locally

From the same checkout, pass the local preview's `capture`
path. Omit `--yes` for an interactive prompt. In a script, use `--yes`
after review.

```sh
codex-security import sonar "/path/from/local-preview.json" --yes
```

### Save locally and publish to Cloud

[Sign in to Cloud](../../sdk/typescript/docs/cli.md#preview-and-publish)
on a deployment that accepts the `sonar` provider. Preview the connected
repository from the local capture.

```sh
codex-security import sonar "/path/from/local-preview.json" --to cloud --dry-run --format json
```

Check the account, repository and any environment listed in `cloud`. Confirm
with the new `capture` path from the successful Cloud preview.

```sh
codex-security import sonar "/path/from/cloud-preview.json" --to cloud --yes --format json
```

For [readback and verification](README.md#verify-the-import), use
the preview's local `repository` path. Check `cloud` and any `cloudError`
if you published.

If the checkout, state directory or Cloud destination changes, preview the
capture again. To resume an interrupted upload, reuse the approved capture
and destination.

## Project and repository selection

Omit `--sonar-project` only when the checkout's Git origin maps to exactly
one project in the active organization. For a monorepo, supply the project
key. If a search exceeds 10,000 results, select issue keys.
[SonarQube plugin](https://www.sonarsource.com/blog/now-available-sonarqube-plugin-for-codex/) · [Codex Security import workflow](../../plugins/codex-security/skills/publish-findings/SKILL.md#sonarqube-cloud-issues)

If Sonar lacks a repository binding, Git uses an SSH host alias or Cloud
finds no usable remote, verify the project's Git URL in Sonar. Pass it as
`--source-repository-url` when previewing the capture. At least one
comparable remote must match if the checkout has any. Preview again if a
fetch URL changes.

Each issue key identifies one record within its source and repository.
The title is the rule name when available, otherwise the rule key. The
description is the issue message. Severity comes from the security impact,
or the native severity for a legacy vulnerability. The capture supplies a
link to that issue on the selected branch or pull request. The primary file
range requires a verified project base directory. Other flow locations and
their messages remain in the original issue under `evidence.source_data.issue.flows`.

## Use a native JSON export

Supply one complete `GET /api/issues/search` page or an ordered array of
all pages for one project and ref. Pages can omit repository and ref context.
Run this preview from the checkout root with the verified repository URL.
The example starts a new source key.

```sh
codex-security publish findings ../reports/sonar-pages.json --provider sonar \
  --to local --repository . --source-repository-url https://github.com/example/project \
  --source-key sonarcloud.io/example/example_project/branch/main --dry-run --format json
```

To update issues from a capture, pass its preview's `repository` path and
exact `sourceKey` (`sonar:<hash>`) as `--repository` and `--source-key`.
Check `source.source_key` in the file preview or `sourceKey` on a stored
record. Native pages replace matching evidence and can omit issue URLs and
repository-relative locations. Replay the capture to retain those fields,
or use another key to keep both versions.
[Save or publish the native report and verify the result](README.md#save-or-publish-and-verify)
