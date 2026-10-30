# Import SonarQube Cloud security issues

Import the open security issues for a SonarQube Cloud project or the issues
you selected in the SonarQube plugin for Codex. The live import uses the
authenticated `sonar` CLI to read findings from the project's Issues view.
A live fetch saves a capture so you can review and publish the same records later.

## Start in Codex

In the checkout, ask the SonarQube plugin to show security issues on a branch
or pull request. Then ask Codex Security to “import those two findings locally”
or “import those two findings locally and publish them to Codex Security Cloud.”
The [publish-findings skill](../../plugins/codex-security/skills/publish-findings/SKILL.md#sonarqube-cloud-issues)
uses the project's key, the selected ref, and the original Sonar issue keys to
retrieve the full records and preview the destination. You can also start in
the terminal with those same identifiers. If you installed only the Codex
Security plugin, install a version of `@openai/codex-security` that includes
the Sonar importer from a trusted directory, then run that CLI in the checkout.

## Preview a local import

Run the command from the matching checkout. Enable external imports for the
session. If you already use the Sonar plugin's issue list, the collector uses
the same `sonar` login. For first-time setup, sign in with `sonar auth login`
using an account that can browse the selected project.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security import sonar --sonar-project example_project --sonar-branch main \
  --sonar-issue ISSUE_A --sonar-issue ISSUE_B --dry-run --format json
```

For a pull request, replace `--sonar-branch main` with, for example,
`--sonar-pull-request 42`. With neither ref option, the collector reads the
project's main branch. Omit the issue options to collect open security
issues for the selected project and ref. If Sonar cannot supply the project's
repository binding, verify its Git URL in Sonar and retry the preview with
`import sonar CAPTURE --source-repository-url GIT_URL --dry-run --format json`
using the reported capture path. Check the target and selection before importing.

The preview saves a private copy even when the input is a file. Use the path
it returns in `capture` to import the reviewed evidence into the local
workbench, then read it back:

```sh
codex-security import sonar "/path/from/capture.json" --yes
codex-security findings imported . --format json
```

Codex Security keeps each Sonar issue key and its native evidence, including
reported file ranges and available data-flow traces. For monorepos, Codex
Security maps paths relative to the Sonar project when it can verify the
project's base directory in the checkout. When the base is unknown, the
native components, ranges and flows remain available in the evidence.
Reimporting the same issue in the same source and repository updates its
record. Imported records start as unassessed findings.

## Publish the same capture to Cloud

From the same checkout, preview the capture with your Codex Security Cloud
login. Your Cloud account must be enabled for external imports, and the
deployment must accept the `sonar` source provider. Review the Cloud account,
repository, environments, counts, and exclusions before confirming. Use
the `capture` path from this Cloud preview to confirm. If the destination
changes, preview again and confirm using the new path. Replaying the capture
works without a Sonar login. For a checkout without a matching Git remote,
verify the Sonar project's repository and pass `--source-repository-url` to
the Cloud preview.

```sh
codex-security import sonar "/path/from/local-preview.json" --to cloud --dry-run --format json
codex-security import sonar "/path/from/cloud-preview.json" --to cloud --yes
```

For a single local-and-Cloud workflow, add `--to cloud` to the first live
preview and confirm using its saved capture. If Cloud authentication or
repository selection fails, you can finish the local import, then rerun the
Cloud preview with the saved capture. If an approved upload is interrupted,
retry with the same file and destination.

## Use a native JSON export

If you already have the complete response from `GET /api/issues/search` for
one project and ref, save the page object or an array containing every page.
The file reader uses the repository URL you verified for that Sonar project:

```sh
codex-security publish findings "/path/to/sonar-pages.json" --provider sonar \
  --to local --repository . --source-repository-url https://github.com/example/project \
  --source-key sonarcloud.io/example/example_project/branch/main --dry-run --format json
```

Keep the source key stable for the same Sonar instance, organization, project,
and ref. For updates to a previous import, use its exact source key. The
native page can omit the branch, project repository URL, and Sonar instance.
Only a Codex Security capture carries the collector's context for offline replay.

See [Sonar's Codex plugin](https://www.sonarsource.com/blog/now-available-sonarqube-plugin-for-codex/),
[Sonar CLI authentication](https://docs.sonarsource.com/sonarqube-cli/quickstart-guide#step-2-authenticate),
and the [Codex Security Cloud publication guide](../../sdk/typescript/docs/cli.md#publish-findings-to-cloud).
