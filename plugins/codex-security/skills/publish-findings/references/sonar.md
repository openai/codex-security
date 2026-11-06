# SonarQube Cloud issues

For “import these Sonar findings,” carry over the Sonar project, branch or PR, and the exact issue keys selected in the [SonarQube plugin for Codex](https://www.sonarsource.com/blog/now-available-sonarqube-plugin-for-codex/). Use the keys from the underlying Sonar result. If only a formatted table remains, resolve the selected rows against the same project and ref and ask about ambiguous matches. A rule can occur more than once. Never turn a selection into a project-wide import.

From the intended checkout, preview the selection using the developer's authenticated `sonar` CLI. Use `--sonar-pull-request` in place of `--sonar-branch` for a PR. Omit `--sonar-issue` only when the user wants the project's open security issues. If the project has no verified SCM binding, confirm the repository URL that belongs to the project and pass it with `--source-repository-url`.

```sh
codex-security import sonar --sonar-project example_project --sonar-branch main \
  --sonar-issue ISSUE_A --sonar-issue ISSUE_B --dry-run --format json
```

Pass `--to cloud` at preview time if the user also requested Cloud publication. Show the selected issues and exclusions, the local repository, and any Cloud destination as described under [Publish to Cloud](../SKILL.md#publish-to-cloud). The preview returns a private evidence file in `capture`. After confirmation, run `codex-security import sonar CAPTURE --yes` for local import. For Cloud, use the exact `capture` from the successful Cloud preview and add `--to cloud`. If the account, repository, or environment changes, show a fresh preview and ask for confirmation. If Cloud is unavailable, finish the requested local import and report the Cloud error. For a request to publish an existing import, start with its capture. Report the saved path so the developer can resume.

Sonar authentication is required only for a live fetch. If the local CLI lacks a login, direct the user to `sonar auth login` and keep the selection. A hosted MCP connection can help identify issues, but its issue summaries omit flow evidence. Use the signed-in CLI or a saved Codex Security Sonar capture to complete the import. If `codex-security` is absent, ask the user to install it from a trusted directory and invoke that installed executable in the checkout.
