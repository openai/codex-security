<!-- release-version: 0.1.26 -->

## Highlights

- Classify finding severity with custom rubrics and supporting context through
  the CLI and SDK. Saved assessments can be reused for Linear publication
  without changing the original findings or sealed scan artifacts. See
  [severity classification](https://github.com/openai/codex-security/blob/npm-v0.1.26/sdk/typescript/README.md#classify-finding-severity).
- Match repeated findings across scan history, preserving confirmed identities
  and related-finding relationships. Automatic matching restores batching, and
  confirmed-finding lookups are faster.
- Open draft GitLab merge requests for verified patches with the existing
  `--create-pr` option, including self-hosted GitLab. See
  [patch publication](https://github.com/openai/codex-security/blob/npm-v0.1.26/sdk/typescript/README.md#validate-and-patch-findings).
- Report component scan progress in headless runs and exclude replayed usage
  events with identical timestamps from scan budgets.
- Preserve analytics settings in finding workflows and allow 120 seconds for
  the bundled plugin's MCP server to start.
- Require an explicit request before invoking the security fix verification
  skill during other work.

## Upgrade notes

- GitLab patch publication requires an installed and authenticated `glab` CLI.
  For self-hosted GitLab, configure the host as described in the patch
  publication documentation above.
- Severity classification is opt-in. Without a rubric, it inherits the
  finding's existing severity without a model call.
- With `--max-cost`, automatic history matching makes at most one extra model
  call. If matching needs more context, the completed scan is retained and a
  warning directs you to run `scans match --all` explicitly.

The categorized list below contains the individual changes.
