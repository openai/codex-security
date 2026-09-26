# Plugin connectors

Codex Security uses connected apps to import tickets and track findings.
The apps are declared in `plugins/codex-security/.app.json` and are optional
until a workflow needs them.

| Manifest key | Connected app | Workflows |
| --- | --- | --- |
| `linear` | Linear | Ticket intake and finding tracking |
| `github` | GitHub | Finding intake, source lookup, and issue tracking |
| `atlassian` | Atlassian Rovo | Jira Cloud ticket intake and finding tracking |

Draft GitHub security advisories require authenticated GitHub CLI access, as
described in the tracking skill. The local `codex-security` MCP server supplies
scan and artifact tools.

## Jira setup

1. Enable Atlassian Rovo in the app directory and connect the intended account.
   If an administrator has disabled the app, ask them to enable it.
2. Confirm the account, site, and project in the connected app.
3. Check read and search access for intake and duplicate checks, and write
   access for creating or updating issues. Fetch the selected issue type's
   required fields before preparing a write.

Use the app's live tool schemas. Discover deferred operations through the app,
and stop if a required operation is unavailable. See Atlassian's
[supported tools](https://developer.atlassian.com/cloud/rovo-mcp/guides/supported-tools/).

Before creating an issue, search for the finding's canonical ID and fingerprint.
Reuse an issue when both bindings and its content match. If a write's outcome
is uncertain, read the issue or search those bindings before taking further
action. See the tracking skill's Jira reference for the full workflow.

## Live QA

Load the plugin build under test in a fresh test profile. Use a selected QA
account and project with synthetic ticket content. Keep account identities,
site URLs, project and issue keys, raw responses, and tool logs out of public
PRs. Record the tested commit and test outcomes separately from private evidence.

| Case | Expected result |
| --- | --- |
| App loading | The plugin selects the declared Atlassian Rovo app and uses its connection for Jira calls. |
| Destination | The account, site, project, issue type, and required fields resolve, including deferred tools when exposed. |
| Intake | Read a synthetic issue directly and through project-scoped JQL. Read every result page, preserve provenance, and make no writes. |
| Create | Preview a synthetic finding with a unique canonical ID and fingerprint, get approval for the QA audience, create once, and read the issue to verify its content. |
| Reuse | Find an existing synthetic issue by both bindings and reuse its key without creating a duplicate. |
| Update | Preview a description change, get approval, update once, and read the issue to verify the change. Preserve unowned fields. |
| Access failure | With a disconnected or insufficiently permitted connection, stop with recovery guidance. Use only the selected app. |
| Other apps | Confirm GitHub and Linear resolve and read a selected synthetic ticket through each available QA connection. |

Mark a case blocked when its app, QA destination, or required permissions are
unavailable. Record live QA separately from catalog checks, static tests, and
builds.

## Local checks

Run the portable source checks in `AGENTS.md`, then:

```bash
python -m pytest plugins/codex-security/tests/test_track_findings_skill.py -q
pnpm --dir plugins/codex-security/skills/triage-finding/evals run test:deterministic
pnpm --dir sdk/typescript run build:plugin
```

Check that `sdk/typescript/_bundled_plugin/.app.json` and the bundled skill
links match the source. The manifest regression test checks each skill app link
against the declared connector IDs.
