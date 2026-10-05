# Plugin connectors

Codex Security uses optional connected apps for ticket intake and finding tracking. Their identities are declared in `plugins/codex-security/.app.json`.

| App       | Workflows                                         |
| --------- | ------------------------------------------------- |
| Linear    | Ticket intake and finding tracking                |
| GitHub    | Finding intake, source lookup, and issue tracking |
| Atlassian | Jira Cloud ticket intake and finding tracking     |

## Jira setup

Connect the **Atlassian** app in the app directory. Existing Atlassian Rovo (Legacy) connections do not connect the new app; authorize it separately with the intended account and site.

Intake and duplicate checks need read and search access. Creating or updating issues also needs write access. Before creating an issue, the tracking skill resolves the project, issue type, and required fields.

Use the app's live schemas and discover deferred operations when needed. See Atlassian's [supported tools](https://developer.atlassian.com/cloud/rovo-mcp/guides/supported-tools/) and the skill's [Jira workflow](../plugins/codex-security/skills/track-findings/references/jira.md).

## QA

Test the plugin build with synthetic findings in a selected QA project:

- Verify that Jira calls use the new Atlassian app and the selected account and site.
- Read a synthetic issue directly and through project-scoped JQL, including pagination.
- Create one issue, reuse it without creating a duplicate, and update approved fields. Verify each write by reading the issue back.
- Verify that missing connections and insufficient access produce recovery guidance without duplicate creates.

Record live results separately from static checks. Keep account and project details, issue keys, and raw tool responses out of public PRs.
