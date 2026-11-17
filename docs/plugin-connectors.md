# Codex Security integrations

Use a connected app in Codex to investigate a finding or track it in an issue.
The [CLI integrations](#cli-integrations) cover importing scanner reports,
publishing completed scans, and exporting files for other systems.

## Plugin connectors

Connect the app you need in the account and workspace that hold the data.
Local scans and saved-report imports work without an app connection.

| App                  | What you can do in Codex                                         | Setup                                                                                |
| -------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Codex Security Cloud | Read saved findings, their evidence, and scan status.            | [Connect Cloud in Codex](../sdk/typescript/docs/sdk.md#read-existing-cloud-findings) |
| Linear               | Read tickets for triage and track findings in a team or project. | [Linear setup](#linear-setup)                                                        |
| GitHub               | Read repository source and alerts, and track findings in issues. | [GitHub setup](#github-setup)                                                        |
| Atlassian            | Read Jira Cloud issues and track findings in a project.          | [Jira setup](#jira-setup)                                                            |

### Linear setup

Connect **Linear** in the Codex app directory. To triage a ticket, give
Codex its URL or identifier and the workspace. To track a finding, name the
destination team and optional project. If you want to use an existing Linear
MCP connection for reads, specify the connection and workspace. [Ticket intake](../plugins/codex-security/skills/triage-finding/references/ticket-intake.md#retrieval)

### GitHub setup

Connect **GitHub** with access to the source repository and the issue or
alert you want to read. Give Codex its URL. For triage with an existing
GitHub CLI login, specify the host and account. [GitHub intake](../plugins/codex-security/skills/triage-finding/references/github-rest-intake.md)

To draft a repository security advisory, select the GitHub CLI (`gh`) account.
The advisory workflow requires one validated finding from a sealed Git revision
and admin access to its public, non-fork source repository on GitHub.com.
[Draft advisory workflow](../plugins/codex-security/skills/track-findings/references/github-security-advisories.md)

### Jira setup

Connect **Atlassian** to the Jira Cloud site that holds the project.
Give Codex the site and issue key for a single issue, or a Jira Query
Language (JQL) query for a collection. To read through an already
authenticated Atlassian CLI instead, specify the site and account.
[Jira ticket intake](../plugins/codex-security/skills/triage-finding/references/ticket-intake.md#retrieval)

## Track a finding

Give Codex the sealed scan directory, the finding ID, and the destination.
The tracking workflow checks saved links and searches the destination for
duplicates before proposing a write. Review the issue content and audience.
The account needs search and read access for duplicate checks, plus the
appropriate create or edit permission for the proposed change.
[Tracking workflow](../plugins/codex-security/skills/track-findings/SKILL.md)

Issue links are stored outside the sealed scan bundle. If a tracker accepts
a write but its follow-up read fails, use the returned issue ID to check the
outcome before retrying. The plugin and CLI share local issue history when
they use the same state directory. For CLI publication to Linear,
`--skip-existing` consults that history. [Linear publication](../sdk/typescript/docs/cli.md#publish-completed-scans-to-linear)

## CLI integrations

Use the `codex-security` CLI for these workflows.

| Input                                                            | Destination                                     | Workflow                                                                                                                                                                                                  |
| ---------------------------------------------------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A saved third-party scanner report                               | Local workbench, or Cloud for supported reports | Use `publish findings` with the options in your [scanner guide](scanner-imports/README.md). Add `--to local --dry-run` for an offline preview.                                                            |
| A completed Codex Security scan or a Codex Security findings CSV | Codex Security Cloud                            | Preview offline with `publish scan --to cloud --dry-run`. Upload uses file-backed ChatGPT credentials. [Cloud publication](../sdk/typescript/docs/cli.md#publish-completed-scans)                         |
| A completed scan                                                 | Linear                                          | Use `publish scan --to linear` with a destination team. Authenticate through the connected app or a Linear API key. [Linear publication](../sdk/typescript/docs/cli.md#publish-completed-scans-to-linear) |
| A completed scan                                                 | A findings service you operate                  | Use `publish scan --to custom` with a compatible service's base URL. [Endpoint contract and dry run](../sdk/typescript/docs/findings-service.md#publish-a-scan)                                           |
| Findings from a completed scan                                   | ServiceNow or a CI system                       | Export a [ServiceNow AVIT CSV](../sdk/typescript/docs/cli.md#export-findings-for-servicenow) for manual upload or [SARIF for CI](../sdk/typescript/docs/cli.md#use-exports-in-ci).                        |
