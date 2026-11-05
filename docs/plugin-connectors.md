# Plugin connectors

Connect an app when you want Codex Security to read findings from a service
or track them in an issue. Local repository scans work without these apps.

| App                  | Use it to                                                                      | Setup                                                                              |
| -------------------- | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| Codex Security Cloud | Read findings, evidence, reports, and scan status in your workspace.           | [Connect Cloud in Codex](../sdk/typescript/README.md#read-existing-cloud-findings) |
| Linear               | Read tickets and track findings in a team or project.                          | [Connect Linear](#linear-setup)                                                    |
| GitHub               | Read alerts and repository source, track issues, or draft a security advisory. | [Connect GitHub](#github-setup)                                                    |
| Atlassian            | Read Jira Cloud tickets and track findings in a project.                       | [Connect Jira](#jira-setup)                                                        |

## Linear setup

Connect **Linear** in the Codex app directory with the account that can access
your team. Give Codex a ticket URL to triage, or name the team and optional
project where you want to track a finding. To use an existing Linear MCP
connection for reads, specify the account and workspace.
See [ticket intake](../plugins/codex-security/skills/triage-finding/references/ticket-intake.md#retrieval).

## GitHub setup

Connect **GitHub** in the app directory with access to the repository and the
type of alert you want to read. Give Codex the repository and an issue or alert
URL. To use an existing GitHub CLI login for triage, specify the host and
account. See [GitHub intake](../plugins/codex-security/skills/triage-finding/references/github-rest-intake.md).
When tracking a finding, specify whether it belongs in an issue or a
[draft security advisory](../plugins/codex-security/skills/track-findings/references/github-security-advisories.md).

## Jira setup

Connect **Atlassian** in the Codex app directory and authorize the account and
site that contain your Jira project. If you already use Atlassian Rovo (Legacy), authorize
the Atlassian app separately. Give Codex an issue key and site, or a Jira Query
Language (JQL) query to select the tickets to read.
See [Jira ticket intake](../plugins/codex-security/skills/triage-finding/references/ticket-intake.md#retrieval)
for using an already signed-in Jira CLI.

## Track a finding

Give Codex the saved scan directory, the finding ID, and the destination. Ask
it to check for an existing issue. The account needs read and search access to
check for duplicates. To create or update an issue, it also needs write access.
Review the destination, audience, and proposed changes before approving a write.
If Codex cannot find a ticket you can see, check the signed-in account and the
selected site, workspace, or repository.

When the plugin and CLI use the same local state directory, both can find issue
links saved by earlier tracking or publication runs. Codex checks a saved link
against the tracker before reusing it and searches the destination for other
matches. You can also track findings from a sealed scan bundle copied from
another machine. Codex saves new issue associations outside the bundle, even
if an issue was created but its follow-up read failed. On retry, check that
issue before approving another write.
See the [tracking workflow](../plugins/codex-security/skills/track-findings/SKILL.md).

To import a scanner report instead, use the [scanner import guides](scanner-imports/README.md)
to choose the input format, preview the records, and select a destination.
