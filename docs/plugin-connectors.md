# Plugin connectors and Jira migration

Codex Security declares its connected apps in
`plugins/codex-security/.app.json`. These integrations are optional until a
workflow needs them. The plugin does not implement a separate Jira client.

| Manifest key | Connected app | Workflows |
| --- | --- | --- |
| `linear` | Linear | Ticket intake and finding tracking |
| `github` | GitHub | Selected finding intake, source lookup, issues, and draft security advisories |
| `atlassian` | Atlassian Rovo | Jira Cloud ticket intake and finding tracking |

There is no Asana integration. The local `codex-security` MCP server in
`.mcp.json` supplies scan and artifact tools; it is not a ticketing connector.
The CLI's Linear publication workflow is separate from the plugin's Jira
workflow.

## Upgrade from the legacy Atlassian connector

The `atlassian` entry now selects the Atlassian Rovo app
`asdk_app_6a83901dde988191b3f3cefdcc19acfa`. The manifest key and Jira workflow
remain the same. No CLI command, flag, scan artifact, or saved finding binding
changes.

1. Update the plugin and enable Atlassian Rovo in the app directory. If the app
   is disabled by an administrator, have the administrator enable it first.
2. Connect the intended Atlassian account. An existing legacy connection is
   not evidence that the replacement app is connected or authorized.
3. Start a new chat with the updated plugin so its manifest and skills are
   loaded together. Verify the app, account, site, and intended project.
4. Check read and search access for intake and duplicate checks, and write
   access for creation or updates. Review the live issue-type field metadata.
5. For existing findings, search their canonical IDs and fingerprints before
   creating anything. Reuse an existing issue when both bindings and content
   match. Do not copy issues or rewrite bindings merely because the connector
   changed.

The workflow uses the app's live tool schemas and supports deferred metadata
tools through discovery. See Atlassian's
[supported tools](https://developer.atlassian.com/cloud/rovo-mcp/guides/supported-tools/).
If an operation is missing or access is denied, stop and resolve the connection
or permissions. Do not silently fall back to the legacy connector or another
transport. Keep an uncertain mutation unresolved until an exact readback or
binding search establishes its outcome.

## Live QA before rollout

Use the candidate plugin in a fresh chat, an explicitly selected QA account and
project, and synthetic ticket content. Keep account identities, site URLs,
project keys, issue keys, raw responses, and tool logs out of public PRs.
Record the tested commit and pass/fail outcomes separately from private evidence.

| Case | Required evidence |
| --- | --- |
| App loading | Candidate manifest resolves the replacement Atlassian Rovo app; Jira calls use that app's connection. |
| Destination discovery | Identity, accessible site, project, issue type, and required fields resolve through the new app, including deferred tools if exposed. |
| Exact and JQL intake | Read one synthetic issue directly and through project-scoped JQL. Exhaust pagination when present. Preserve provenance and perform no writes. |
| Create and readback | Preview a synthetic finding with a unique canonical ID and fingerprint, approve it for the QA audience, create once, and verify the resulting issue through the new app. |
| Reuse after migration | Find an existing synthetic issue by both bindings, including an issue created before the upgrade. Reuse its key without creating a duplicate. |
| Update and readback | Preview one changed description, approve it, update once, and verify the change while preserving unowned fields. |
| Unavailable access | With a disconnected or insufficiently permitted QA connection, stop with recovery guidance and no legacy/REST fallback. |
| Other connectors | Confirm GitHub and Linear still resolve; perform a read of a selected synthetic ticket through each available QA connection. |

Approve only the exact test writes. Mark live cases blocked when the replacement
app, QA destination, or required permissions are unavailable. Catalog resolution,
legacy-connector calls, static assertions, simulated evals, and package builds
do not establish that live QA passed. Keep a migration PR in draft until the
required live cases pass.

## Local checks

Run the portable source checks in `AGENTS.md`, then:

```bash
python -m pytest plugins/codex-security/tests/test_track_findings_skill.py -q
pnpm --dir plugins/codex-security/skills/triage-finding/evals run test:deterministic
pnpm --dir sdk/typescript run build:plugin
```

Inspect the generated
`sdk/typescript/_bundled_plugin/.app.json` and skill links to confirm the package
contains the same app ID as the source manifest. The manifest regression test
also checks every skill app link against the declared connector IDs.
