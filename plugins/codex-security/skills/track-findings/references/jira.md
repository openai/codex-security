# Jira Issues

Use this reference only when the destination is `jira`.

## Contract

- Track one validated finding or an explicitly selected batch of up to 25. Use one Jira Cloud issue per finding.
- Use only the native [Atlassian Rovo](app://asdk_app_6a83901dde988191b3f3cefdcc19acfa) app. Reuse needs read and search access but not write access. Create and update need all three. Stop if the app is unavailable, disconnected, cannot read the destination, or cannot perform the approved mutation.
- Pin one authenticated Atlassian identity, site and `cloudId`, project key, and issue type from duplicate checks through readback. Use the same destination and issue type for every item in a batch. Start a separate run for work that needs another site, project, or issue type.
- Require the user to explicitly confirm that the project audience is approved to see the finding details. One confirmation may cover an exact reviewed batch. Jira create permission does not prove who can read the issues.

Do not use the legacy Jira connector, Jira Data Center, Jira Service Management request workflows, CLI tools, direct REST, browser automation, or Computer Use.

## Tool Discovery

Use the tools exposed by the selected Atlassian Rovo app and their live input schemas. The current Rovo catalog exposes primary tools directly and metadata tools through `discover` and `executeRead`. If an operation is deferred, discover it and use the returned schema and execution pathway. An `executeWrite` call is a mutation and requires the same exact preview and approval as a directly exposed write tool. Do not treat discovery as permission to write.

Resolve the read, search, and intended write operations before previewing a mutation. Tool availability depends on the connection and its granted permissions. If discovery cannot provide a required operation, stop and explain which access or capability is missing. Do not substitute a similarly named tool from the legacy connection.

## Destination And Fields

Call the Rovo tools in this order:

1. Resolve the exact site with `getAccessibleAtlassianResources` and the current identity with `atlassianUserInfo`.
2. Resolve the selected project with `listJiraProjects`. Confirm the intended create, edit, or browse access using the operation filter or permission information exposed by its live schema and results. A visible project alone does not prove write access.
3. Resolve the selected issue type with `listJiraProjectIssueTypesMetadata`.
4. Fetch its current fields with `getJiraIssueTypeMetaWithFields`.

Select the site, project, and issue type from an explicit choice in the current request or one unambiguous live result. Stop on ambiguity. Fetch every page when results are paginated. For a batch, confirm each operation required by its proposed `create`, `update`, or `reuse` outcome. Keep the destination pinned.

Build each create payload from the live `createJiraIssue` schema using:

- the pinned site, project, issue type, summary, and approved description
- any approved optional fields supported by the schema

Use Markdown when supported and select its content format explicitly when the schema exposes that choice. Use the schema's designated container for priority, components, labels, and custom fields (`additional_fields` when exposed); do not copy a payload from the legacy connector. Include every field required by live metadata. Use an optional field only after verifying its key or id and value live and getting user approval. Build update payloads from the live `editJiraIssue` schema with only the approved changed fields.

Never:

- guess a custom field id
- map finding severity to Jira priority
- infer an assignee
- invent a label as an idempotency key

Include the canonical finding id and primary fingerprint as labeled text in the description. Add the approved finding details, remediation, and the source block or role-aware plain locations required by the main skill. Include only content approved for the confirmed project audience.

## Duplicates

For every selected finding, use `searchJiraIssuesUsingJql`. Use project-scoped JQL for the finding id and fingerprint, but search each value separately. Do not combine bindings from several findings in one query. Escape scan-derived values as JQL data, exhaust pagination using the live schema and returned continuation tokens, and search all statuses. Do not print unrelated issue descriptions.

JQL tokenization does not prove an exact match. Read every plausible candidate with `getJiraIssue`. Compare its labeled bindings, affected area, root cause, and source context. After the exact-binding searches, use narrow semantic terms only when the confirmed audience is safe for them.

- `create`: both searches are complete and no reviewed candidate is the same finding.
- `reuse`: one issue carries both exact bindings and its approved content is already current.
- `update`: one issue is clearly the same finding and the exact proposed field changes have been previewed.
- `blocked`: candidates are unreadable, bindings point to different or multiple issues, or semantic ambiguity remains.

An update may change only the approved fields. Preserve unowned fields. Do not transition the issue or add a comment as part of tracking.

## Preview, Write, And Verify

Before any mutation, preview:

- the authenticated identity
- the site URL and `cloudId`
- the project key and issue type
- the audience confirmation and duplicate outcome
- the exact summary and Markdown description
- every additional field

For a batch, show every item in execution order and get one explicit approval covering that exact list.

Immediately before each create, update, or reuse, rerun source validation with that finding's exact id. Then recheck the identity, site, intended operation access, project, issue type metadata, audience confirmation, and duplicate results. If anything changes, preview again.

Process a batch serially in its approved order. For each `create`, call `createJiraIssue` exactly once. For each `update`, call `editJiraIssue` exactly once with only the approved fields. Never retry when a mutation may have succeeded. If a create does not return one issue key, search the exact bindings and stop as uncertain.

Read the resulting key with `getJiraIssue` before continuing to the next item. Verify the site, project, issue type, summary, description, both bindings, source context, and approved metadata. Jira may return the description as rendered content or a document; compare its text, structure, and links semantically instead of requiring byte-identical Markdown. Stop the batch on the first failed or uncertain result. Report success and construct the canonical site URL only after readback passes.

If a batch stops early, reconstruct completed items from exact provider readback and binding searches. Rerun source and duplicate checks. Then preview the remaining items again before resuming.

## Non-Goals

Do not add comments, transition issues, log work, attach files, or link issues. Do not manage watchers, create projects or users, change project settings, or perform Jira Service Management request actions. Do not use one approved item as permission for a second mutation or an unpreviewed finding.
