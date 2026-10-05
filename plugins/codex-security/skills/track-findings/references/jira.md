# Jira Issues

Use this reference when the destination is `jira`. Use only the native [Atlassian](app://asdk_app_6a83901dde988191b3f3cefdcc19acfa) app and its live input schemas. Discover deferred operations with `discover` and call the returned execution tool. Write tools require the same reviewed payload and approval as direct mutations.

## Destination And Fields

Resolve the current identity with `atlassianUserInfo` and the selected site with `getAccessibleAtlassianResources`. Keep that identity, site and `cloudId`, project, and issue type for the run. Choose from the user's current request or unambiguous live results. Follow the main skill's audience confirmation and batch selection rules.

Use `listJiraProjects` to resolve the project. For a new issue, confirm browse and create access using its live filters or equivalent permission data. For an existing issue, a successful read establishes read access. An empty JQL result or project visibility alone does not establish issue access. Check edit access when proposing an update.

For a create, resolve the issue type with `listJiraProjectIssueTypesMetadata` and required fields with `getJiraIssueTypeMetaWithFields`. Fetch additional pages only as needed to resolve the selected value or complete a search. Reuse this metadata during the run; a reuse or summary-only edit does not need create-field discovery.

Build `createJiraIssue` with the selected project and type, approved summary and description, and required fields. Use Markdown explicitly when supported. Include the finding id and fingerprint as labeled text, and the main skill's source details or role-aware plain locations. Verify optional field keys and values against live metadata. Do not guess custom field ids, severity-to-priority mappings, assignees, or labels.

Build `editJiraIssue` with only the approved changes. Preserve unowned fields and existing rich content; a summary-only edit does not need the description resent.

## Duplicates

Use project-scoped `searchJiraIssuesUsingJql` for the finding id and fingerprint separately, across all statuses. Escape values as JQL data and follow returned continuation tokens until complete. Read plausible candidates with `getJiraIssue`; search tokenization alone does not prove a match. Use narrow semantic terms when needed and safe for the confirmed audience.

Use model judgment to compare the affected code, root cause, and source context, with binding identifiers when present:

- `create`: searches are complete and no candidate tracks the same finding.
- `reuse`: one issue already tracks the finding, established by a read or this run's successful create receipt. It does not need identical wording or newly added bindings.
- `update`: one issue tracks the finding and the user approved specific changes.
- `blocked`: an unreadable candidate or conflicting evidence prevents deciding whether a duplicate exists.

Reuse is read-only. Do not add bindings or rewrite an existing issue merely to reuse it.

## Write And Report

Follow the main skill's preview and approval flow. Keep successful reads and metadata from this run; refresh when there is evidence of change or after an interruption. Do not repeat identity, issue-type, and field lookups before every item.

Call `createJiraIssue` or `editJiraIssue` once with the approved payload. Trust a successful create response returning an issue key or id as evidence of creation. Use that returned identity for an already approved follow-up edit; do not require a separate read to rediscover the payload just sent.

When possible, read the result with `getJiraIssue` to check the destination and changed fields. Compare descriptions by meaning, structure, and links rather than byte-identical Markdown. Report a failed follow-up read separately from an accepted write, including the returned issue identity. A read failure does not authorize another create. If the mutation itself is uncertain, reconcile through binding searches or an exact read, then stop if its outcome remains unknown.

Construct the issue URL from the pinned site and returned key. Distinguish an accepted write, a verified read, and an access failure in the result; live QA must report which operations actually passed.

Do not add comments, transition issues, attach files, manage watchers, create projects or users, or change project settings as part of tracking.
