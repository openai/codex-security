# Jira issues

Use the native [Atlassian](app://asdk_app_6a83901dde988191b3f3cefdcc19acfa) app and its live schemas. Discover deferred operations with `discover` and call the returned execution tool. Deferred writes follow the main skill's approval flow.

## Destination and fields

Resolve identity with `atlassianUserInfo` and site with `getAccessibleAtlassianResources`. Pin that identity, site, `cloudId`, project, and issue type for the run. Ask when the user's request and live results leave the destination ambiguous.

Resolve the project with `listJiraProjects`. For creates, confirm browse and create access through its live filters or equivalent permission data. For existing issues, a successful read establishes read access; an empty JQL result or visible project does not. Check edit access for updates.

For creates, resolve the type with `listJiraProjectIssueTypesMetadata` and required fields with `getJiraIssueTypeMetaWithFields`. Follow pages needed to resolve the selected values. Reuse metadata during the run; reuse and summary-only edits do not need create-field discovery.

Build `createJiraIssue` with the approved project, type, summary, description, and required fields. Select Markdown when supported. Verify optional field keys and values against live metadata; do not guess custom fields, priority mappings, assignees, or labels. The main skill defines source details and binding identifiers.

Build `editJiraIssue` with only the approved changes. A summary-only edit does not resend the description.

## Duplicates

Search the finding id and fingerprint separately with project-scoped `searchJiraIssuesUsingJql`, across all statuses. Escape JQL values and exhaust continuation tokens. Read plausible matches with `getJiraIssue`; tokenized search results alone do not establish a match. Use narrow semantic terms when needed and safe for the confirmed audience.

Apply the main skill's matching rules and outcomes. An unreadable plausible match or conflicting evidence blocks the decision. A matching issue need not have identical wording or newly added bindings to be reused.

## Writes and receipts

Call `createJiraIssue` or `editJiraIssue` once with the approved payload. A successful create returning a key or id establishes creation and can support an already approved follow-up edit, subject to the main skill's pause and refresh rules.

When possible, use `getJiraIssue` to check destination and changed fields. Allow formatting changes that preserve description meaning, structure, and links. Keep the returned identity if readback fails; report the read failure separately from the accepted write. Reconcile uncertain mutations through binding searches or an exact read before considering a retry.

Use a returned URL or construct the browse URL from the pinned site and a returned issue key. If only an id is known, report it without inventing a key or URL.

Tracking does not add comments, transition issues, attach files, manage watchers, create projects or users, or change settings.
