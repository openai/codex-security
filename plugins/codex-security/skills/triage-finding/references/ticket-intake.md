# Jira and Linear ticket intake

Retrieve the requested content before normalization. Do not infer inaccessible ticket content from an identifier, title fragment, or repository code.

## Retrieval

Use the native [Atlassian](app://asdk_app_6a83901dde988191b3f3cefdcc19acfa) app for Jira. Resolve identity and site with `atlassianUserInfo` and `getAccessibleAtlassianResources`; keep that connection and site for the selected set. Ask when the source is ambiguous.

Use live schemas: `getJiraIssue` for exact issues and `searchJiraIssuesUsingJql` for collections. Exhaust returned pages. Discover deferred metadata through `discover` and `executeRead`; intake does not invoke write tools.

Use natural-language search to discover a site, project, issue family, or first key from a vague request, then use JQL or exact fetches. Order collection queries by a stable field and preserve the JQL as provenance. Jira text search tokenizes punctuation: if an exact marker gives no results, search a stable token and filter returned summaries for the exact family.

For Linear, fetch exact URLs or identifiers directly. Search team, project, or phrase requests to resolve the intended issue set, then fetch every selected issue before normalization.

## Linear parents and sub-issues

Fetch the supplied parent. When the request includes its sub-issues or a finding collection organized under it, list the relevant descendants with the parent filter, exhausting pagination.

Honor the requested collection scope across depths. If it is unclear whether descendants are included, show the available set and clarify once rather than asking at every level. Fetch each selected issue's full content before triage.

Include the parent when it has an independent vulnerability claim. Use an organizing summary as context rather than inventing a separate finding. Ask only if an ambiguous claim would change the selected set.

Keep one result per selected issue in deterministic breadth-first tree order: parent first when selected, then each selected depth by creation time with identifier as tiebreaker. Preserve parent relationships in references. Do not truncate or drop selected findings.

## Retrieval failures

- Missing connector or authentication: state which source is unavailable and ask to connect or reauthorize it.
- Insufficient permission: report the access error and ask the user to request access or choose an account with access.
- Not found or inaccessible: ask to verify the identifier and workspace. Do not claim the issue does not exist when it may be hidden.
- Transient failure: retry when likely to help, keeping the same source and scope. Report unresolved errors.

Offer to continue with complete finding content pasted by the user. Do not infer an inaccessible ticket's claim or assign it a verdict. For collections, continue with findings that were retrieved and report the inaccessible items separately. If no finding content was retrieved or supplied, stop before repository inspection or emitting `triage-finding/v0`.

## Normalization and result

Normalize Jira and Linear vulnerability tickets as `source_type: "scanner_ticket"` unless the body represents `bug_bounty`, `advisory`, `cve`, or `codex_security_finding`.

Preserve available issue key or identifier, URL, project, status, labels, components, priority, assignee, reporter, timestamps, issue type, and import query in `input_id`, `normalized_input.references`, and evidence or proof-gap text.

Default to read-only import and triage. Do not add comments, transition or close issues, assign owners, or change labels without an explicit writeback request. Finish static verdicts before reviewing writeback.

For collections, report the imported count, query or selected set, where the full result was rendered or saved, and whether Jira or Linear changed.
