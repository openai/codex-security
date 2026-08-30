# Jira and Linear Ticket Intake

Use this reference whenever `$triage-finding` imports Jira or Linear issues. Retrieve the requested ticket content before normalization. Never infer inaccessible ticket content from an identifier, title fragment, or repository code.

## Source Retrieval

For Jira, use the Atlassian Rovo connector when it is available:

- Prefer structured JQL for repeatable imported collections, ordered by a stable field such as key or created date. Use natural-language search only to discover the cloud/site, project, issue family, or first matching key from a vague phrase. After discovery, switch to JQL or exact issue fetches.
- Jira text search tokenizes punctuation. If a hyphenated marker such as `KAN-PROMPTFOO-SYNTH` returns no rows, broaden to a stable token such as `PROMPTFOO`, then filter returned summaries for the exact family before triage.
- Fetch exact issue URLs or keys directly when the connector supports it. For a project family or saved query, use JQL and preserve the JQL string as source provenance.

For Linear, fetch exact issue URLs or identifiers directly. When the user supplies a team, project, or search phrase, use search results only to identify the intended issue set, then fetch every selected issue before normalization.

## Linear Parent and Sub-Issue Selection

For an exact Linear issue, fetch the parent issue first. Then list its direct children with the connector's parent filter. Exhaust all pages of the direct-child listing before deciding whether children exist.

When the parent has direct children:

1. Show the number of direct children and each child's identifier and title. This listing is selection metadata, not imported finding content.
2. Ask whether to include that level before fetching any child's full content.
3. If the user declines, do not fetch or normalize those children.
4. If the user approves, check that the selected finding count remains within the result limit, then fetch the full content of every approved child.
5. List direct children for each approved issue, exhausting pagination and grouping the next-level identifiers and titles by parent. If another level exists, repeat the confirmation at the next depth before fetching its full content.

Do not interpret approval for one level as approval for deeper descendants. If no children exist at a level, continue without another sub-issue question.

Classify the originally supplied parent separately from its children:

- Include the parent as a triage item when its title and body contain a clear independent vulnerability claim.
- Exclude it when it only organizes or summarizes the child findings.
- If the parent mixes collection context with a possible standalone claim and the classification is ambiguous, explain the ambiguity and ask whether to include the parent before normalization.

Preserve one result per selected issue. Use deterministic breadth-first tree order: include the parent first when selected, then each approved depth ordered by creation time with the issue identifier as the tie-breaker. Preserve source identifiers and parent relationships in references.

The `triage-finding/v0` result accepts at most 250 findings. Before fetching full content for an approved level, count the parent when selected plus all previously imported and newly approved issues. If the total would exceed 250, stop and report the count. Ask the user to narrow by depth, status, label, or a smaller parent. Do not truncate the issue set or split it into multiple result payloads automatically.

## Connector Failure Handling

Classify a failed Jira or Linear read before deciding what to do:

- **Missing connector or authentication:** The connector tool is unavailable, the source is not connected, or authentication is missing or expired. Do not retry. State which source could not be accessed and ask the user to connect or reauthorize it. Also offer to continue if the user pastes the complete finding content.
- **Insufficient permission:** The connector is authenticated but reports forbidden, access denied, or an equivalent authorization error. Do not retry. Preserve the connector's safe error detail, ask the user to request access or use an account with access, and offer the paste-the-finding alternative.
- **Issue not found or inaccessible:** An exact identifier or URL returns no matching issue, or the connector cannot distinguish missing from hidden. Do not claim that the issue does not exist. Ask the user to verify the identifier and source workspace or provide the ticket content directly.
- **Transient connector failure:** A timeout, rate limit, temporary service error, or transport failure may recover without a configuration change. Retry the identical read once. Do not broaden the query or switch sources during the retry. If the identical retry fails, stop and report both the original and retry errors when they are safe to show.

After any unresolved retrieval failure, stop the intake workflow. Do not inspect the repository, normalize a finding, assign a verdict, or emit the `triage-finding/v0` contract. Give the recovery step that matches the failure class rather than a generic success-shaped response.

## Normalization and Provenance

Normalize Jira and Linear vulnerability tickets as `source_type: "scanner_ticket"` unless the ticket body clearly represents `bug_bounty`, `advisory`, `cve`, or `codex_security_finding` input.

Preserve the issue key or identifier, URL, project, status, labels, components, priority, assignee, reporter, timestamps, issue type, and import query in `input_id`, `normalized_input.references`, and evidence or proof-gap text.

## Read-Only Default

Default to read-only import and triage. Do not add comments, transition issues, close issues, assign owners, or change labels unless the user explicitly asks for writeback.

When writeback is requested, finish the static verdicts first. Summarize the planned issue mutations and keep mutation separate from evidence analysis.

For imported collections, the final summary must state the number of issues imported, the query or issue set, where the full result was rendered or saved, and whether the source system changed. The default status is: no Jira or Linear changes made.
