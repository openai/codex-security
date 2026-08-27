# Evidence and repeatable snapshots

## Gather evidence through actual read-only capabilities

Inspect the installed connector schemas and returned pagination contracts before use. For Linear, a list tool may accept one priority/team per query; preserve all caller filters through every cursor and combine results by canonical ID. Read issue details, relationships and every comment page. Inspect both transport errors and structured error fields; a page limit is not proof of completeness.

Search the caller's authorized repositories for exact ticket identifiers and distinctive affected-source terms. Inspect actual PR bodies/diffs and replacement stacks. Do not assume a private organization, repository or fixed tool signature. Record query scope, unsuccessful reads and source limitations without disclosing credentials. Back off on rate limits.

The connector may distinguish a stable provider ID from a readable ticket key, or expose them under unexpected field names. Establish that contract; never synthesize an ID or treat a display key as canonical without evidence. Preserve reported, proposed, attempted and confirmed remediation separately. A search hit, assignee or merged PR alone is not a verified fix.

## Normalize a snapshot

The bundled helper reads **schema version 3**. Normalize source values explicitly; this is not a raw tracker-response parser. Its priority scale is Linear's `0..4`. For another tracker, provide a reviewed mapping that preserves the requested selection and retain the original values/mapping in the scope, or use the review workflow without this optional helper. Never silently reinterpret the source priority scale.

Version 3 requires an independent routing-gap assessment, dated supporting evidence and a named pending step for `pending_validation`; its delta field is `assignee_changes`, not `owner_changes`. Older snapshots are rejected. Recheck their source evidence and normalize them to version 3 before comparison; do not merely change the version number, invent missing observations or overwrite a previous complete baseline with an incomplete migration.

- `checked_at`: ISO-8601 timestamp with timezone for the final reconciled cutoff.
- `scope`: a stable nonblank key, exact selected numeric `priorities`, boolean `assigned_only`, and boolean `include_archived`. Also retain the actual source/view, teams/projects, other filters, subissue rules and any policy version affecting the comparison. Equality covers the whole supplied object. The helper cannot discover missing scope details or infer a view's contents.
- `coverage`: `inventory`, `details`, `comments`, `remediation`, each marked `complete` only after the relevant reads/checks and final inventory refresh actually succeeded. Otherwise preserve the incomplete value and gap.
- `issues`: all selected-priority inventory rows necessary for the requested counts, including terminal/unassigned rows. Keep exact unique canonical `id`; retain a readable ticket key and links separately when useful. Out-of-scope rows need no engagement classification, but their exclusion must be established, not inferred from missing state.

For each row, use an exact integer priority `0..4` (the helper also accepts a normalized `{ "value": 1 }` wrapper). Booleans and floating-point values are not priorities. Supply `archived_at` explicitly: `null` means known unarchived; otherwise use the known timezone-bearing archive timestamp. Supply `status_type` as `backlog`, `unstarted`, `started`, `triage`, `completed` or `canceled`. Map actual workflow meanings, including authoritative duplicates, to these types from evidence; never classify a terminal state from an arbitrary title alone.

Use `assignee: null` only for verified unassigned state; an assigned row uses the stable nonblank assignee ID, with an optional separate display name. Missing/invalid priority, archive, workflow or assignment state remains unresolved and prevents a complete baseline; it must not become a confident unfinished/unassigned count.

Every eligible row needs one supported engagement classification, a nonblank reason, complete `details`/`comments`/`remediation` checks and nonempty evidence. This applies to **positive classifications as well as follow-up candidates**. Missing support becomes `unverified`.

- `routing_gap`: a required boolean assessed separately from engagement. A verified unassigned row or a `routing_gap` classification requires `true`; an assigned `active` row can also have `true` when ownership or handoff remains unresolved. Use `false` only with supporting review evidence. A missing, unknown or contradictory value makes the classification `unverified`.
- Each evidence record requires `url`, `at` and `summary`: an absolute HTTP(S) source link without embedded credentials, or an absolute `file:///` URL for an authorized local export; an ISO-8601 observation timestamp with timezone; and a nonblank supporting fact. The observation must be no later than `checked_at`. The helper checks link shape only, without accessing the source. This neither authenticates evidence nor authorizes fetching a link.
- `event_at`, when known and supplied, must be a timezone-bearing timestamp no later than that record's observation time. `last_substantive_activity_at` may be absent or null when unknown; when supplied, it must be a timezone-bearing timestamp no later than `checked_at`. Do not substitute an ETA or a future commitment date for an observed event.
- `pending_step` is required for `pending_validation`: `patch_review`, `merge`, `patch_verification`, `deployment`, `mitigation_execution` or `deployed_retest`. Name the next required step and explain any additional pending work in the reason. A named step is not proof that preceding steps succeeded.

Invalid links, missing supporting facts, invalid/future observation or activity times, or a missing/unknown required pending step leave the classification `unverified`. Avoid raw sensitive payloads.

This fictional shape illustrates the contract, not evidence of a real completed review:

```json
{
  "schema_version": 3,
  "checked_at": "2026-01-10T12:00:00Z",
  "scope": {
    "key": "selected-urgent-findings",
    "source_url": "https://tracker.example/views/urgent",
    "teams": ["security-team-id"],
    "projects": [],
    "priorities": [1],
    "assigned_only": false,
    "include_archived": false,
    "other_filters": {},
    "include_subissues": true,
    "policy_revision": "reviewed-policy-v1"
  },
  "coverage": {
    "inventory": "complete",
    "details": "complete",
    "comments": "complete",
    "remediation": "complete"
  },
  "issues": [{
    "id": "provider-stable-id-1",
    "identifier": "SEC-1",
    "title": "Fictional finding",
    "url": "https://tracker.example/issues/SEC-1",
    "priority": 1,
    "archived_at": null,
    "status": "Backlog",
    "status_type": "backlog",
    "assignee": null,
    "active_responder": null,
    "area_dri": null,
    "classification": "routing_gap",
    "routing_gap": true,
    "reason": "The supplied fictional record confirms no current assignee or accepted handoff.",
    "last_substantive_activity_at": null,
    "checks": {
      "details": "complete",
      "comments": "complete",
      "remediation": "complete"
    },
    "evidence": [{
      "kind": "tracker",
      "url": "https://tracker.example/issues/SEC-1",
      "at": "2026-01-10T12:00:00Z",
      "summary": "Fictional complete issue/comment/remediation review."
    }]
  }]
}
```

## Inspect or compare offline

Use Python 3.9 or later (standard library only) and this bundled helper from the skill directory:

```bash
python3 scripts/reconcile.py /authorized/private/path/current.json
python3 scripts/reconcile.py /authorized/private/path/current.json --previous /authorized/private/path/previous-complete.json
python3 scripts/reconcile.py --self-test
```

The helper has no network calls and does not write snapshots. It validates declared structure/support, reports counts and follow-up IDs, and compares matching-scope snapshots. `routing_gap_ids` lists supported routing gaps independently of the engagement classification; `follow_up_ids` is the union of those IDs and supported follow-up classifications, counted once per issue. `assignee_changes` records assignee-ID changes only, not accepted responsibility or a verified change of fixing team. `routing_gap_changes` records supported changes to the separate routing assessment. Counts with unresolved rows are known partial counts. It does not choose a severity rubric, classify real engagement, verify external source facts or establish that every source was searched.

`baseline_eligible: true` means the supplied snapshot passes those structural/support gates. Advance the saved baseline **only after** the reviewer also verifies source completeness, supported judgments and the final live refresh. Never replace a previous complete baseline with a partial result or infer that the helper authenticated evidence. A changed full scope or an incomplete previous baseline is not comparable; an older current cutoff is rejected.

An incomplete current refresh must preserve uncertainty about missing or unresolved previous rows. Do not translate absence into pickup, completion, reprioritization or remediation. Even a complete `left_scope` result describes population movement only; consult the refreshed issue evidence to explain why it moved. `delta_is_complete: false` means no complete-delta claim is allowed.

`left_follow_up` is not a pickup metric: an already-active issue may leave follow-up because its routing gap was resolved. Consult the separate classification, routing and assignee changes and their source evidence before describing the outcome. No helper count or delta establishes deployment or a separate retest of the deployed fix.

Keep authorized snapshots/reports in a task-owned restricted directory. Do not package live inventories, security evidence or prior snapshots with the reusable skill. The embedded self-tests use fictional in-memory records only.
