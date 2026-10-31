# Review CEF audit events

These synthetic CEF records demonstrate an audit-event review; they do not describe
any customer's logging system. Run from this directory with a CLI built from these PRs:

```sh
codex-security review-events --json < events.cef
codex-security review-events --json < batch.json
codex-security review-events --screen-with-decisions --json < events.cef
```

`events.cef` contains native CEF records, one per line. `batch.json` demonstrates the
optional grouping/history envelope: `events` and `contextEvents` contain the same
unchanged CEF strings. No collector or conversion to a proprietary event schema is
needed. Collection, durable history, checkpoints, and paging belong to the caller.

CEF 0 and 1 headers are supported, with or without a syslog prefix. Header framing
and severity are checked; extension values are retained verbatim, including spaces,
pipes, escaped equals signs, backslashes, and escaped newlines. This is not a complete
CEF conformance validator or a syslog receiver. Physical newlines delimit records.

The header's event class ID names an event type, not an occurrence. Citation IDs use
`sha256:` followed by the SHA-256 of each complete UTF-8 record, including its optional
syslog prefix and original escaping, excluding the transport line terminator. The
model receives parallel `eventReferences` arrays; the records are not modified.
Identical records share an ID; changing content, spacing, or prefixes changes it.
Reuse the exact earlier record for historical citations. Each group must have unique
IDs across its new and historical records.

Raw records use source `cef` and group `events`. Use the optional JSON envelope to
name a feed, group related events, describe service behavior, and supply prior evidence.
The SDK accepts one CEF string, an array of CEF strings, or an envelope through
`reviewSecurityEvents()`; `securityEventInputSchema` validates those inputs.

Direct review uses the configured Codex authentication. Decisions screening is opt-in
and needs `OPENAI_API_KEY`; its confidence cutoff defaults to 0.95. A `page` result is
a recommendation, not a delivered page. These examples do not measure detection quality.

JSONL is a transport format, separate from CEF. The one-shot command expects one
JSON value; native CEF files use one record per line.
Existing CloudTrail, OCSF, and legacy custom JSON inputs remain compatible.

Reference: [ArcSight CEF implementation standard](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm).
