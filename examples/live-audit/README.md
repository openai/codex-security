# Live CEF audit event review

Run from the repository root with a CLI built from these PRs. These synthetic CEF
records describe no particular customer's sources or export format. Stream native
CEF directly, with no collector or schema conversion:

```sh
codex-security review-events --live -c examples/live-audit/monitor.yaml < examples/live-audit/events.cef
```

For an existing append-only CEF file on Unix:

```sh
tail -n 0 -F events.cef | codex-security review-events --live --batch-size 10 --max-wait-seconds 300
```

CEF 0 and 1 records may include syslog prefixes. Each physical line is one input;
CEF extension newlines remain escaped. LF and CRLF transports are accepted. Output
always uses JSONL. JSONL is transport, separate from the CEF event format.

The static `batches.jsonl` example adds explicit grouping and historical context:

```sh
codex-security review-events --live -c examples/live-audit/monitor.yaml < examples/live-audit/batches.jsonl
```

Each JSON envelope contains unchanged CEF strings in `events` and `contextEvents`.
With the configured two-line windows, the administrative grant in the second window
can cite the session start supplied as history from the first. The monitor does not
retain earlier windows automatically. No collector is included; the caller owns
collection, durable history, checkpoints, and delivery to a pager.

Raw CEF uses source `cef` and group `events`. Use the envelope for feed names and
related-event grouping. The monitor deduplicates byte-identical records by their
content-derived citation ID and promotes new evidence over identical context. The
CEF header event class ID is not used as an occurrence ID. Changed content, spacing,
or prefixes change the citation; see [citation semantics](../audit-events/README.md).

A JSON string, array of CEF strings, or version 1 batch can also occupy an input line.
Existing native JSON formats remain compatible. Batch size counts input lines, not
the events within a JSON array or envelope. Source/context changes and EOF flush a
window, as do the configured count and elapsed-time thresholds. `firstLine` and
`lastLine` identify the inclusive input range to checkpoint after saving the result.

Direct review uses the configured Codex authentication. Decisions screening remains
opt-in and requires `OPENAI_API_KEY`. A ChatGPT login alone does not authenticate
Decisions. A `page` result is a recommendation; this command does not deliver pages.
