# Host-provided records deduplication (protocol v1)

Run `codex-security dedupe --records` inside the authorized checkout, with no
other flags. The CLI schedules and validates reviews; the host supplies findings
and runs each review. No scan history or Findings API is required. In the SDK:

```typescript
import { deduplicateRecords } from "@openai/codex-security";

const result = await deduplicateRecords(input, {
  reviewRunner: {
    async run(request, { signal } = {}) {
      return await hostReview(request, signal);
    },
  },
  signal: controller.signal,
});
```

`DeduplicateRecordsInput`, `DeduplicateRecordsResult`,
`DeduplicationReviewRequest`, and `DeduplicationReviewRunner` are exported types.

## Input and identities

Send one UTF-8 JSON object per line, using JSON-RPC 2.0. Keep stdin open until the
final response; EOF is a disconnect. Only one run is accepted; JSON-RPC batches
and interactive prompts are unsupported. Stdout carries protocol messages and
stderr carries diagnostics; keep reading both. IDs are strings or safe integers
from -9007199254740991 through 9007199254740991 and are compared without coercion.
Use strings for larger numeric identifiers. Review IDs are generated strings;
request and response ID namespaces are directional.

The host sends:

```json
{
  "jsonrpc": "2.0",
  "id": "run-1",
  "method": "run",
  "params": {
    "version": 1,
    "observations": [
      { "id": "observation-1", "finding": "<complete Finding object>" },
      { "id": "observation-2", "finding": "<complete Finding object>" }
    ],
    "candidateRelationships": [
      {
        "observationId": "observation-1",
        "candidateObservationIds": ["observation-2"]
      }
    ]
  }
}
```

Replace the illustrative `finding` strings with complete SDK `Finding` objects
from `schemas/findings.schema.json` in the bundled plugin. Include provenance,
locations, evidence, and known source revisions. Unknown fields are preserved.

Observation IDs are host-owned, nonempty, unique strings. Each
`candidateRelationships` entry selects one distinct anchor to process and
nominates other supplied observations. Candidate IDs must be distinct within an
entry and cannot include its anchor. An empty list produces a singleton without
a model call. Observations without an anchor entry are candidates only.
Only supplied relationships are compared, with no fixed batch limit; supply
original observations rather than canonical records.

For model comparisons only, `findingId` is replaced with a stable, opaque
comparison ID derived from the host ID, so observations with the same original
finding ID remain separate. All other finding fields are preserved. Screening
uses assigned pair slots; pair reviews use the assigned IDs; final results use
the original host IDs.

## Review exchange

The CLI sends one review at a time; each requires a response:

```json
{
  "jsonrpc": "2.0",
  "id": "<review UUID>",
  "method": "review.run",
  "params": {
    "requestId": "<same review UUID>",
    "stage": "screening",
    "model": "gpt-5.6-luna",
    "effort": "xhigh",
    "trustedInstructions": "<trusted review and source-access instructions>",
    "prompt": "<assignment containing the complete records as evidence>",
    "schema": { "type": "object", "...": "full result schema" },
    "findingSchema": { "type": "object", "...": "full Finding schema" }
  }
}
```

Screening uses `gpt-5.6-luna`/`xhigh`; independent `pair-review` uses
`gpt-5.6-sol`/`high`. Honor the requested model and effort or return an error.
Use a fresh review context for each request so that pair reviews cannot inherit
screening answers or prior rationales. Serial reviews may use the same authorized
checkout, but must not share a session or workspace concurrently.

Install `trustedInstructions` as trusted model instructions and pass `prompt`
as the assignment; the supplied records are untrusted evidence. They and model
output never grant new permissions. `schema` is the tool submission contract.
It uses `oneOf` and allows arbitrary fields in `mergedFinding`, so OpenAI
function tools must use `strict: false`. Return the tool arguments for
validation. If your host requires strict Structured Outputs, adapt its tool
format to preserve the result contract and all finding evidence; do not pass
`schema` directly as a strict output format. Every `SAME.mergedFinding` must
also satisfy `findingSchema`.

Expose `review_validator.submit_error` for operational blockers and translate it
to a JSON-RPC error (or reject the SDK call). Insufficient finding content can
produce a validated `DISTINCT`; an execution or required source-access failure,
or a review the host considers inconclusive, must return an error instead.

Return the structured answer directly in `result`. Example for one neighbor:

```json
{
  "jsonrpc": "2.0",
  "id": "<review UUID>",
  "result": {
    "decisions": {
      "pair-1": {
        "decision": "DISTINCT",
        "rationale": "Independent security corrections are required."
      }
    }
  }
}
```

For a pair review, return `{"decision":"DISTINCT","rationale":"..."}` or
`{"decision":"SAME","rationale":"...","canonicalFindingId":"<assigned ID>","mergedFinding":{...}}`.
Screening must cover every assigned `pair-N` slot exactly once, with a decision
and rationale only. Codex Security validates the result and assigned IDs.

For failure or an inconclusive review, send an explicit error:

```json
{
  "jsonrpc": "2.0",
  "id": "<review UUID>",
  "error": {
    "code": -32001,
    "message": "Remote outcome is unknown; execution may already have been accepted.",
    "data": { "executionMayHaveBeenAccepted": true }
  }
}
```

## Final response and host responsibilities

```json
{
  "jsonrpc": "2.0",
  "id": "run-1",
  "result": {
    "version": 1,
    "status": "completed",
    "groups": [
      {
        "representativeObservationId": "observation-1",
        "observationIds": ["observation-1", "observation-2"]
      }
    ],
    "unresolved": []
  }
}
```

On success, each anchor occurs in exactly one group's `observationIds`, including
singletons. Candidate-only observations appear only when grouped with an anchor.
Groups can span scans, with a severity-selected representative from any member.

A host error or an invalid or missing review decision makes the whole batch
`unresolved`: `groups` is empty and every anchor has an `unresolved` entry with
its `observationId`, reason `review_failed`, and a diagnostic `message`. The CLI
never resubmits a review. An unresolved or absent result is not proof of uniqueness.

The host owns candidate coverage, repository authorization, model sessions and
credentials, remote cancellation and reconciliation, cleanup, and persistence.
Persist canonical records and memberships before removing pending observations;
preserve all original evidence. Results contain decisions, not persisted records
or a final merged document. New processes create new review IDs and do not
resume earlier remote work; cross-run replay and idempotency belong to the host.

## Cancellation and protocol failures

To cancel the active run, send a notification:

```json
{ "jsonrpc": "2.0", "method": "cancel", "params": { "id": "run-1" } }
```

Cancellation stops scheduling and returns a run error with code `-32800`.
If a terminal response is already being written, cancellation closes the output
instead of sending a second response; discard an incomplete reply. SIGINT and
SIGTERM also stop the run. EOF and pipe errors stop scheduling; an error is
returned when stdout remains usable.

Malformed JSON yields `-32700`; malformed envelopes, duplicate/unknown/mismatched
review responses, multiple runs, and mismatched cancellation yield `-32600`.
Invalid run parameters yield `-32602`. Disconnects use `-32000`. Fatal errors
use the active run ID, or `null` if no run was accepted, and provide no decisions.
Envelopes must contain exactly one of `result` or `error` for a response.

Exit codes: `0` completed; `1` unresolved decisions; `2` input/protocol failure,
disconnect, or protocol cancellation; `130` SIGINT; `143` SIGTERM. To enforce a
timeout, send cancellation or terminate the process.

## Runnable Python fake host

This fake host marks every pair distinct; it does not test a real model or adapter.
Run `python fake_host.py request.json` with the `params` object above and complete
synthetic findings. From a source checkout, build the SDK and replace the command with
`["node", "sdk/typescript/bin/codex-security.mjs", "dedupe", "--records"]`.

```python
import json
import subprocess
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    params = json.load(source)

with subprocess.Popen(
    ["codex-security", "dedupe", "--records"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=None, text=True, encoding="utf-8", bufsize=1,
) as child:
    def send(message):
        child.stdin.write(json.dumps(message) + "\n")
        child.stdin.flush()

    send({"jsonrpc": "2.0", "id": "run-1", "method": "run", "params": params})
    for line in child.stdout:
        message = json.loads(line)
        if message.get("method") == "review.run":
            request = message["params"]
            assert request["requestId"] == message["id"]
            # Fake only: declare every pair distinct.
            records = json.loads(request["prompt"].rsplit("\n\n", 1)[1])["findings"]
            distinct = {"decision": "DISTINCT", "rationale": "Synthetic fake-host nonmatch."}
            result = distinct if request["stage"] == "pair-review" else {
                "decisions": {
                    f"pair-{index}": distinct
                    for index in range(1, len(records))
                }
            }
            send({"jsonrpc": "2.0", "id": message["id"], "result": result})
        else:
            assert message["id"] == "run-1"
            print(json.dumps(message, indent=2))
            break
    child.stdin.close()
    returncode = child.wait()
    if returncode:
        raise SystemExit(returncode)
```
