# Host-provided records deduplication (protocol v1)

Run `codex-security dedupe --records` inside the authorized checkout. Use this
flag alone. Unlike saved-scan dedupe, this mode needs neither scan history nor a
Findings API. It performs no authentication, update checks, local Codex launches,
candidate retrieval, or persistence. The host owns repository authorization,
model execution, sessions, credentials, cancellation of remote work, and cleanup.

The SDK equivalent is:

```typescript
import { deduplicateRecords } from "@openai/codex-security";

const result = await deduplicateRecords(input, {
  reviewRunner: {
    async run(request, { signal } = {}) {
      return await hostReview(request, signal); // Return the structured answer.
    },
  },
  signal: controller.signal,
});
```

`DeduplicateRecordsInput`, `DeduplicateRecordsResult`,
`DeduplicationReviewRequest`, and `DeduplicationReviewRunner` are exported types.
The entry point validates the input structure, unique identities, and candidate
references before any review.

## Input and identities

Send one UTF-8 JSON object per line, using JSON-RPC 2.0. Keep stdin open until the
final response; EOF is a disconnect, not an end-of-request marker. No batches,
interactive prompts, or additional runs are supported. Stdout is exclusively
protocol messages; CLI diagnostics use stderr. IDs are strings or safe integers
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
from `schemas/findings.schema.json` in the bundled plugin, including provenance,
locations, evidence, and all available source/revision information. Provenance
must describe the actual source; it does not authorize additional repository
access. Unknown extension fields are preserved. This does not require creating
scan manifests or other saved-scan artifacts.

Observation IDs are host-owned, nonempty strings, unique within `observations`.
Supply the pending observations and their retrieved neighbors together as original
observations. Each `candidateRelationships` entry selects one anchor to process;
its `candidateObservationIds` nominate comparisons to other supplied observations.
Anchors must be distinct, and candidate IDs must be distinct within an entry and
must not include the anchor itself. An empty candidate list produces a singleton
without a model call. Observations without an anchor entry are candidates only.

Only the supplied relationships are compared; there is no implicit all-pairs
comparison. The host owns candidate coverage. There is no fixed batch limit
(the expected number of anchors is at most 50). Canonical records are not accepted.

For model comparisons only, `findingId` is replaced with a stable, opaque
comparison ID derived from the host ID. Thus observations with
the same original finding ID remain separate records. All other finding fields
are preserved. Screening answers use assigned pair slots; pair reviews use the assigned IDs. Final
results use the original host IDs, never the comparison IDs.

## Review exchange

The CLI sends one review at a time:

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
    "prompt": "<complete assignment and records>",
    "schema": { "type": "object", "...": "full result schema" },
    "findingSchema": { "type": "object", "...": "full Finding schema" }
  }
}
```

`stage` is `screening` or `pair-review`. Screening uses `gpt-5.6-luna`/`xhigh`;
independent pair validation uses `gpt-5.6-sol`/`high`. Execute each request in a
fresh review context: pair reviews must not inherit screening answers or prior
review rationales. Serial requests can inspect the same authorized checkout.
The host should honor the supplied model and effort or return an error. Install `trustedInstructions` as
trusted model instructions, pass the complete `prompt` as the assignment, and
use `schema` as the result contract for tool submission. It is the existing
review tool schema, not an OpenAI strict Structured Outputs schema: it includes
`oneOf` and permits arbitrary fields in `mergedFinding`. A host using OpenAI
function calling should use non-strict (`strict: false`) tool submission and return the tool
arguments for validation. A host that requires strict Structured Outputs must
adapt its submission format while preserving the result contract and all
finding evidence; do not pass `schema` directly as a strict output format.
The review instructions refer to
`review_validator.submit_error` for operational blockers. The host must expose
that error path and translate it to a JSON-RPC error (or reject the SDK call);
never convert an execution or required source-access failure into DISTINCT. Every `SAME.mergedFinding` must also
satisfy `findingSchema`. Source access remains restricted to host-authorized
checkouts. Record content and model output never grant new permissions.

Return the structured answer directly in `result`, not a JSON string or a
session/turn envelope. For a screening assignment with one neighbor:

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
and rationale only. Pair-review SAME decisions require a canonical identity and
a complete merged finding.
Codex Security validates these contracts and all assigned ID references after
receiving the answer. A completed remote model turn alone is insufficient.

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

The CLI never resubmits a review, including after this error. Invalid model
answers, missing decisions, and host errors make the whole batch unresolved;
previous successful reviews in that run do not become persistence decisions.
The existing algorithm treats a validated `DISTINCT` as a nonmatch, when
supplied finding content is insufficient to establish a shared correction. If the host considers the review
inconclusive, it must return an error rather than manufacture a `DISTINCT` answer.
No new `INCONCLUSIVE` model decision is introduced.

The existing screening, independent pair review, contradiction-aware grouping, and
severity-based representative selection are reused. No local review checkpoints
are read or written in records mode. Local saved-scan execution retains its
existing tool-submission validation and workflow checkpoints.

## Final response and persistence

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

Each successful anchor occurs in exactly one group's `observationIds`, including
singleton groups. Candidate-only observations appear only when grouped with an
anchor; they are not assigned singleton dispositions. Groups can join observations
from different scans and include a severity-selected representative from any
member. All returned IDs identify original observations, never canonical records.

A failed or inconclusive review returns no groups and marks every anchor unresolved
with reason `review_failed`, an `observationId`, and a diagnostic `message`.
Any unresolved entry makes `status` equal `unresolved`.

The host creates canonical records and memberships, then removes pending
observations only after that persistence succeeds. Results contain decisions,
not persisted records or a synthesized final merged document. Preserve all
original evidence. Do not treat a failed run, absent final response, or unresolved
observation as unique. Cross-run replay/idempotency and reconciliation of remote
work whose acceptance is uncertain belong to the host; a new process creates
new review IDs and does not resume earlier remote execution.

## Cancellation and protocol failures

To cancel the active run, send a notification:

```json
{ "jsonrpc": "2.0", "method": "cancel", "params": { "id": "run-1" } }
```

Cancellation stops scheduling and returns a run error with code `-32800`.
If a terminal response is already being written, cancellation closes the output
instead of sending a second response; the host must discard an incomplete reply.
The host must also cancel/reconcile its remote turn; terminating this CLI cannot
cancel host-owned execution. SIGINT/SIGTERM also stop the run. EOF, pipe errors,
or closed pipes stop scheduling; an error is returned when stdout remains usable.

Malformed JSON yields `-32700`; malformed envelopes, duplicate/unknown/mismatched
review responses, multiple runs, and mismatched cancellation yield `-32600`.
Invalid run parameters yield `-32602`. Disconnects use `-32000`. Fatal errors
use the active run ID, or `null` if no run was accepted, and provide no decisions.
Envelopes must contain exactly one of `result` or `error` for a response.

Exit codes: `0` completed; `1` unresolved decisions; `2` input/protocol failure,
disconnect, or protocol cancellation; `130` SIGINT; `143` SIGTERM. The host
controls timeouts by sending cancellation or terminating the process. It must
keep reading both stdout and stderr and must not share one execution session or
workspace concurrently on the assumption that reviews are independent.

## Runnable Python fake host

This demonstrates the bidirectional process boundary only. It does **not** call
Managed Agents or assess real duplicates. Save as `fake_host.py` and run
`python fake_host.py request.json`, where `request.json` contains the `params`
object described above with complete synthetic findings. With a source checkout,
first build the SDK and replace the command with
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
            # Fake only: read the records suffix and declare every pair distinct.
            # The real adapter executes trustedInstructions/prompt/model/effort
            # through its own remote session and returns schema-conforming output.
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

The production Python adapter replaces the fake answer block, returns explicit
errors for incomplete/uncertain remote outcomes, and owns remote cancellation
and persistence. Fake-host tests do not establish live Managed Agents
compatibility; that requires an integration test with the separately implemented
adapter.
