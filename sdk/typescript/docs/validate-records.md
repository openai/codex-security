# Host-provided standalone validation (protocol v1)

Run `codex-security validate --records` with that flag alone. It uses the
standalone validation instructions to assess existing findings against source
evidence. The host runs the model; the CLI does not start Codex, authenticate,
read scan history, or save results. Existing `validate` commands are unchanged.

Use the same JSON-RPC transport as [records deduplication](dedupe-records.md):
one JSON object per line, one `run` request, and `review.run` requests answered
by the host. Keep stdin open until the final response. Cancellation, disconnects,
and host errors terminate the invocation without retrying the review.

The `run` request's `params` has this shape:

```json
{
  "version": 1,
  "findings": [
    {
      "id": "finding-1",
      "finding": { "title": "Example candidate", "evidence": "..." }
    }
  ],
  "context": "Optional deployment facts or reviewer feedback.",
  "knowledgeBasePath": "/validation/context",
  "outputSchema": {
    "type": "object",
    "properties": { "rationale": { "type": "string" } },
    "required": ["rationale"],
    "additionalProperties": false
  }
}
```

Provide at least one finding with a unique, nonempty host ID. The `finding`
value preserves the caller's candidate format. Supply enough source locations
and evidence to assess it. `context` and `knowledgeBasePath` are optional.
The directory must already exist in the host's review environment; this mode
does not copy files. Context and notes are evidence to check against source,
not instructions or automatic dismissal rules.

`outputSchema` is required. It controls the returned structured answer; it does
not define a standard disposition or product status model. The host must verify
finding ID coverage and any application-specific conditions before changing
published findings. Optional `model` and `effort` override the SDK's default
model configuration. Local configuration files and CLI model flags are not read.

The CLI emits one `review.run` request containing `requestId`, `model`, `effort`,
`trustedInstructions`, `prompt`, and `schema`. The host supplies the authorized
source checkout and context directory, executes the review, and returns its
structured answer. The CLI checks that answer against `outputSchema` before
returning `{ "status": "completed", "result": <assessment> }` as the final
JSON-RPC `result`. Success exits with code 0; invalid input, invalid output, or
execution failure exits with code 2. SIGINT and SIGTERM
retain exit codes 130 and 143.

The host owns repository authorization, credentials, model accounting,
cancellation of remote work, and cleanup. It selects and enforces the review
environment's isolation and permissions.
The review instructions require source-only assessment: no builds, tests, PoCs,
target execution, or network investigation. This mode does not configure a local
Codex sandbox; regular `validate` retains its existing read-only sandbox. A
protocol success only proves that the answer matched the schema; it does not
establish assessment quality.

The SDK equivalent is `validateRecords(input, { reviewRunner, signal })`, exported
from `@openai/codex-security`. The runner's `run(request, { signal })` method returns
the structured answer. `ValidateRecordsInput`, `ValidateRecordsOptions`, and
`ValidationReviewRequest` are exported types.
