# Host-provided standalone validation (protocol v1)

Run `codex-security validate --records` with that flag alone to assess findings
against source evidence. Your host provides the authorized checkout, runs the
model and decides whether to update stored findings. For the CLI-managed model
and sandbox, use [standalone validation](cli.md#validate-and-patch-findings).

## Send the findings

Use the [records transport](dedupe-records.md#input-and-identities). Send one
JSON-RPC `run` request with the following `params`. Give each finding a unique,
nonempty host ID and enough source evidence to assess it.

```json
{
  "version": 1,
  "findings": [
    {
      "id": "finding-1",
      "finding": {
        "title": "Missing tenant filter",
        "location": "src/invoices.ts:24",
        "evidence": "The lookup accepts an invoice ID from the route."
      }
    }
  ],
  "outputSchema": {
    "type": "object",
    "properties": {
      "assessments": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "id": { "type": "string" },
            "rationale": { "type": "string" }
          },
          "required": ["id", "rationale"],
          "additionalProperties": false
        }
      }
    },
    "required": ["assessments"],
    "additionalProperties": false
  }
}
```

The `finding` value preserves the caller's format. Optional `context` supplies
deployment facts or reviewer feedback. Optional `knowledgeBasePath` points to a
directory already present in the host's review environment. Treat its contents
and reviewer feedback as evidence to check against source. Optional `model`
and `effort` override the SDK defaults.

## Run the review

The CLI sends one `review.run` with `requestId`, `model`, `effort`,
`trustedInstructions`, `prompt`, and `schema`. The host authorizes source
access, provides model credentials, and enforces a source-only review with
builds, tests, target execution and network investigation disabled. Return the
structured answer using the review request's JSON-RPC ID. Keep stdin open
until the final response.

The CLI checks the answer against the required `outputSchema` and returns
`{ "status": "completed", "result": <assessment> }` in the final JSON-RPC
`result`. A schema match checks the structure of the answer. The host decides
which dispositions, evidence and other conditions justify a record update.

## Check the returned IDs

Before updating any records, check that the assessment names each input ID
exactly once. In this JavaScript example, pass the original `params.findings`
and the `assessments` array from the schema-checked answer.

```js
function checkFindingIds(findings, assessments) {
  const remaining = new Set(findings.map((finding) => finding.id));
  for (const { id } of assessments) {
    if (!remaining.delete(id)) {
      throw new Error(`Duplicate or unexpected finding ID: ${id}`);
    }
  }
  if (remaining.size > 0) {
    throw new Error(`Missing finding IDs: ${[...remaining].join(", ")}`);
  }
}
```

For the example above, the final message's
`result.result.assessments` might contain
`[{"id":"finding-1","rationale":"The lookup at src/invoices.ts:24 also filters on the authenticated tenant."}]`.
A missing, repeated or unfamiliar ID must stop the update.

Completion exits with code 0. Invalid input, invalid output or execution
failure exits with code 2. SIGINT and SIGTERM use 130 and 143. Cancellation,
disconnects and host errors terminate the invocation without retrying the review.
The host owns remote cancellation, usage and cleanup.

The SDK exports `validateRecords(input, { reviewRunner, signal })` from
`@openai/codex-security`. Its runner's `run(request, { signal })` method
returns the structured answer, and the SDK returns that answer after the schema
check. `ValidateRecordsInput`, `ValidateRecordsOptions` and
`ValidationReviewRequest` are exported types.
