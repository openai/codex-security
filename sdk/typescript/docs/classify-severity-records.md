# Classify canonical records with host-provided execution

`codex-security classify-severity --records` accepts canonical reports without a
repository, saved scan, synthetic provenance, local Codex login, or filesystem
state. It uses the same bidirectional JSON-RPC transport as [record deduplication](dedupe-records.md).
Use `--records` alone or with `--runs N`; model execution remains host-provided.

The SDK exports `classifySeverityRecords`, `classifySeverityRecordsInputSchema`,
and their input, result, and review-request types. The protocol and input have
version `1`. Before using the protocol, confirm that your installed CLI lists
`--records` in `classify-severity --help`.

## Immutable inputs

Send one newline-delimited JSON-RPC request with `method: "run"` and these params:

```ts
{
  version: 1,
  rubric: { revision: 4, markdown: rubricMarkdown, sha256: rubricSha256 },
  model: "your-authorized-model",
  effort: "high",
  records: [{ id: "canonical-one", revision: 7, findingJson, inputSha256 }]
}
```

The `rubric` field is optional. Omitting it uses the
[bundled severity rubric](https://github.com/openai/codex-security/blob/main/plugins/codex-security/references/default-severity-rubric.md)
at revision `1`, without fetching rubric configuration by default. To opt in to the shared
Statsig default, set `CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC=1` in the CLI
environment or SDK options' `environment`. Unset it or use `0` to disable fetching;
only the exact value `1` enables it. The opted-in request sends no account
credentials or report data and has a three-second timeout; missing, invalid, or
unavailable configuration uses the bundled rubric. Independent host reviews and
usage accounting are unchanged. The policy is resolved once before the first review. The result
echoes the selected revision and exact Markdown SHA-256. Supplying a custom rubric
replaces the default completely and preserves the supplied revision/hash binding.
Do not reuse cached results across differing rubric hashes; preserve the default
snapshot from the review prompt alongside its returned binding. Default revisions
are independent of workspace rubric revisions.

`findingJson` is the exact JSON text of an object with nonblank `findingId`,
`title`, and `summary`. `findingId` must equal the canonical `id`. Optional
`severity.level` uses `critical`, `high`, `medium`, `low`, or `informational`.
Other report fields are preserved as evidence. Missing legacy titles or summaries
must be resolved by the caller; do not invent evidence or scan metadata.

Both hashes are lowercase SHA-256 hex of the exact UTF-8 string bytes, without
normalizing newlines, whitespace, Unicode, object key order, or JSON numbers.
Compute `inputSha256` from `findingJson`, not from its parsed/reserialized object.
For example, Node uses `createHash("sha256").update(text, "utf8").digest("hex")`;
Python uses `hashlib.sha256(text.encode("utf-8")).hexdigest()`.
The CLI recomputes supplied hashes before requesting any review. Rubric revisions are
positive safe integers; record revisions are nonnegative safe integers. Duplicate
canonical IDs and invalid records reject the entire input before host work.
The implementation snapshots caller input before awaiting model execution and
preserves the validated report JSON text verbatim in the model prompt, including
numeric evidence that JavaScript cannot represent exactly.

## Host execution contract

The `classificationRuns` SDK option or CLI `--runs N` flag accepts
an integer from 1 through 10 (default: 3), validated before any host work.
For each record the CLI emits that many sequential `method: "review.run"` requests,
each with a unique request ID and params containing `requestId`, `stage: "severity-classification"`, explicit
`model` and `effort`, `trustedInstructions`, untrusted report/rubric `prompt`, and
an output JSON `schema`. The host must authorize the requested model and effort,
create a fresh independent review context, preserve the instruction/data boundary,
and disable tools, repository access, browsing, and source inspection.
A managed-agent host can execute this request directly in its existing session
infrastructure; it does not need a repository checkout. The CLI does not provide
credentials, create sessions, or select an authentication fallback.

Reply with the same JSON-RPC ID and `result` set to the schema-conforming assessment
object. Do not wrap the assessment in a string or an array. An assessment contains
`findingId`, `decision` (`assessed` or `excluded`), normalized `level`, original
`rubricLabel`, `rationale`, separate `confidence`, and nullable `reviewTrigger`.
Excluded assessments require null level and label; assessed ones require both.

The reviews receive identical inputs and do not see earlier answers. The
most common normalized severity wins; the highest among tied top counts wins
(`critical` > `high` > `medium` > `low` > `informational`). Exclusion is a separate
vote: exclusions can win by count, but lose ties to assessed severities. The first answer matching the winner supplies all assessment fields.

The host owns model budgets, usage accounting, transport limits, timeouts, and
session cancellation. Account for every review request, including work preceding
a later failure; classification results do not aggregate or report token usage.
Use the transport's `cancel` notification with the active run ID and also stop
any remote execution. EOF or a broken pipe means disconnection, not successful
completion. No review is retried automatically, including after an ambiguous
host execution error.

## Results and persistence

A completed result contains `version: 1`, `status: "completed"`, the rubric's
`revision` and `sha256`, `classificationRuns`, and `assessments`. Each assessment replaces model-provided
`findingId` with the verified canonical `id`, `revision`, and `inputSha256`.
The original report and severity are never rewritten.

Invalid or mismatched model output and host failures return `status: "unresolved"`,
an empty `assessments` array, and an error with `recordId` and stable code
`invalid_assessment` or `review_failed`. All requested reviews must succeed; partial
votes and earlier assessments in that invocation are discarded. Invalid input,
protocol errors, and cancellation use JSON-RPC error responses. Exit codes are 0 for completion, 1 for unresolved review, and 2 for
input/protocol failure (130/143 for SIGINT/SIGTERM).

Prefer one canonical record per workflow invocation when the host needs independent
retries and partial success. The host should retain immutable rubric/report
snapshots, compare every echoed binding including `classificationRuns`, and conditionally persist only computed
prioritization fields if the expected canonical version and rubric still apply.
Keep manual edits and original severity intact. Repeating the same inputs binds
results to the same hashes; it does not promise deterministic model answers.
