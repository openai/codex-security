# Telemetry and measurement

Codex Security keeps model-request attribution, native analytics, local usage
accounting, and host-owned telemetry export separate. It does not configure a new
remote collector.

## Controls and collection

Native `analytics` and `otel` settings keep their Codex semantics. Scan profiles,
project settings, and explicit overrides keep their native precedence. Per-scan
settings are not merged into shared credential configuration. Discovery, reducer,
and resumed workers inherit their scan's settings. Worker runtime snapshots live
under the credential home denied to model tools. OTel exporter configuration can
contain authentication headers, so it is excluded from model-readable preflight
files and saved scan recipes while remaining available to native execution.

For authentication/bootstrap commands and stored-account CLI app-server startup,
automatic inheritance covers analytics consent and request metadata. OTel
exporters come from the selected native home or existing explicit runtime
configuration; ambient/profile exporter settings are not copied when
authentication selects another home. The pinned runtime cannot load a separate
private profile for these helpers without changing authentication/state identity.
The wrapper does not copy inherited exporter headers into arguments or
temporarily rewrite shared settings.

Request metadata includes command, surface, package/plugin versions, configured
provider family, and scan mode when available. Wrapper operations and workers add
opaque operation, attempt, and parent-attempt IDs. IDs are join keys, not metric
labels. Hosted scan execution receives the same attribution in
`request.runtime.requestMetadata`; the executor owns forwarding it to its runtime.
Native analytics opt-out does not remove request attribution or configure an OTel
exporter. Hosted schema and checkout preparation precede the SDK invocation;
rejections at that boundary remain the host's responsibility to record.
The [hosted remediation executor](./hosted-remediation.md) owns request
attribution, durable attempt tracking, and usage reporting for
`runHostedRemediation`.

Local operational receipts are saved under `telemetry/` in the existing Codex
Security state directory. These are local history, not an analytics upload.
Removing that directory removes these receipts and their resume bindings.
Receipts are never written inside the protected repository; a journal failure
remains observable and does not override the main operation.
Retention and remote deletion in a host's collector remain the host's
responsibility. Existing scan output, diagnostics, and explicit feedback retain
their existing behavior.

## Operation receipts

SDK `run`, `patch`, `validate`, and `generatePolicy` capture an `attempt_started`
receipt at invocation and one `attempt_finished` receipt on settlement. Local
initialization can delay start delivery; its occurrence time remains the original
invocation time. Inference preparation waits for that initialization.
CLI scans use the SDK path. Standalone CLI patch, validation, verification, and
patch-risk assessment also record native invocation starts and outcomes. Mock
scans and preflight-only calls are excluded. Policy generation emits its start to
observers immediately and buffers disk persistence until policy path validation
establishes all protected Git stores. Policy attempts rejected before that point
are observable only through `onTelemetry`; they do not create local state.
Finding workflows likewise defer persistence until explicit and saved artifact
paths have been protected. Their journal cannot write into either artifact tree,
including when the selected artifact directory occupies the journal path.
Each receipt has a schema version, stable event ID, random operation/attempt IDs,
occurrence and local observation times, command, surface, package version, and
resume status. Terminal receipts add duration, outcome, a bounded failure category,
and available numerical usage and result counts. Plugin version and configured
provider family are added once the runtime is known.

The terminal receipt embeds the last SDK measurement with its own `observedAt`
and available `coverageScope`. Saved workbench accounting may reconcile later
native evidence; terminal snapshots are not backfilled.

The outcome is `completed`, `failed`, `canceled`, or `unresolved`. A hosted
submission with unknown acceptance is unresolved. A start without a terminal
receipt, including process loss, also remains unresolved when summarized.
Completion describes operation execution; finding counts do not measure accuracy.
A terminal `reusedResult: true` identifies a cached workflow return. The summary
counts these as `reusedAttempts`; exclude them from new-work, finding-yield, and
usage-coverage denominators. Older receipts without the field have unrecorded
reuse status. Surface and deferred counts are model-reported workflow coverage.

Resuming a saved scan keeps its operation ID but creates a new attempt ID.
`usageScopeId` identifies cumulative accounting across those attempts. Do not sum
resumed cumulative receipts. The supplied summary takes the maximum observed cost
per usage scope; separate retry scans have separate scopes.

```ts
import {
  readOperationTelemetry,
  summarizeOperationTelemetry,
} from "@openai/codex-security";

const { events, parseFailures } = await readOperationTelemetry(stateDirectory);
const summary = summarizeOperationTelemetry(events);
console.log({ ...summary, parseFailures });
```

The reader reports corrupt/truncated records separately from usable receipts. The
summary deduplicates event IDs, counts attempts and logical operations separately,
retains unresolved attempts, and reports usage coverage and priced-attempt counts
beside observed cost. Duration samples can be pooled into histograms or
percentiles; do not average percentiles from separate groups.

`onTelemetry` is an optional SDK observer for these same receipts. An observer
cannot delay or fail a scan. It is not an acknowledgement from a remote collector.
A host needing delivery across restarts should replay the local journal, dedupe
by event ID, and checkpoint only after its collector acknowledges acceptance.
Ingestion should add its own timestamp while preserving `occurredAt`.
Journal write failures reach the warning observer; receipt collection counters
describe local persistence only. They do not claim remote acceptance.

Track collector pending, accepted, retried, dropped/expired, duplicate, and late
records at the integration that owns delivery. Reconcile emitted event IDs against
accepted IDs there. Local tests exercise failed writes, replay, duplicate
terminals, corrupt tails, and unclosed attempts; they do not establish a
production collector's loss rate.

## Usage and completeness

Prefer `onMeasurement` when displaying or collecting live usage:

```ts
await security.run(repository, {
  onMeasurement(measurement) {
    // usage and cost may be null; partial values are observed subtotals.
    display(measurement.usage, measurement.cost, measurement.coverage);
  },
});
```

The observation contains `usage`, `cost`, `coverage`, `observedAt`, measured
`threadCount`, and `missingThreadCount`. Coverage is `complete`, `partial`, or
`unavailable`. An incompletely measured thread can contribute to both thread
counts. Complete coverage means all discovered threads are accounted for;
descendants absent from native metadata and worker receipts cannot be detected.
A newly discovered worker can change complete usage to partial. The
dashboard updates the qualifier and clears unavailable values. Existing
`onUsage` and `onCost` observers retain their complete-only behavior; budget
enforcement still uses known spending subtotals.

Coverage applies to the tracked scan threads, including optional owner evidence
recorded during the scan. Automatic owner reports validate that evidence without
additional model calls. Standalone owner suggestions, finding comparisons, and
severity-review helpers do not contribute usage to these scan/component subtotals.

When available, `coverageScope` identifies every discovered thread and worker
attempt, including missing measurements. Saved reconciliation clears a known gap
only when newer complete evidence covers that entire scope. A newer observation
that does not encompass the retained scope leaves the maximum reported subtotal
partial, even when both observations individually report complete. The
`usage_scope_incomplete` warning identifies these unreconciled scope totals;
later encompassing complete evidence clears that uncertainty. Reconciliation
retains the union of known identities and the largest reported missing-thread
count. Overlapping aggregates cannot establish an exact combined missing-thread
count. Legacy observations without a scope cannot prove that their gaps were
resolved.
These identities belong in local records, not metric labels.

Saved success, failure, and cancellation records retain numerical usage even
without a model price. Repeated terminal updates reconcile late observations
without changing the saved outcome or summing overlapping receipts. Component
and bulk receipts also keep failed/canceled usage. Legacy receipt status values
are preserved; their additive `outcome` distinguishes cancellation.
Bulk recovery of an already sealed scan copies the saved `usage` object with its
original source, observation time, coverage, and scope into the receipt without
creating a new inference attempt or live measurement.

Both live and saved collectors read plain and compressed rollouts. Deep workers
persist a receipt per attempt before validating their output, including failed
and canceled attempts. These receipts live under
`codex-home/worker-usage/<scanId>/` in the host's Codex Security state directory,
with the scan and worker permission profiles protecting the host-managed store.
Collectors bind receipts to the selected scan and attempt; model-authored scan
artifacts cannot introduce usage totals or authorize reading another session.
Worker receipts remain local runtime state, subject to the host's retention and
deletion policy. The pinned native CLI reports cumulative thread usage at
turn completion. Receipts mark this as `usageScope: "thread_cumulative"`:
resumed attempts on the same thread are reconciled by maximum, then compared
with the native thread total by maximum, preserving whole cumulative snapshots.
Separate threads are summed. Missing native evidence
keeps worker fallback usage partial, including when the native state database is
unavailable.

Missing cache-write usage is represented with
`cache_write_input_tokens_reported: false` in SDK token usage and
`cacheWriteInputTokensReported: false` in saved usage. Its numeric zero is a
placeholder, not an observed zero. Worker receipts also treat SDK-defaulted zeroes
without field-presence evidence as unknown. Known total usage remains usable. Cost is an
estimate with its existing price provenance and uncertainty, not a billing total.
Late saved usage can exceed an earlier supplied price estimate; the warning
`cost_estimate_covers_earlier_usage` identifies that cost subtotal.

Embedding batch usage is observed separately through `onEmbeddingUsage`. Provider
input tokens can be unknown; local token estimates do not replace a missing
provider receipt. Publication telemetry uses existing publication results and
receipts, with destination family, duration, outcome, and counts. An upsert
acknowledgement does not establish whether a finding was newly created or reused;
those counts remain unknown when the integration cannot distinguish them.

## Reporting and data selection

Routine operation telemetry contains no source, prompts, model output, finding
text, paths, repository URLs, account IDs, raw exceptions, or full configuration.
This field selection does not redact or change existing diagnostic text.

Use bounded dimensions such as command, surface, scan mode, worker role, outcome,
and provider family. Keep correlation IDs out of metric labels. Report the
population, sample count, missingness, and relevant version/workload cohorts with
every comparison:

- Reliability: terminal outcomes per eligible attempt, unresolved rate, and
  eventual operation success separately.
- Performance: attempt duration distributions, separating cancellation and
  incomplete work.
- Cost: all observed usage scopes, including failed attempts, divided by useful
  completed outcomes; show partial-usage and unknown-price rates alongside.
- Caching: cache-read/write shares only where the required breakdown is observed.
- Worker efficiency: attempts, retries, duration, usage coverage, and accepted
  output by role.
- Quality: reviewed true-positive share among adjudicated findings, with review
  coverage. Unreviewed findings are unknown. Publication and patch outcomes are
  separate signals.

The latest closed false positives used as scan context are a selected sample,
not a false-positive-rate denominator. Recall requires held-out labeled
evaluations or independent representative review; production finding counts
cannot establish it.
