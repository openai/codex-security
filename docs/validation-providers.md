# Validation providers

A validation provider assesses reported findings with evidence outside the source
scan, such as the live deployment. It runs on the host after the scan is sealed,
not in the scan model's sandbox. Provider assessments are supplemental: they do
not rewrite sealed findings or change `--fail-on-severity`.

## Select a provider

Select `scan.validation.provider` in an explicitly chosen, trusted project file.
AWS Continuum is the first built-in provider. See
[project configuration](project-configuration.md#validation-provider-settings)
for its keys and defaults.

```sh
codex-security scan . --validate -c codex-security.yaml
codex-security scan . --validate=continuum -c codex-security.yaml
```

Bare `--validate` uses the configured provider; `--validate=NAME` overrides its
name. Without a configured provider, bare `--validate` keeps the existing Codex
validation. This is separate from `--provider`, which selects inference.
Project files are not discovered automatically.

For a plugin scan, include the project file in the request:

> Scan this repository for security issues using codex-security.yaml.

The existing completion tools run the configured provider after sealing; no new
MCP tool or skill step is needed. Reopening a completed scan reuses results
saved in protected host state, bound to the scan and its selected provider,
rather than resubmitting. The supplemental files in the scan directory are
output projections, not authoritative cache input. SDK callers explicitly
invoke `validate()` with the provider after `run()`; see the
[SDK example](../sdk/typescript/docs/sdk.md#use-a-validation-provider).

Provider work is outside Codex cost accounting. As with existing validation,
`scan --validate` cannot be combined with a scan cost limit. Posture questions
and other deferred review work are not submitted. External provider registry
discovery is not supported.

## Read the supplemental results

CLI and plugin scans save two files beside the sealed scan report:

- `validation.md`: one section per Continuum issue. The headline gives Continuum's
  verdict, issue severity and structured reachability, then Codex's original severity.
  Each section names Continuum's issue, explains the reachability reason and its basis,
  says how and when the issue was checked, and lists the scan's occurrences with locations.
- `validation.json`: `schemaVersion: 2` and `items`, containing typed conclusions for
  each submitted finding. Plugin completion also writes a `findings` count and `summary`.

Each structured item has `itemId`, `provider`, `state`, `codexSeverity` and `reasons`.
`state` is `validated`, `declined`, `pending` or `unavailable`. Codex severity never
changes. Reasons have `basis` and `reason`; failures may include `unavailable`.

The optional `issue` object contains `id`, `url`, `title`, `severity`, `verdict`,
`findingCount`, `checkedBy`, `validatedAt`, `validationBeforeSubmission`, `scoredAt`
and `scoringBeforeSubmission`. Reachability is carried in `reachableFromAttacker`
(a boolean; absence means unknown), `reachabilityBasis` and `reachabilityReason`.
Reason prose never establishes reachability. The two before-submission booleans
are absent when their timestamps are missing.

The optional `findingResult` contains only the `verdict` explicitly naming that
submitted finding in the newest validation artifact. It is displayed separately;
a negative finding result never becomes an exploitable finding simply because the
issue has an exploitable result.

Reports contain conclusions, not raw proof bodies, payloads, commands or validation
console output. Custom SDK providers can omit `record`; their text is still reported,
but they contribute no entry to JSON `items`.

### Reason bases

A basis describes where a reason came from, not its severity or certainty:

- `GRAPH`: deployment graph evidence, such as live reachability.
- `CODE`: source evidence.
- `FINDING`: stated in the finding or supplied validation context, not independently
  checked by the scorer in code or the deployment graph.
- `INFERRED`: an inference rather than a directly established fact.

Unknown future basis values are preserved as reported. Missing bases use `INFERRED`.

### One issue-level answer

For every submitted finding, Continuum reports the issue it filed that finding
under. This is not individual finding validation, even if the issue has one member.
The adapter does not compare claims, attribute issue proof to a finding, search
older artifacts for matching findings, or rewrite Codex severity.

All findings are submitted before polling. `SUBMITTED` and `VALIDATING` stay pending.
`DISCARDED` and `NOT_PURSUED` are definite declined answers, with the service's reason.
For an associated issue, the adapter reads only the newest `VALIDATION_EVIDENCE`
and newest scoring `EVIDENCE`. Both must exist before reporting a validated result.
At the shared deadline, unfinished results remain pending with the issue link when
known. One finding's failure does not affect the others.

If validation or scoring was written before submission, the report says so.
Reused issue evidence is not a new validation of the submitted finding. Neither
new nor reused evidence proves that the deployment runs the scanned source:
deployment source identity and local-tree drift are not compared.

## AWS Continuum requirements

Install AWS CLI v2.38.5 or later outside the checkout. Configure credentials and
the Region for the selected environment. The environment must contain the
matching source; the caller needs permission to submit findings and read
findings, issues, and their artifacts. See
[AWS Continuum permissions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_continuum.html).
Calls use the existing protected host AWS launcher and credential chain, not the
scan model. Keep profiles and custom AWS models outside the scanned checkout.

The adapter sends reported code findings as sink-first OCSF 2002. It submits all
items before polling up to four concurrently under one `wait_minutes` deadline,
including throttling backoff. It follows created, duplicate, and merged issues
and waits for both `VALIDATION_EVIDENCE` and scorer `EVIDENCE`. Recorded-shape
tests are anonymised offline replays, not live results.

Importing existing Continuum issues is a separate workflow; see the
[Continuum import guide](scanner-imports/continuum.md).
