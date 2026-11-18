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
MCP tool or skill step is needed. Reopening a completed scan reuses saved results
rather than resubmitting. SDK callers explicitly invoke `validate()` with the
provider after `run()`; see the [SDK example](../sdk/typescript/docs/sdk.md#use-a-validation-provider).

Provider work is outside Codex cost accounting. As with existing validation,
`scan --validate` cannot be combined with a scan cost limit. Posture questions
and other deferred review work are not submitted. External provider registry
discovery is not supported.

## Read the supplemental results

CLI and plugin scans save two files beside the sealed scan report:

- `validation.md`: one section per finding, with disposition, verdict, original
  and supplemental severity, reasons and their bases, claim match, freshness,
  and an issue link when available. CLI sections also include provider provenance.
- `validation.json`: `schemaVersion: 1` and `items`, containing structured
  conclusions. Plugin completion also writes a `findings` count and `summary`.

Each structured item uses these fields:

| Field              | Meaning                                                            |
| ------------------ | ------------------------------------------------------------------ |
| `itemId`           | Codex finding identifier                                           |
| `provider`         | Validation provider name                                           |
| `verdict`          | Provider verdict, or `UNAVAILABLE`                                 |
| `severityBefore`   | Original Codex severity                                            |
| `severityAfter`    | Supplemental severity; original retained for an unmatched claim    |
| `providerSeverity` | Provider's severity, when returned                                 |
| `reasons`          | Entries with `basis` and `reason`                                  |
| `claimMatch`       | `on_target`, `on_target_escalated`, `different_flaw`, or `unknown` |
| `issueUrl`         | Provider issue link, when available                                |
| `freshness`        | Optional `validatedAt` timestamp, `stale` flag, and `reasons`      |
| `unavailable`      | Per-finding failure explanation, when present                      |

Reports contain conclusions, not raw proof bodies or validation console output.
Custom SDK providers can omit `record`; their text assessment is still reported,
but they then contribute no entry to JSON `items`.

### Reason bases and claim matching

A basis describes where a reason came from, not its severity or certainty:

- `GRAPH`: deployment graph evidence, such as live reachability.
- `CODE`: source or validation evidence about the code.
- `INFERRED`: an inference rather than a directly established fact.

A provider can prove a related flaw without validating the submitted claim.
Continuum labels that case “Not validated: Continuum proved a related flaw” and
retains Codex severity (`claimMatch: different_flaw`). An `unknown` match also
retains Codex severity. Claim matching is a small text-and-path heuristic, not a
service-certified identity.

### Unavailable or stale evidence

Submission rejections, missing code locations, read errors, and polling deadlines
produce unavailable assessments per finding. Other findings keep their results,
and supplemental provider failures do not fail the sealed scan. Continuum records
`verdict: UNAVAILABLE`, retained severity, and an `unavailable` explanation;
the assessment disposition is `deferred`.

Evidence older than the submission is marked stale in `freshness` and Markdown.
Current-at-submission evidence does not prove that the deployment runs the scanned
code: deployment source identity and local-tree drift are not checked.

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
