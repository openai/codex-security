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

For automatic validation at plugin scan completion, install the packaged plugin or build the plugin in a full checkout after installing the SDK dependencies. With a standalone plugin source checkout, use the CLI on the saved scan as described below.

For a plugin scan, include the project file in the request:

> Scan this repository for security issues using codex-security.yaml.

Standard and diff setup save the provider settings from the selected project
file. Rejoining the scan uses that saved configuration.

The plugin runs the configured provider after sealing the scan. Ask Codex to
show the completed scan to read the last saved assessment from protected host
state. If polling timed out, ask Codex to retry supplemental validation for
that scan ID. Completing the scan again resumes polling accepted findings by
their AWS IDs and reuses finished assessments. The CLI can also poll a
selection from the saved scan. SDK callers invoke `validate()` with the
provider after `run()`. [SDK example](../sdk/typescript/docs/sdk.md#use-a-validation-provider)

After an upgrade, patch and verify skip cached Continuum assessments computed
before the current finding and HTTP proof checks. Reading a scan makes
no AWS requests. If the plugin shows `outdated`, explicitly complete the scan
again to refresh its assessments. For CLI snapshots, rerun `validate --scan`
for the affected occurrences. Use the original host state and configuration
to reuse accepted submissions. A missing receipt can cause a new submission.
If a CLI retry creates a new AWS finding for a plugin scan, complete the scan
again to update the plugin’s saved finding ID before remediation.

Provider work is outside Codex cost accounting. As with existing validation,
`scan --validate` cannot be combined with a scan cost limit. Posture questions
and other deferred review work are not submitted. External provider registry
discovery is not supported.

## Validate findings from a saved scan

From the checkout, use `codex-security scans list --json` to find a completed
scan and `codex-security scans show SCAN_ID --json` to inspect its findings.
Submit a selection by occurrence ID with the trusted provider configuration.

```sh
codex-security validate --scan SCAN_ID -c codex-security.yaml OCCURRENCE_ID --format json
```

Supply multiple IDs separated by spaces. Omitting the IDs selects all open
findings from the scan. `--scan latest` selects the latest completed scan in
the current directory. The command reads the saved findings and runs the
provider directly. Output goes to stdout. JSON contains `scanId` and one
`items` entry per selected finding. Exit code 1 indicates at least one
unavailable assessment. Check the individual records for accepted submissions.

Continuum receives each selected finding's identifier, title, summary, severity,
CWE when available, file paths and line ranges. Before calling
`CreateCodeFinding`, the host saves the exact request and token in its private
state directory under `continuum-submissions`. After acceptance it saves the
AWS finding ID, ARN and original submission time, and deletes the request body.
After an interruption, rerun the command with the same scan ID, selection,
environment and host state. Pending requests reuse the same document and token.
Accepted findings resume at `GetCodeFinding`. A new finding, changed submitted
content, another destination or loss of the host state can create a fresh
submission. If a finding stays `SUBMITTED`, check the scan activity in the
Continuum environment. The finding may be waiting for the next build.

### Patch and verify a saved occurrence

After validation, reopen the original occurrence on the same host. CLI patch
and verify-fix and workbench Generate and Verify can read its saved assessment
without AWS access. The model receives sensitive provider identifiers, status,
scope, freshness and any eligible observation. It checks the candidate against
the original remediation tests. Apply uses the recorded patch unchanged.

The workbench owns the whole scan's validation report and retries. The CLI
saves individual results under `cli-continuum-*` in its private state directory.
Validating a subset leaves the workbench's queue and report intact. For a
timed-out workbench finding, only a retry of the same AWS submission can supply
its result. For competing results on the same submission and issue, the latest
AWS validation artifact wins. An invalid workbench result prevents a CLI
result from a different submission taking its place. Missing or ambiguous
evidence leaves the original finding available for remediation.

Import is optional. To collect full AWS evidence or available patches, pass
the returned `findingId` to
`codex-security import continuum ENVIRONMENT_ID --finding-id FINDING_ID --source-root CHECKOUT --format json`.
Use the same AWS profile and Region as for validation. The collector retrieves
the finding's evidence and any matching patches. [Collect, patch and verify a finding](scanner-imports/continuum.md#collect-a-finding-with-patches)

### Match an imported issue to local findings

A local Continuum import stores one external record per AWS issue. Its
`sourceFindingId` is the issue ARN. The raw export also has a `sourceFindingId`
on each contributing finding if AWS returns it. For a finding submitted from a
Codex scan, that value is the occurrence ID. [Continuum import guide](scanner-imports/continuum.md)

To match contributors using local records, set `issue_arn` to the imported
issue ARN, `import_json` to the JSON output file from
`publish findings --to local --format json`, and `assessment` to the scan's
`validation.json` or saved `validate --scan` JSON output. This prints a row
with the AWS finding ARN and local occurrence ID for each match in that scan.

```sh
jq -r --arg issue "$issue_arn" --slurpfile validation "$assessment" '
  .findings[] | select(.sourceFindingId == $issue)
  | (.evidence.source_data.findings[]?.findingArn // empty) as $arn
  | $validation[0].items[] | select(.findingArn == $arn)
  | [.findingArn, .itemId] | @tsv
' "$import_json"
```

## Read the supplemental results

CLI and plugin scans save two files beside the sealed scan report:

- `validation.md`: one section per finding, with disposition, verdict, original
  and supplemental severity, reasons and their bases, claim match, freshness,
  and an issue link when available. CLI sections also include provider provenance.
- `validation.json`: `schemaVersion: 1` and `items`, containing structured
  conclusions. Plugin completion also writes a `findings` count and `summary`.

Each structured item uses these fields:

| Field                     | Meaning                                                                                |
| ------------------------- | -------------------------------------------------------------------------------------- |
| `itemId`                  | Codex finding identifier                                                               |
| `findingId`, `findingArn` | AWS identity after acceptance, including when subsequent polling fails                 |
| `issueId`, `issueArn`     | Associated AWS issue, when retrieved                                                   |
| `submittedAt`             | Original submission time                                                               |
| `provider`                | Validation provider name                                                               |
| `verdict`                 | Provider verdict, or `UNAVAILABLE`                                                     |
| `terminalStatus`          | How the validation run ended, when reported by the provider                            |
| `statusMessage`           | Provider explanation for a discarded or declined finding, when supplied                |
| `severityBefore`          | Original Codex severity                                                                |
| `severityAfter`           | Original severity unless current validation and scoring support this finding           |
| `validationArtifactId`    | AWS identifier of the selected validation artifact, when available                     |
| `scoringArtifactId`       | AWS identifier of the selected scoring artifact, when available                        |
| `proofObservation`        | Observed HTTP effect from a matched finding                                            |
| `providerSeverity`        | Provider's severity, when returned. Continuum reports the severity of the issue.       |
| `resultScope`             | `finding` or `issue`, indicating the scope of the verdict                              |
| `issueFindingCount`       | Number of distinct findings in the associated issue, when known                        |
| `joinedValidatedIssue`    | Issue-scoped proof predates this finding's submission                                  |
| `reasons`                 | Entries with `basis` and `reason`                                                      |
| `claimMatch`              | `on_target`, `on_target_escalated`, `different_flaw`, or `unknown`                     |
| `issueUrl`                | Provider issue link, when available                                                    |
| `freshness`               | Optional `evidenceCreatedAt` and `validatedAt` timestamps, `stale` flag, and `reasons` |
| `unavailable`             | Per-finding failure explanation, when present                                          |

Continuum reports `reachableFromAttacker` as a structured boolean from the
issue's scoring evidence. Its absence means reachability is unknown.

Reports contain conclusions, not raw proof bodies or validation console output.
Custom SDK providers can omit `record`; their text assessment is still reported,
but they then contribute no entry to JSON `items`.

### Reason bases and claim matching

A basis describes where a reason came from, not its severity or certainty:

- `GRAPH`: deployment graph evidence, such as live reachability.
- `CODE`: source or validation evidence about the code.
- `FINDING`: stated in the finding or its supplied validation context, without
  independent confirmation by the scorer in code or the deployment graph. It is
  not a finding-specific proof or a deployment observation.
- `INFERRED`: an inference rather than a directly established fact.

Unknown future basis values are preserved as reported, not renamed to `INFERRED`.
Missing bases use `INFERRED`; aggregate severity factors are also labelled
`INFERRED` because the adapter does not receive one provenance basis for the
combined severity.

A provider can prove a related flaw without validating the submitted claim.
Continuum labels that case “Not validated: Continuum proved a related flaw” and
retains Codex severity (`claimMatch: different_flaw`). An `unknown` match also
retains Codex severity.

For a conclusive [per-finding verdict](https://docs.aws.amazon.com/continuum/latest/APIReference/API_PerFindingResult.html),
Codex looks for a reasoning step whose `source` cites the first submitted
location and whose `claim` describes the same kind of flaw. The citation
must include the exact repository-relative path and a starting line within
the submitted range. The citation and claim must occur in the same step.

The same finding result must contain a complete HTTP
[exploit artifact](https://docs.aws.amazon.com/continuum/latest/APIReference/API_ValidationExploitArtifact.html).
For `EXPLOITABLE`, the observed effect must be `DATA_LEAKED`, `ERROR_REVEALED`
or `BEHAVIOR_CHANGED`. For `NOT_EXPLOITABLE`, it must be `NO_EFFECT`.
Missing or contradictory evidence leaves the claim match unknown and preserves
Codex severity. An executed program or source analysis on the issue cannot
supply missing proof for an individual finding. Claim comparison remains a
heuristic because distinct flaws can share a location and vocabulary.

The newest eligible scorer supplies reachability and other scoring evidence.
Its signals must identify the issue by ID or ARN, with a single exploitability
signal referencing the selected proof and verdict. Timestamps must establish
submission, validation, scoring and issue update in that order. To apply the
issue severity to the finding, the proof must match, the issue must have one
member and the linked scorer must be the newest on the issue. The issue
severity is reported separately in `providerSeverity`.

A matched result with linked scoring and an explicit `COMPLETED` status can
include an execution `proofObservation` with the observed HTTP effect.
An older artifact with no run status can qualify for matching and scoring
under the same checks, but carries no observation. Codex omits requests,
responses and raw reasoning from the assessment. Consult the selected
artifact for details. The original finding supplies the remediation criteria.

### Findings that share an issue

Continuum can group several findings into one issue. If validation and scoring
artifacts exist but the validation cannot be attributed to this finding alone,
the adapter returns promptly with an **issue-level result**. It gives the
current number of findings and reports the issue's verdict, severity and
structured reachability with its reason basis. Codex retains its finding severity.
JSON records use `resultScope: "issue"`, `issueFindingCount`, and
`claimMatch: "unknown"`. This applies even when the issue currently lists
only the submitted finding. Membership can change after evidence collection.

Before reading artifacts, the adapter verifies the associated issue ARN and
checks that the issue still lists the submitted AWS finding ID. This ties
current severity and reachability to the issue associated with the submission.
An artifact supports a finding verdict only when exactly one `perFindingResults`
entry matches the submitted AWS finding ID and carries a recognized
`exploitable` verdict. That entry takes precedence even in an older artifact.
The claim comparison uses the projected finding evidence. If all artifacts
lack a unique valid result for the finding, the adapter uses the newest
overall verdict for the issue. For conclusive verdicts, the adapter waits for
scoring within the shared deadline.

If issue proof predates submission, the report says the finding joined an issue
Continuum had already validated (`joinedValidatedIssue: true`). Validation,
scoring and issue timestamps all participate in stale checking. Reachability
comes only from the structured boolean value; missing or `UNKNOWN` stays unknown.

### Inconclusive, unavailable or stale evidence

Read `verdict` together with `terminalStatus`. For example, a run can end
with `FAILED`, return `UNCERTAIN` for exploitability and still have a low
issue score. Codex defers the assessment, preserves the original finding
severity in `severityAfter` and reports the issue score in `providerSeverity`.
A failed run or missing source also sets `unavailable`, so `validate --scan`
exits with code 1.

For `FAILED`, open `issueUrl` and check the validation run. If the cause is
unclear, ask AWS for worker logs privately. Include `findingArn`, `issueArn`,
`validationArtifactId` and `freshness.evidenceCreatedAt` from the same item.
The plugin caches terminal failures. Repeating completion cannot restart the
AWS worker.

To check for progress on an issue, use the same AWS profile and Region.
This read lists communication timestamps, producers and IDs.

```sh
aws continuum list-code-issue-artifacts --environment-id "$environment_id" \
  --issue-id "$issue_id" --region "$region" --artifact-type AGENT_COMMUNICATION \
  --query 'items[].{created:createdAt,producer:producer,id:artifactId}' --output table
```

Communications can describe a different finding, run or patch on the issue.
Even a `ContinuumValidation` message can precede a failed run. Keep the
message bodies private. Codex excludes them from claim matching and remediation.

A partial run or an uncertain verdict also yields a deferred assessment.
In plugin completion and `scan --validate --format json`, a deferred Continuum
assessment sets `validation.status` to `incomplete`.
`DISCARDED` and `NOT_PURSUED` yield `not_applicable` with the provider's
explanation when available. All these outcomes have `claimMatch: unknown`.
`validatedAt` requires a conclusive verdict and a timestamp from the
validation artifact.

Submission rejections, missing code locations, read errors, and polling deadlines
produce unavailable assessments per finding. Other findings keep their results,
and supplemental provider failures do not fail the sealed scan. Continuum records
`verdict: UNAVAILABLE`, retained severity, and an `unavailable` explanation;
the assessment disposition is `deferred`.

Evidence older than the submission is marked stale in `freshness` and Markdown.
Freshness describes the age of the evidence. Verifying that the deployed
revision matches the scanned tree requires a separate revision comparison.

## AWS Continuum requirements

Install AWS CLI v2.38.5 or later outside the checkout. Configure credentials and
the Region for the selected environment. Scan the Git repository root.
Continuum must have a single Git repository as its only code source, matching
a remote of that checkout. The adapter verifies the source using
`GetEnvironment` and `GetIntegration` before sending any results.
The caller also needs `CreateCodeFinding`, `GetCodeFinding`, `GetCodeIssue`,
`ListCodeIssueArtifacts` and `GetCodeIssueArtifact`. See
[AWS Continuum permissions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_continuum.html).
Calls use the existing protected host AWS launcher and credential chain, not the
scan model. Keep profiles and custom AWS models outside the scanned checkout.

The adapter sends reported code findings as sink-first OCSF 2002. It submits all
items before polling up to four concurrently under one `wait_minutes` deadline,
including throttling backoff. It follows created, duplicate, and merged issues
and reads `VALIDATION_EVIDENCE` and scorer `EVIDENCE`. Recorded-shape
tests are anonymised offline replays, not live results.

Importing existing Continuum issues is a separate workflow; see the
[Continuum import guide](scanner-imports/continuum.md).
