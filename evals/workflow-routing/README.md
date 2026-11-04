# Repository-installed skill routing eval

This opt-in cohort checks whether a fresh Codex thread loads the appropriate
production security skill for a natural-language request. The request does not
name a skill. The eval stops after workflow selection and loading, before source
review, scan startup, triage, patching, or verification.

See [the routing cases](cases.mts) for each prompt and expected skill.

The negative controls catch accidental security-workflow activation. In
particular, testing a fix does not automatically request the standalone
`verify-fix` workflow, and an ordinary repository scan does not request Deep Scan.

## Run

Use the repository's normal SDK and MCP dependency setup, then:

```sh
pnpm --dir sdk/typescript run build:evals
node --experimental-strip-types evals/workflow-routing/run.mts
```

An optional positional argument selects a model. Without one, Codex selects its
default; the SDK does not expose that resolved model. Model runs consume usage
and are not part of CI.

The runner reuses the secret-discovery eval's private-home authentication,
restricted permission profile, native preflight, cancellation draining, and
cleanup. See its [runtime notes](../secret-discovery/README.md#run), including
saved-login refresh behavior and the Windows elevated-sandbox requirement. It
also isolates `HOME` so ambient user skills do not enter discovery. Each case
starts a fresh thread with the fixture as its authoritative working directory.

All current production skills and their references are copied unchanged into
the temporary repository's `.agents` directory. Expected routes and the grader
remain outside the readable fixture. Plugins, connected apps, network access,
memories, and subagents remain disabled. No application source or real findings
are supplied; the invoice claim is synthetic and is not evaluated as a finding.

## Evidence and limits

A routing pass requires a completed turn and a successful shell-tool trace that
returns the expected skill's production heading and introductory instructions.
The grader accepts ordinary or line-numbered reads. An agent's claimed choice,
a filename listing, failed read, or reading every skill does not satisfy the
positive cases. Loading another security skill fails both positive and negative
cases. The final response is retained for review, not used as proof of selection.

`report.json` records each route, turn outcome, full-turn token usage, elapsed
time, failed/repeated commands, repeated skill reads, final response, source
revision and dirty state, package/SDK/CLI versions, requested model, prompt hash,
and hashes of all staged skill entrypoints. Per-case JSONL files retain SDK events.
Artifacts are saved under ignored `reports/`. Cohort status and missing-case IDs
distinguish a partial or interrupted run from all-case success. A failed or incomplete turn cannot
pass; unavailable usage remains `null`. No monetary cost or efficiency threshold
is inferred from token counts.

This checks repository skill discovery and loading, not marketplace installation,
the packed npm layout, successful workflow execution, target handoff, saved
artifacts, finding quality, or missing-tool recovery. The harness explicitly
stops at the routing boundary; a passing case must not be presented as a completed
security task. It does not parse arbitrary shell programs to prove what they
read. Unsupported command-output formats can fail the content-based grader and
should be reviewed in the retained transcript before changing the assertion.

## Deterministic checks

```sh
node --experimental-strip-types --test evals/workflow-routing/test_*.mts
```

Normal CI checks unchanged production staging, each expected route, negative
controls, false-positive trace rejection, failures, cancellation, and SDK thread
setup. These checks validate the harness; they do not establish model accuracy.
