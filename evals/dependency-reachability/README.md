# Dependency reachability eval

The default eval runs 23 checks against fresh snapshots of MailParser, Pillow,
and Backstage. Each check invokes the shipped CLI with only a CVE identifier.
The CLI fetches the advisory from OSV and runs the bundled `dependency-exploitability`
skill with a fresh in-memory graph for each check. The checkout combines pinned
upstream source with synthetic application and deployment files. Case IDs,
caller descriptions, and expected answers stay outside the checkout.

```sh
codex-security exploitability check CVE-2025-14874 --json
```

The CLI reviewer checks the evidence before the command returns a report.
The eval then grades that report against the expected verdict and source
citations for the case. Only the eval grader has those expectations.
Record wall time and token use alongside accuracy. Use `--cli PATH` to select
a specific built CLI, allowing concurrent evals of frozen builds.

The wheel fixtures select official artifacts by URL and SHA256. Their bundled
library manifests record static inspection of those exact wheels: native library
hashes, version getters, dynamic linkage and matching Python source. These are
artifact facts, not observations of a running service. The archive-worker
fixtures select a local Docker build that copies the application and installs
its locked dependencies; an unspecified external image would not establish
those same source or dependency facts.

The Nodemailer cases also include the locked `@zone-eu/mailsplit` and `libmime`
source, with artifact hashes and original licenses. Their npm tarballs were
verified against the upstream lockfile's integrity values before extraction.
This makes MIME boundary and header handling available to the repository-only
reviewer, including on the corresponding negative cases. These source fixtures
are evidence for the selected packages, not a runnable dependency installation.

| Package | CVE | What varies across snapshots |
| --- | --- | --- |
| Nodemailer | CVE-2025-14874 | Mail routing, a downstream patch, attachment processing, and which archived message or ZIP member a consumer reads. |
| linkify-it | CVE-2026-48801 | MailParser options, input handling, and whether the receiver implementation is available. |
| glibc | CVE-2024-2961 | The conversion direction used by MailParser's native charset decoder. |
| libwebp | CVE-2023-4863 | Image decoding versus encoding, the library bundled in a wheel, and the build loaded by a serving process during rollout. |
| vm2 | CVE-2023-37466 | How the Backstage starter handles a user-supplied task parameter in a full v1.14.1 checkout. |

## Run the CLI eval

Use Node.js 22.22+, Git, and the same model credentials you use with the CLI.
Install OpenGrep and ensure `PATH` resolves `opengrep` to an executable outside
the scanned checkout.
From the repository root, download the verified universal native artifact for
the checkout's native sources. Replace `RUN_ID` and `native-universal-COMMIT`
with the ID and artifact name from the successful GitHub Actions run.
[Native package inputs](../../plugins/codex-security/native/README.md#package-inputs)

```sh
gh run download RUN_ID --name native-universal-COMMIT --dir plugins/codex-security/native/prebuilt
pnpm --dir plugins/codex-security/mcp-app install --frozen-lockfile
pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir sdk/typescript run build:plugin
pnpm --dir sdk/typescript run build
```

For a quick check with no upstream clones, select `mixed-services` explicitly.
This standalone smoke case checks whether the command finds both services using
a shared HTTP handler and distinguishes their installed versions of `linkify-it`.
It runs separately from the 23 checks. Live runs access OSV and consume model usage.

```sh
node --experimental-strip-types evals/dependency-reachability/run.mts --case mixed-services
```

The 23 checks read pinned Git objects from `--repos DIR`, under
`<owner>/<repository>`. For one MailParser backport check, two clones suffice.

```sh
repos="$(mktemp -d)"
mkdir -p "$repos/nodemailer"
git clone --no-checkout https://github.com/nodemailer/mailparser.git "$repos/nodemailer/mailparser"
git clone --no-checkout https://github.com/nodemailer/nodemailer.git "$repos/nodemailer/nodemailer"
node --experimental-strip-types evals/dependency-reachability/run.mts --repos "$repos" --case address-backport
```

Add the remaining repositories and omit the selector to run all 23 checks.

```sh
mkdir -p "$repos/python-pillow" "$repos/backstage" "$repos/alpinelinux"
git clone --no-checkout https://github.com/python-pillow/Pillow.git "$repos/python-pillow/Pillow"
git clone --no-checkout https://github.com/python-pillow/pillow-wheels.git "$repos/python-pillow/pillow-wheels"
git clone --branch v1.14.1 --single-branch --no-checkout https://github.com/backstage/backstage.git "$repos/backstage/backstage"
git clone --no-checkout https://github.com/alpinelinux/aports.git "$repos/alpinelinux/aports"
node --experimental-strip-types evals/dependency-reachability/run.mts --repos "$repos"
```

Use `--case ID` for one snapshot or `--suite mailparser`, `--suite pillow`, or
`--suite backstage` for one project. `--suite challenge` selects the ten patch,
attachment, archived-mail, and ZIP cases. Checks run sequentially by default.
Set `--jobs N` to run up to N commands concurrently.
Use `--model MODEL` to select the assessment model. Omitting it uses the CLI's
default model. The selected model is recorded in each case's command arguments.

## Grade and compare runs

For each of the 23 cases, the grader looks for the expected dependency use in
the CLI report. That use must identify the component, version, verdict, and
location, explain its reasoning, and cite the deciding lines in the snapshot.
Other uses can have different verdicts. The grader checks the overall status
for consistency with the reported uses. The smoke case requires both service
verdicts and their deployment evidence. A failed grade or CLI error exits
nonzero.

Evidence groups are conjunctive: every group must be covered, while alternatives
within a group express equivalent evidence for one fact. A `completeFile` anchor
requires the union of validated citation ranges to cover the entire file, for
example when the deciding fact is an absent receipt. `evidenceCorrect` measures
this source coverage, not the semantic quality of the explanation; the CLI's
reviewer handles the latter. A passing target use does not certify every other
use in the report.

The Backstage target is the configured portal task path, including workflow and
fixed-skeleton rendering. Its expected exclusion does not cover standalone
backends elsewhere in the upstream checkout.
It assesses configured checkout behavior, not the contents of an observed
running image; citing a particular convenience build script is not required.

The external-worker case requires `version: null` for its absent HTTP receiver.
The local checkout's known version does not identify that receiver. Its
`commandVersion` override applies only to CLI grading; the historical scoped
question separately asks for the local image version. Other cases retain exact
version matching, including explicitly listed distribution-version aliases.

The current 23 snapshots have nine expected `potentially_exploitable` uses,
twelve `ruled_out` and two `unknown`. None establishes both a running
affected use and access by the relevant caller. A captured worker can prove
what is running while a desired route leaves public access unconfirmed.
Earlier runs used `exploitable` for some code-level findings and are scored
under their original contract.

Each `reports/command-*/report.json` records the command, source revision,
snapshot digest, per-case grade, command wall time, and token usage when
available. Compare the same cases, snapshot digests, model settings, and job
count across runs. Check pass counts and individual use grades alongside time
and input, cached input, and output tokens. Unavailable usage is reported as
`null`.

Changes to artifact selection or build fixtures change snapshot digests. Keep
the earlier scores and rerun those cases with the corrected inputs; do not
rescore old outputs as though they had received the new evidence. Changes only
to grading can be evaluated against saved reports on their original snapshots.

## Historical skill baseline

`run-skill-baseline.mts` runs `attack-path-analysis` directly on the 23 caller-scoped
questions. It supplies the entry point, caller permissions, and advisory.
Earlier scores used those scoped prompts and earlier fixture digests. Use
fresh CLI runs to measure changes to the CVE-only command.

```sh
node --experimental-strip-types evals/dependency-reachability/run-skill-baseline.mts --repos "$repos" --case address-backport
```

Use `--help` for case and suite selectors. To compare a trusted local adapter,
append `-- /absolute/path/to/adapter`. It runs in a copy of the snapshot,
reads the scoped question and output instructions from stdin, and writes one
JSON answer to stdout. The scoped grader checks the verdict, dependency
version, and exact source quotes. Baseline reports are written to
`reports/run-*/report.json`. [Shared eval runtime](../secret-discovery/README.md#run)

## Deterministic checks

CI runs these checks without model calls or upstream clones.

```sh
pnpm --dir evals/triage-finding install --frozen-lockfile
pnpm --dir sdk/typescript run build:evals
node --experimental-strip-types --test evals/dependency-reachability/test_*.mts
python3 -B -m unittest discover -s evals/dependency-reachability/fixtures/zip -p test_catalog.py
```
