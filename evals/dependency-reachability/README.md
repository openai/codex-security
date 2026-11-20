# Dependency reachability eval

Given a CVE and a caller, can `codex-security exploitability check` identify which copy of a dependency the application uses and cite what makes the affected operation reachable or rules it out?

## Compare the reviewer on and off

The pinned suite runs the repository command in a fresh Git checkout for every investigation. The CLI looks up the advisory and the investigator traces the caller through the application. By default, an independent model reviews claims and can ask the investigator to correct them. With `--grader=disabled`, the host checks the claims and their source references and labels the result unreviewed. To try both modes in your own checkout, use a build with the grader option.

```sh
export CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY=1
codex-security exploitability check CVE-2026-54283 --json
codex-security exploitability check --grader=disabled CVE-2026-54283 --json
```

The **eval grader** runs after the CLI exits. It scores both reports against the same expected use, version, verdict and evidence. The expected answer stays outside the checkout. The CLI gets the CVE and a project config with the caller’s scope in `exploitability.scope.instructions`. The runner records the actual command, progress events and report for each attempt.

### Start from a fresh checkout

Run the following from the repository root with Git, Python 3.12+ and Node.js 22.13+, 24 or 26. The first command tests the eval itself in a few seconds using local fixtures. Fetch the pinned public sources once (~229 MiB) and use `--prepare-only` to validate all the case inputs and expected citations offline. Both checks run before building the CLI and require no model credentials.

```sh
node --test evals/dependency-reachability/test-eval.mjs
runner=evals/dependency-reachability/upstream.mjs
cache=$(mktemp -d)
outputs=$(mktemp -d)
python3 evals/dependency-reachability/upstream/assets.py fetch "$cache"
node "$runner" --cache "$cache" --prepare-only --out "$outputs/prepared"
```

For live runs, build the CLI **and its plugin** in the worktree you want to evaluate. With the repository’s pinned pnpm and Rust toolchain, these commands build both from source on a Unix host. The last line lets the Node launcher find the local plugin. After rebuilding the SDK, recreate the link because the build replaces `dist/`. If you already have the universal native payload, use `pnpm --dir sdk/typescript run build:plugin` in place of the last three lines. [SDK setup](../../sdk/typescript/TESTING.md#install-dependencies) · [Native build](../../plugins/codex-security/native/README.md#build-the-standalone-plugin-for-this-host)

```sh
pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir plugins/codex-security/mcp-app install --frozen-lockfile
pnpm --dir sdk/typescript run build
node plugins/codex-security/mcp-app/scripts/build_native.mjs
node plugins/codex-security/mcp-app/scripts/build_mcp_app.mjs --output plugins/codex-security/mcp --native host
ln -s ../../../plugins/codex-security sdk/typescript/dist/_bundled_plugin
```

### Run one pair or the full suite

Put `opengrep` on `PATH` and choose a model your account can use. Live checks contact OSV and the model provider. The runner sets the feature flag and invokes the regular repository CLI. With `OPENAI_API_KEY` or `CODEX_API_KEY` in the environment, use `--isolated-state` for a fresh CLI state directory per investigation. To use your stored CLI login, omit that option. [OpenGrep installation](https://github.com/opengrep/opengrep#installation) · [Authentication](../../sdk/typescript/docs/cli.md#authentication)

```sh
CLI=sdk/typescript/bin/codex-security.mjs
model=gpt-6.1-sol
opengrep --version
node "$runner" --cache "$cache" --cli "$CLI" --model "$model" --isolated-state \
  --case clips-handler-validation --grader both --out "$outputs/clip"
```

`--grader both` launches two independent investigations per case, alternating which mode starts first. To reproduce a single failure, supply its `--case ID` and `--grader enabled` (the default) or `--grader disabled` with a fresh `--out` directory. Repeat `--case` to select several IDs. `--help` lists them. Select `--suite original` for the historical 23 cases, `--suite added` for the additions, or a suite from the table. Omit the selectors for a full run. `--jobs` limits concurrent CLI processes and defaults to one.

```sh
node "$runner" --cache "$cache" --cli "$CLI" --model "$model" --isolated-state \
  --grader both --jobs 4 --out "$outputs/pairs"
```

### What the cases test

| Suite         | Cases | Deciding question                                                                                                                                       |
| ------------- | ----: | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mailparser`  |    16 | Can an incoming message reach the affected parser through the selected route, queue, archive or ZIP member? Does the installed copy include a backport? |
| `pillow`      |     6 | Does the caller decode or encode an image? Which version of libwebp does the selected wheel or running worker load?                                     |
| `backstage`   |     1 | Can the user supply a template, or only a value passed into a template controlled by the portal?                                                        |
| `resolution`  |     3 | Two installed copies of Nodemailer have the same version. Which one does the address book load?                                                         |
| `application` |     5 | Does the selected upload service reject a URL-encoded request before Starlette parses the body?                                                         |

The fixtures combine pinned upstream source with synthetic services and deployment records. The manifest pins archives, individual source files and npm releases by SHA-256. The materializer verifies the inputs and stages source as inert files. `--prepare-only` also verifies that each expected citation exists in the resulting Git commit. [Manifest](upstream/assets.json) · [Cases](upstream/cases.mjs)

**Follow one request through the upload service.** In `clips-handler-validation` an anonymous caller chooses the headers and body of `POST /clips`. The handler calls `request.form()` before checking for an audio file. A URL-encoded body therefore reaches the parser affected by CVE-2026-54283 before the handler returns 422. The expected verdict is `potentially_exploitable`. The checkout establishes the configured path. [Handler](upstream/fixtures/clips/api.py) · [Advisory](https://github.com/advisories/GHSA-82w8-qh3p-5jfq)

In `clips-gateway-validation` the launch config enables a multipart gate. The same request gets a 415 at the gateway, so the parser is `ruled_out` for this caller. In `clips-external-profile` the gate depends on a setting supplied outside the checkout. A correct `unknown` identifies the missing setting. The last two cases share one Git commit containing both services. Changing one word in the caller scope, from `mobile` to `studio`, selects the service with the gate enabled. [Launch profiles and caller scopes](upstream/application-cases.mjs)

**Follow one package selection.** In the address book, both copies declare Nodemailer 7.0.10. The service uses `createRequire` from the configured project directory. The main copy has the affected parser, the contacts plugin has a backported guard and the externally selected profile leaves the copy unresolved. Each answer needs the binding from the launcher to the implementation. [Copy selection cases](upstream/copy-selection-cases.mjs)

### Read the results

In a paired run, open `results.json` for the comparison and `enabled/<case>/` and `disabled/<case>/` for the underlying reports. In a single run the path is `<case>/`. Each successful command saves `report.json`. Inspect `progress.jsonl` for investigation and review events and `stderr.log` for diagnostics. A failed command also saves `stdout.log`.

- `passed` requires one assessed use to satisfy the full rubric. The eval checks the search audit, claim provenance and source citations against pinned Git blobs. It measures the citations attached to the assessed use in both conditions. Inspect the per-case errors to see which facts are missing.
- `verdict`, `identity`, `version` and `decidingEvidence` count individual requirements on the best matching use. A verdict label can be correct while the report misses the application binding. `identityAndVerdict` requires both. Execution errors count in the denominator, and a completed `unknown` is graded against its case.
- `selectedEvidence` checks whether the citations marked as deciding cover the identity, decisive facts and required call site. With review enabled, the reviewer selects these citations. With review disabled, this set contains all host-validated citations. Earlier CLI scores required the selected set and additional intermediate citations. Regrade saved reports to compare with the current rubric.
- `gainedWithReview` and `lostWithReview` name cases that passed in only one condition. The comparison checks the Git commit, scope, CVE and available advisory digests. It lists unfinished pairs and input mismatches separately. The process exits nonzero for an execution error, failed grade or mismatched inputs.
- `medianPairedElapsedDeltaMs` is the median of the per-case time with review minus the time without review. `reviewBatches` counts review events in complete progress logs. Each batch can cover multiple claims and may require another model turn. Token totals cover the reports with usage. One pair per case gives a sample that includes variation between independent investigations.

Regrade saved reports offline after changing the rubric. The runner infers the cases and reviewer modes from the saved `results.json`, reads the original report bytes and re-creates the pinned Git commits. You can narrow the replay with `--case` and `--grader`. The new results reference the original output directory, which holds the reports and logs.

```sh
node "$runner" --cache "$cache" --grade-existing "$outputs/clip" --out "$outputs/regraded"
```

### Work on a candidate in parallel

`results.json` records the Git commits of the runner, CLI and optional case module in `checkouts` when their entry points are tracked. It records tracked edits across each worktree for the runner and CLI and within the module directory for external cases. Regrading preserves these records and adds `regradeCheckouts`. Rebuild the CLI after editing its source so the binary matches the recorded checkout.

Keep the baseline worktree at the starting commit. From its root, create a candidate with `git worktree add -b reachability-candidate ../reachability-candidate HEAD`. Give the other worker the starting commit, absolute cache path, case IDs, model, reviewer modes and baseline results directory. Each worker builds in their own worktree, reads the shared cache after fetching and writes to a new output directory outside Git. Workers can split the cases using repeated `--case` flags or run the same cases to compare implementations.

For a CLI change, build the candidate in its worktree. From the baseline root, repeat the one-pair command against that build so both runs use the same fixtures and grading code.

```sh
node "$runner" --cache "$cache" --cli "../reachability-candidate/$CLI" --model "$model" --isolated-state \
  --case clips-handler-validation --grader both --out "$outputs/clip-candidate"
```

Compare each mode with the corresponding baseline mode at the same model and job count. Check the source, caller scope and advisory fingerprints, then read the changed reports. Repeat a changed case to see if the result recurs. The pinned cases measure the configured caller path and its evidence. The local service cases also exercise confirmation that the affected copy ran and a caller reached it. [Local service cases](#local-service-and-captured-stack-checks)

For a new case, start with a neighboring case definition, add its fixture and register it in `cases`. Keep the caller question separate from the expected answer. Identify the exact source excerpts that decide the verdict. Run `--prepare-only --case ID` and then a live pair for that ID. [Case definitions](upstream/cases.mjs) · [Example with two callers](upstream/application-cases.mjs)

### Load a local case module

Use `--case-module PATH` in place of `--cache` to supply your own cases, fixtures and rubric. The runner imports and executes the module even for `--help`, so supply a trusted local JavaScript file. The same `--suite`, `--case`, CLI and reviewer options apply. Supply the module again when regrading.

```sh
module=/path/to/cases.mjs
node "$runner" --case-module "$module" --help
node "$runner" --case-module "$module" --prepare-only --out "$outputs/local-prepared"
node "$runner" --case-module "$module" --cli "$CLI" --model "$model" --isolated-state --grader both --out "$outputs/local"
node "$runner" --case-module "$module" --grade-existing "$outputs/local" --out "$outputs/local-regraded"
```

Provide four named exports. Each function may be async. [Module example](test-eval.mjs) · [Runner](upstream.mjs) · [Citation helpers](grade.mjs) · [Comparison fields](upstream/compare.mjs)

- `cases` is an array of records with `id`, `suite`, `revision`, `cve` and `callerScope`. Use unique IDs containing letters, digits, underscores or hyphens. Only the CVE and caller scope go to the CLI.
- `prepare(scenario, scratch, commitFixture)` creates a repository under `scratch` and returns `{ repo, sha }`. Call `commitFixture(repo)` on a fresh fixture directory to obtain a deterministic commit. The runner removes `scratch` after each attempt, including regrades.
- `validateSnapshot(scenario, repo, sha)` verifies the fixture, throws on invalid inputs and returns JSON evidence metadata for `results.json`.
- `gradeSnapshot(report, scenario, repo, sha, grader, { verifyClaimCitations, sourceReader })` returns `{ pass: boolean, ... }`. For each assessed use, call `verifyClaimCitations(report, use, sourceReader(repo, sha), sha, grader === "enabled")` to verify its citations. Return individual correctness fields to populate the comparison metrics.

### Run the historical skill

The standalone skill baseline supplies the historical caller questions for the original 23 cases. It runs the production attack-path skill with an isolated Codex home and a read-only checkout. Its own rubric checks the version, verdict and exact source quotations. Build the SDK and install its eval dependencies first. To evaluate a local adapter, append `-- COMMAND [ARG...]` to the skill command. The adapter reads the question on stdin and writes one JSON answer on stdout.

```sh
node --experimental-strip-types "$runner" --cache "$cache" --skill-baseline --jobs 3 --out "$outputs/skill"
```

A separate suite exercises launcher selection and catalog evidence on five fixtures. [Application mapping](../package-application-mapping/README.md)

## Local service and captured stack checks

`run.mjs` exercises the installed CLI against two small Git projects. Four cases supply measured stack evidence for a synthetic availability bug. Five cases check two configured services using the same public dependency.

| Case              | Inputs and deciding outcome                                                                                                                                                                                                                                                                                                                           |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `positive`        | An anonymous client sends a valid empty batch to a loopback summary service. The loaded sample-summary 0.2.0 library throws, terminating the disposable process. A separate health client can no longer connect. The packet ties the version and source commit to that process. Expect `exploitable` for a caller in the service's network namespace. |
| `fixed`           | The same application running sample-summary 0.2.1 sums an empty batch to zero and stays healthy. Expect `ruled_out` with a citation to the running version.                                                                                                                                                                                           |
| `unbound`         | Omit only the running source commit from the positive capture. Leave the affected version, original frames and source checkout intact. The report must identify the missing build-to-source link and leave the outcome `unknown` or `potentially_exploitable`.                                                                                        |
| `missing-version` | Omit the runtime binding entirely. A conclusive verdict fails the grade. The report must name the missing dependency version or copy.                                                                                                                                                                                                                 |
| `mixed-services`  | Run a repository CVE check for linkify-it. The configured notes service installs 5.0.0 and exposes its parser to request input. The reviews service installs fixed 5.0.2. Expect `potentially_exploitable` and `ruled_out` respectively, with citations specific to each build.                                                                       |
| `mixed-package`   | Run `check npm:linkify-it` against a fresh copy of the same project. Find the advisory inside the package report and grade both service decisions independently.                                                                                                                                                                                      |

The example summary package and CVE-2099-1001 are fictional. The external observer takes a V8 breakpoint inside the actual library during a request, verifies the running checkout and loaded module, and saves the frames in their original order. A fresh, uninstrumented process must produce the same HTTP results with the same requests. The expected answers, probe requests and probe outcomes stay outside the investigator inputs.

The runtime controls hold the CVE and Git checkout fixed. Three configure a read-only stdio MCP server through `exploitability.evidence_sources`. It returns synthetic build and request records. A confirmed verdict requires evidence that the affected copy ran and the caller reached its parser on that same service. The fixed reviews service should be `ruled_out` throughout.

| Case                       | Evidence for the notes service                                                                                          | Expected notes verdict    |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `mixed-services`           | Checkout and configured build                                                                                           | `potentially_exploitable` |
| `mixed-evidence-no-access` | The affected version ran at the target revision. Caller access is unresolved.                                           | `potentially_exploitable` |
| `mixed-evidence-sibling`   | The notes release matches. Querying for a notes request returns a request to reviews at the same revision.              | `potentially_exploitable` |
| `mixed-evidence`           | The affected version ran at the target revision. An anonymous caller sent text to its parser and received parsed links. | `exploitable`             |

The grader checks the cited service, tool, arguments, and exact response against the server's independent transcript in `source-calls.json`. Each response includes a freshly generated record ID so a report from an earlier run cannot stand in for a new lookup.

The mixed-services project uses the published linkify-it CVE-2026-48801, npm distribution URLs and integrity digests. Each service runs a shared handler using its own lockfile and Docker build argument. [Published advisory](https://github.com/advisories/GHSA-22p9-wv53-3rq4)

### Run the local checks

Use Node.js 22.13 or later, Git and a built CLI with the `@openai/codex-security/stack-packet` export. Point `CLI` to the JavaScript entry point of the installed package to test packed resources. For a local build use `sdk/typescript/bin/codex-security.mjs`. The runner sets `CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY=1` on its CLI processes. Live cases use OSV and the CLI's normal model credentials. Repository cases also use OpenGrep.

From the repository root, capture the ground truth and run the offline host contracts. Every `--out` path must be new. Omitting it creates a temporary output directory.

```sh
runner=evals/dependency-reachability/run.mjs
CLI=/absolute/path/to/node_modules/@openai/codex-security/bin/codex-security.mjs
outputs=$(mktemp -d)
node "$runner" behavior --out "$outputs/observed"
node "$runner" contracts --cli "$CLI" --packets "$outputs/observed/packets" --out "$outputs/contracts"
node --test evals/dependency-reachability/test-eval.mjs
```

The offline contract drives the public `run` commands from a scripted caller and checks a finalized fixed-version report against the original binding. It also alters the returned evidence and checks that the grader detects it. This measures the host and grader. The live run measures the model's investigation.

Run all cases through actual CLI sessions or select one with `--case positive`. Set `--model MODEL` to use the same model across builds. Supplying `--packets` reuses the original input bytes, frame order and timestamps. Each investigator still gets its own clean checkout. Without that option the suite takes new measurements.

```sh
node "$runner" live --cli "$CLI" --packets "$outputs/observed/packets" --out "$outputs/live"
node "$runner" live --case mixed-evidence --cli "$CLI" --out "$outputs/evidence"
node "$runner" live --case mixed-evidence-no-access --cli "$CLI" --out "$outputs/missing-access"
node "$runner" benchmark --cli "$CLI" --packets "$outputs/observed/packets" --out "$outputs/benchmark"
```

Select a `mixed-*` case to compare the two modes of the regular repository CLI. Each command runs in a fresh copy of the fixture. The independent eval checks service-specific source citations and verifies runtime records against that run’s MCP transcript in both modes. Check `progress.jsonl` for reviewer batches and `results.json` for the exact arguments.

```sh
for control in mixed-services mixed-evidence-no-access mixed-evidence-sibling mixed-evidence; do
  for grader in enabled disabled; do
    node "$runner" live --cli "$CLI" --case "$control" --grader "$grader" --out "$outputs/$control-$grader"
  done
done
```

Both live runners save `stderr.log` in each case's output directory. If the CLI exits unsuccessfully, they also save its stdout byte-for-byte in `stdout.log`, even when it produced no report. Both logs use file mode `0600`. Successful CLI runs save the finalized JSON for grading. The grader checks scope, original frame indices, Git source and capture citations, exact claim revisions, and the deciding evidence. For a live stack check it verifies the reviewed draft’s digest and approval for the assessed work item. For a repository or package check it also checks each service's selected lockfile and the claim's review state. The suite exits nonzero for an execution failure or a failed grade. A valid `unknown` conclusion is an assessment and is graded against its case. See `results.json` for the per-case status, source and fixture fingerprints and elapsed time.

The benchmark initializes five fresh SQLite attempts. Each timed trial writes one batch of ten source-backed claims and reads them back in another CLI process. It checks all ten IDs, revisions, hashes and payloads and records the median, including CLI startup time. Fixture preparation and state initialization take place before timing.
