# Dependency reachability eval

This suite runs the installed dependency exploitability CLI against two small Git projects. One supplies measured stack evidence for a synthetic availability bug. The other tests how the independently reviewed workflow distinguishes two configured deployments of the same public dependency. The grader lives outside both checkouts.

| Case              | Inputs and deciding outcome                                                                                                                                                                                                                                                                                                                           |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `positive`        | An anonymous client sends a valid empty batch to a loopback summary service. The loaded sample-summary 0.2.0 library throws, terminating the disposable process. A separate health client can no longer connect. The packet ties the version and source commit to that process. Expect `exploitable` for a caller in the service's network namespace. |
| `fixed`           | The same application running sample-summary 0.2.1 sums an empty batch to zero and stays healthy. Expect `ruled_out` with a citation to the running version.                                                                                                                                                                                           |
| `unbound`         | Omit only the running source commit from the positive capture. Leave the affected version, original frames and source checkout intact. The report must identify the missing build-to-source link and leave the outcome `unknown` or `potentially_exploitable`.                                                                                        |
| `missing-version` | Omit the runtime binding entirely. A conclusive verdict fails the grade. The report must name the missing dependency version or copy.                                                                                                                                                                                                                 |
| `mixed-services`  | Run a repository CVE check for linkify-it. The configured notes service installs 5.0.0 and exposes its parser to request input. The reviews service installs fixed 5.0.1. Expect `potentially_exploitable` and `ruled_out` respectively, with citations specific to each build.                                                                       |
| `mixed-package`   | Run `check npm:linkify-it` against a fresh copy of the same project. Find the advisory inside the package report and grade both service decisions independently.                                                                                                                                                                                      |

The example summary package and CVE-2099-1001 are fictional. The external observer takes a V8 breakpoint inside the actual library during a request, verifies the running checkout and loaded module, and saves the frames in their original order. A fresh, uninstrumented process must produce the same HTTP results with the same requests. The expected answers, probe requests and probe outcomes stay outside the investigator inputs.

The `mixed-evidence` case uses the same checkout as `mixed-services` and configures a read-only stdio MCP server through `exploitability.evidence_sources`. The server returns synthetic observations for the notes service. One lookup identifies the running revision and package, and another records an anonymous client's request to the parser. The expected verdicts are `exploitable` for notes and `ruled_out` for reviews. In `mixed-evidence-no-access`, the server still reports the running build but has no record of a client request. The expected notes verdict becomes `potentially_exploitable`.

The grader checks the cited service, tool, arguments, and exact response against the server's independent transcript in `source-calls.json`. Each response includes a freshly generated record ID so a report from an earlier run cannot stand in for a new lookup.

The mixed-services project uses the published linkify-it CVE-2026-48801, npm distribution URLs and integrity digests. Each service runs a shared handler using its own lockfile and Docker build argument. The checkout establishes the configured build. The two evidence-source cases supply the additional observations through MCP. [Published advisory](https://github.com/advisories/GHSA-22p9-wv53-3rq4)

## Run

Use Node.js 22.13 or later, Git and a built CLI with the `@openai/codex-security/stack-packet` export. Point `CLI` to the JavaScript entry point of the installed package to test packed resources. For a local build use `sdk/typescript/bin/codex-security.mjs`. The runner sets `CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY=1` on its CLI processes. The live repository cases also use OSV, OpenGrep and the CLI's normal model credentials.

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

Both live runners save `stderr.log` in each case's output directory. If the CLI exits unsuccessfully, they also save its stdout byte-for-byte in `stdout.log`, even when it produced no report. Both logs use file mode `0600`. Successful CLI runs save the finalized JSON for grading. The grader checks scope, original frame indices, Git source and capture citations, exact claim revisions, and the deciding evidence. For a package or CVE check it also checks independent claim approval and each service's selected lockfile. The suite exits nonzero for an execution failure or a failed grade. A valid `unknown` conclusion is an assessment and is graded against its case. See `results.json` for the per-case status, source and fixture fingerprints and elapsed time.

The benchmark initializes five fresh SQLite attempts. Each timed trial writes one batch of ten source-backed claims and reads them back in another CLI process. It checks all ten IDs, revisions, hashes and payloads and records the median, including CLI startup time. Fixture preparation and state initialization take place before timing.

## Pinned upstream suites

The optional suites materialize 23 source snapshots and run ordinary reviewed CVE checks. A caller scope is supplied through the public project config, `exploitability.scope.instructions`. Each isolated checkout combines a pinned upstream source tree and the selected synthetic application or build files. The CLI never receives a case ID, expected verdict or grading rubric.

| Suite        | Cases | What changes                                                                                                                                                                  |
| ------------ | ----: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mailparser` |    16 | Direct and queued parsing, disabled or unmounted routing, an external recipient, a backported address parser, filtered headers, MIME-part promotion and ZIP extraction paths. |
| `pillow`     |     6 | WebP decode versus encode, official wheel selection, a backported system library, and which library copy a synthetic worker has loaded.                                       |
| `backstage`  |     1 | Which inputs the configured task API, catalog, template and skeleton actually expose to the sandboxed operation.                                                              |

The SHA-256 manifest pins five GitHub archives by full revision, ten selected upstream files and two published npm archives. Snapshot preparation also checks the MIME packages' lockfile SHA-512 integrity and individual file hashes. Upstream source is staged as inert evidence. The checkout's dependency installation scripts and application code are never executed by the snapshot builder. The published wheel manifests describe the exact wheel artifacts in those cases. Rollout records and application overlays are synthetic.

Fetch the sources once into a local cache (about 226 MiB). This optional step uses Python 3.12 or later with HTTPS access to GitHub and npm. Snapshot assembly and verification then work offline. Live runs use the selected CLI's OSV access, OpenGrep and model credentials.

```sh
cache=$(mktemp -d)
python3 evals/dependency-reachability/upstream/assets.py fetch "$cache"
node evals/dependency-reachability/upstream.mjs --cache "$cache" --prepare-only
node evals/dependency-reachability/upstream.mjs --cache "$cache" --suite mailparser --cli "$CLI"
node evals/dependency-reachability/upstream.mjs --cache "$cache" --case fixed-decode --cli "$CLI"
node evals/dependency-reachability/upstream.mjs --cache "$cache" --case task-parameter --cli "$CLI"
```

To regrade saved CLI reports, pass `--grade-existing RESULTS_DIR` instead of `--cli PATH`. This re-creates the pinned Git source and preserves the original report bytes.

With no selector, the upstream runner evaluates all 23 cases sequentially. `--help` lists their IDs. `--prepare-only` verifies materialization and every required evidence group against the generated Git commit. A live case checks one assessed location's identity, expected version, deciding source citations, caller-specific conditions and claim approval. Alternatives within an evidence group are equivalent. All groups must be supported by the same assessed use. The expected distribution is nine `potentially_exploitable`, twelve `ruled_out` and two `unknown`. It describes the rubric; actual per-case scores and execution failures are recorded when the suite runs.

### Compare investigator and skill runs

Use the same cache, model, and case IDs for both CLI builds. Each case has an isolated checkout. `sourceSha` identifies the complete staged checkout, including the synthetic application. The output includes execution failures and full-rubric grades. The grader requires a captured checkout trace of the target dependency and validates the scope, timestamps, outcome and completeness of its search audit.

```sh
runner=evals/dependency-reachability/upstream.mjs
node "$runner" --cache "$CACHE" --cli "$OLD_CLI" --model "$MODEL" --jobs 3 --out "$OUT/original"
node "$runner" --cache "$CACHE" --cli "$NEW_CLI" --model "$MODEL" --jobs 3 --out "$OUT/candidate"
```

To run the standalone attack-path skill baseline, build the SDK and install its eval dependencies, then run the following command. It uses each case’s historical caller question, the production skill, an isolated Codex home, and an offline read-only checkout. The baseline answer contains a version, verdict, reason and exact source quotations. Its grader checks the submitted quotes against the pinned Git blobs. The saved prompt digest and checkout SHA identify the inputs. Reviewed CLI grades use the separate per-use evidence rubric.

```sh
node --experimental-strip-types "$runner" --cache "$CACHE" --skill-baseline --model "$MODEL" --jobs 3 --out "$OUT/skill"
```

The [application mapping suite](../package-application-mapping/README.md) exercises launcher selection and catalog evidence on five further fixtures.

To compare a local adapter with the skill, run the same `--skill-baseline` command and append `-- COMMAND [ARG...]`. The process receives the question on stdin in the staged checkout and returns the same JSON answer on stdout.
