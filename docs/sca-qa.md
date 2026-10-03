# SCA MVP implementation and QA

The additive SDK entry point is
`security.scanDependencies({ repositoryPath, outputDir, auth, signal, maxCostUsd })`.
The MVP covers the [supported language/file matrix](../sdk/typescript/README.md#dependency-assessment-sca-mvp), retains OSV evidence,
performs static application assessment, and produces a report, conservative
base/head comparison, and developer-selected update handoff.
See [the runnable examples](../examples/sca/README.md).

## Verification

Focused checks rerun on Linux on October 2, 2026:

| Check                          | Observed result                                                                                                           |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| Focused SDK regressions        | 307 tests passed: input formats, adapter, orchestration, schemas, partial assessment, reports, comparisons, and handoffs. |
| Deterministic SCA evaluation   | 28 tests passed.                                                                                                          |
| Portable plugin compatibility  | Source check and all 9 checker tests passed.                                                                              |
| Python source checks           | Ruff 0.16.8 lint and format checks passed.                                                                                |
| SDK compilation and formatting | `build`, `build:ci`, `types`, and `format` passed.                                                                        |

Earlier implementation checks remain recorded below; they were not rerun in
this follow-up:

| Check                      | Observed result                                                                                                    |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Actual OSV-Scanner v2.6.0  | 104 offline synthetic contract cases passed under Node 24; 103 under Bun 1.3.14.                                   |
| Built examples             | Syntax checks passed; comparison and handoff runners worked against a synthetic SDK result.                        |
| Live SDK/model integration | One synthetic assessment completed, retained its advisory match, and saved all four artifacts with no diagnostics. |
| Live evaluation smoke      | Six correct synthetic verdicts; five of six strict citation assertions passed.                                     |

Package-wide validation and the latest CI results are recorded with the pull
request. The checks above describe the implementation and its focused contracts.

The added ecosystem contracts cover Python, Go, Rust, Java/Kotlin, Ruby, PHP,
and .NET alongside JavaScript/TypeScript. Tests verify vulnerable and fixed
versions, local origins, explicit exclusions, mixed repositories, and coverage
limits. SDK orchestration tests exercise each ecosystem through persisted
artifacts and the model prompt. Requirements and Maven declarations remain
partial; Maven parent projects, requirement includes, and older Go module
formats are not treated as complete inventories. Legacy or missing Go directives
with a usable modern toolchain retain matching but remain partial because indirect
requirements may be absent. Composer short-commit skips retain inventory while
marking matching incomplete. Multi-input tests verify per-invocation artifacts
are retained immediately and combined artifacts are written on completion or
interruption, including a 400-input case.

The live SDK smoke used a synthetic scanner executable and a real Codex session.
The separate pinned OSV tests exercised the real scanner against a fictional
offline database. These verify distinct parts of the pipeline and are not a
public-advisory accuracy study. See [evaluation QA](../evals/triage-finding/sca/QA.md)
for the six-call smoke measurements and its citation failure.

The live SDK smoke identified two integration requirements now covered by
regressions: Codex structured output needs explicit types and required object
properties, and sandboxed shell tools need the native executable directory as a
read-only runtime root. The canonical triage parser remains compatible with its
existing v0 contract. A further QA regression ensures the saved run remains
partial while assessments are pending; completed assessments cannot promote
incomplete matching coverage to a completed run. Static assessments compare the
existing source snapshots before inventory and after model output; changed or
unavailable source context retains scanner facts without accepting a completed
assessment.

Actual OSV failure cases included exit 127 with retained inventory for a missing
local database and exit 130 with retained matches for invalid configuration.
Both remain incomplete. Git submodule inventory is explicitly incomplete;
case-only directory aliases preserve tracked lockfiles. A Git lookup failure in a
checkout fails inventory rather than falling back to filesystem enumeration;
ordinary non-Git directories remain supported. Local and direct URL
origins remain unresolved while public npm registry tarball URLs retain registry
matching. Unchanged OSV configuration cannot turn conditional exclusions into
resolution claims. Nested-source tests also verify that unused root
configuration cannot abort matching or hide missing inventory. The Composer
short-commit case returns exit zero despite skipped matching; retained diagnostics
keep that result incomplete.

## Reproduce

Use the repository's normal Node/Bun/pnpm setup and install OSV-Scanner v2.6.0
separately. The deterministic suites need no model or network:

```sh
pnpm --dir sdk/typescript run build:plugin
cd sdk/typescript
bun test --timeout 30000 tests-ts/sca.test.ts tests-ts/sca-*.test.ts
bun scripts/check-sca-osv-contract.mts /path/to/osv-scanner
cd ../..
node --test evals/triage-finding/sca/scripts/test-sca.js
```

The scanner harness constructs fictional advisory data without installing or
executing dependency code. Run the package and portable plugin checks specified
in [SDK instructions](../sdk/typescript/AGENTS.md) and
[root instructions](../AGENTS.md) before publication.

## Remaining evaluation

Bun 1.3.14 has a reproduced `realpath` limitation for literal backslashes in
POSIX filenames. The real-scanner harness skips only that native-path case for
that Bun version; it passes under Node 24, and the normalization regression stays
enabled on both runtimes.

Portable tests exercise Windows paths. The synthetic cancellation regression
polls for retained stdout and stderr with a deadline, then checks that both
survive cancellation. Cleanup always aborts and settles the child, which also
has a finite lifetime. Validate this behavior in native Windows and macOS CI.

The twelve-case model corpus is JavaScript-focused and has no independent
human labels. Multilingual scanner and orchestration tests do not establish
per-language model assessment accuracy. The planned
90-case adjudicated corpus and 5–8-developer update pilot require further study.
No production accuracy, automatic-dismissal safety, or developer-productivity
claim is established. The small live smoke retains its baseline citation failure,
and the product preserves advisory matches regardless of model assessment.
