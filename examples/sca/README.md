# Dependency assessment example

Install [OSV-Scanner v2.6.0](https://github.com/google/osv-scanner/releases/tag/v2.6.0)
on your PATH separately. With Codex Security installed, run:

```sh
cs scan dependencies /path/to/repository \
  --output-dir /path/outside/repository/sca-result --max-cost 5
```

Omit the repository to use the current directory. Omit `--output-dir` to save
artifacts in a persistent directory under the Codex Security state root. Add
`--json` for structured stdout; the default summary and diagnostics go to stderr.
The command uses the existing `--auth`, `--model`, `--effort`, and provider/runtime
settings. See the [command options](../../sdk/typescript/docs/cli.md#dependency-command-options)
for supported settings and rejected source-scan options. To scan source in a
directory named `dependencies`, use `cs scan ./dependencies`.

To run the SDK example from this checkout, build it first:

```sh
pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir sdk/typescript run build:plugin
pnpm --dir sdk/typescript run build
node examples/sca/run.mjs /path/to/repository /path/outside/repository/sca-result
```

Use a new or empty output directory outside the repository and its enclosing Git
worktree. Node 24 or 26 supports the SDK example's
`await using` syntax. The SDK also supports Node 22; use `try/finally` and
`await security.close()` there. The existing Codex authentication and SDK model
configuration apply. Complete scans without advisory matches do not need Codex
authentication. OSV queries its advisory service with package identities;
repository source is not uploaded to OSV. Model assessment follows the existing
Codex provider configuration.

The same SDK workflow handles JavaScript/TypeScript, Python, Go, Rust,
Java/Kotlin, Ruby, PHP, and .NET dependency files, including mixed repositories.
See the [supported file matrix and limitations](../../sdk/typescript/docs/cli.md#dependency-assessment-sca-mvp).
Untracked Git-ignored files and node_modules are outside inventory. Unsupported
inputs and unresolved local/Git/URL identities leave coverage incomplete.
Requirements and Maven manifest results explicitly retain partial coverage;
projects are never built to discover dependencies. OSV configuration exclusions
remain in effect and are described in the report. The scanner does not provide
a full dependency graph or package introduction chain.

Supported file formats describe inventory coverage, not demonstrated model
accuracy for each language. Applicability assessments are static reviews, not
verified function-call graphs.

Read `report.md` and `sca-result.json`. Raw scanner stdout and diagnostics are
`osv-output.json` and `osv-stderr.log`. Every advisory match remains visible,
including assessments marked `not_actionable`, unavailable, or cancelled.
`needs_review` is a completed uncertain assessment; `failed` means no valid
assessment was available. Static assessment neither reproduces vulnerabilities
nor changes dependencies.

Start with the report's run, matching-coverage, and assessment summaries and its
diagnostics. Zero matches with incomplete coverage do not establish a clean
repository. Assessment does not run when no matches were retained, and an
unreported model cost is not a measured zero-dollar result. The existing
`maxCostUsd` option interrupts on estimated assessment cost across turns; it is
not a hard billing ceiling.

The CLI and SDK example runner return 0 for complete execution, including
advisory matches, and 2 for partial/failed execution. The CLI also returns 2 for
invalid inputs and budget stops, and 130/143 for SIGINT/SIGTERM interruptions.
[ci.yml](ci.yml) shows artifact-only CLI steps;
provide the normal build, scanner installation, and authentication setup in the
surrounding job. There is no automatic merge gate or publication.

For separate base/head checkouts:

```sh
node examples/sca/compare.mjs /path/base/sca-result.json /path/head/sca-result.json
```

Comparison correlates aliases and repository-relative lockfile paths, preserving
multiple versions and ambiguous cases. `newlyObserved` retains all head-only
matches; `introduced` contains them only when the scans are comparable. Live OSV
runs do not share a frozen advisory snapshot, so they cannot establish
introduction or resolution. Incomplete coverage or changed configuration also
prevents those claims. Disappeared matches remain in `noLongerObserved` with
`resolved: false` until comparability is established.

Select match IDs from `sca-result.json` for a deliberate update request:

```sh
node examples/sca/handoff.mjs /path/sca-result.json /path/new-handoff match-id
cd /path/to/repository
codex-security patch /path/new-handoff/issues.md --validation-prompt-file /path/new-handoff/validation.md
```

Review the handoff before patching. Fixed versions are advisory candidates, not
verified compatible upgrades. Identify the owning direct dependency from the
package manager, resolve the lockfile, rerun OSV matching, and run the repository's
normal build/type/test checks. Record which checks passed or were unavailable.
