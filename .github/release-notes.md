<!-- release-version: 0.3.0 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security Local 0.3.0 reduces unnecessary work in Deep Scan, includes more
source files, and makes scan exit codes easier to use in scripts. It also improves
recovery when scans are interrupted.

- Deep Scan waits for earlier results to be checked before starting more reviews,
  avoiding extra reviews when it already has enough information to stop. Fresh
  API-key and Amazon Bedrock scans also skip a model step during startup when
  using the bundled plugin and default Node runtime.
  ([#1630](https://github.com/openai/codex-security/pull/1630),
  [#1555](https://github.com/openai/codex-security/pull/1555))
- Source selection now includes text files without recognized extensions, build
  and test files, and JSP and ASP.NET templates. Fixes also preserve unusual
  filenames and the original contents of saved Git-diff and directory scans.
  ([#1347](https://github.com/openai/codex-security/pull/1347),
  [#1414](https://github.com/openai/codex-security/pull/1414),
  [#1345](https://github.com/openai/codex-security/pull/1345),
  [#1280](https://github.com/openai/codex-security/pull/1280))
- Resumed scans preserve their original knowledge context, model/provider
  settings, and selected paths. Interrupted scans retain usable results, and
  Deep Scan cancellation waits for worker cleanup and state updates before
  returning. Exhausted usage stops workers instead of triggering more retries.
  ([#1556](https://github.com/openai/codex-security/pull/1556),
  [#1501](https://github.com/openai/codex-security/pull/1501),
  [#1602](https://github.com/openai/codex-security/pull/1602),
  [#1260](https://github.com/openai/codex-security/pull/1260),
  [#1638](https://github.com/openai/codex-security/pull/1638))
- The terminal dashboard batches updates during busy scan replays and avoids
  rereading unchanged logs. It shows token usage even when pricing is unavailable
  for the selected model. Cost reporting adds Cyber pricing, restores GPT-6 Sol
  estimates, and includes Codex context-compaction usage.
  ([#1276](https://github.com/openai/codex-security/pull/1276),
  [#1336](https://github.com/openai/codex-security/pull/1336),
  [#1585](https://github.com/openai/codex-security/pull/1585),
  [#1590](https://github.com/openai/codex-security/pull/1590))

### Scan exit codes

Coverage warnings no longer turn a completed scan into a failure. Deep Scans can
also finish when an optional detailed writeup is missing; the findings remain
in the report.

| Exit code | Meaning                                                             |
| --------- | ------------------------------------------------------------------- |
| `0`       | The scan completed without a configured severity-threshold failure. |
| `1`       | Findings met the configured `--fail-on-severity` threshold.         |
| `2`       | Execution, result integrity, or required output failed.             |

A successful exit does not mean every file was reviewed. Check coverage details
when your workflow requires that information.
([#1633](https://github.com/openai/codex-security/pull/1633),
[#1624](https://github.com/openai/codex-security/pull/1624))

### Other CLI and SDK additions

- Use `cs` as a shorter alias for `codex-security`. Policy drafting now
  works when Codex is installed under your home directory, and app clients can
  rename and search saved scans.
  ([#1415](https://github.com/openai/codex-security/pull/1415),
  [#1416](https://github.com/openai/codex-security/pull/1416),
  [#1180](https://github.com/openai/codex-security/pull/1180))
- Generate and verify fixes from TypeScript with `security.patch()`, using
  the SDK client's authentication, model settings, and cancellation support.
  Your application controls review, commits, and publication. When you request a
  pull request for a supplied issue, CLI results now include its branch and URL.
  ([#1635](https://github.com/openai/codex-security/pull/1635),
  [#1645](https://github.com/openai/codex-security/pull/1645))
- Owner suggestions prefer committed CODEOWNERS before falling back to Git
  history. In Codex, the new `$cloud-findings` skill reads findings, reports,
  and recorded validation from existing Codex Security Cloud scans.
  ([#1519](https://github.com/openai/codex-security/pull/1519),
  [#1422](https://github.com/openai/codex-security/pull/1422))

Other fixes cover GitLab merge-request publication, Windows process launch and
network-share database paths, configuration errors, YAML error messages, and
plugin integrity checks after Python creates cache files. The package includes
Codex CLI/SDK 0.162.1. Display names now say **Codex Security Local**; the package
remains `@openai/codex-security`.

## GitHub Action

A new GitHub Action runs repository and pull-request scans in CI. Set the source
scope and time and cost budgets, review job summaries, and download saved results.
You can upload findings to GitHub code scanning as SARIF and fail a job at a
chosen severity.

The initial Action supports GitHub.com, Linux x64 runners, and API-key
authentication. Action releases follow the verified npm release. See the
[Action guide](https://github.com/openai/codex-security/blob/npm-v0.3.0/github-action/README.md).
([#1015](https://github.com/openai/codex-security/pull/1015),
[#1418](https://github.com/openai/codex-security/pull/1418))

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

Read the sections that apply to your scripts, saved scans, or integrations before
updating from 0.2.0.

### Scripts and integrations that read scan results

If you consume scan JSON or SDK types, replace `coverage.completeness`,
`CoverageCompleteness`, bulk/component `incomplete` counters, comparison
`comparable`, and Action `scan-status: incomplete` handling with
`manifest.scan.status` and exit codes. Action `scan-status` now uses
`completed`, `failed`, or `skipped`. If a later scan does not find a previously
reported finding in the code it scanned, comparison returns `not_observed`.
Excluded paths and uncertain matches remain `unknown`; `resolved` requires
explicit closure as already fixed.

New drafts, imports, worker output, and custom-validation results must use the
current `codeEvidence`, `rootCause`, `attackPath.dataflow`, and
`evidenceRefs` fields. Migrate unfinished drafts or finish them with their
original version. Completed historical reports remain readable and exportable.
([#1633](https://github.com/openai/codex-security/pull/1633))

### Standalone validation

`validate` now assesses source in a read-only sandbox. It does not build or
execute the target, run tests or proofs of concept, or contact services.
Save the assessment from CLI stdout or SDK `result.report`; the validator
no longer writes report files:

```bash
codex-security validate findings.json > assessment.md
```

Run a separate reproduction when you need runtime proof. Validation within
Standard, Deep, and Diff scans keeps its existing behavior.
([#1423](https://github.com/openai/codex-security/pull/1423))

### Resuming existing scans

Keep the private `.scan-knowledge.json` file with scan artifacts. Resume
uses this captured knowledge-base context even if the original documents change
or disappear. Older individual scans that used knowledge bases but lack this
snapshot require a new scan. Scans without knowledge bases and bulk scans with
captured context remain resumable. Reruns use current inputs.
([#1556](https://github.com/openai/codex-security/pull/1556))

Reading compressed `.jsonl.zst` sessions requires Node 22.15+ within 22.x,
or Node 24/26. Node 22.13–22.14 still supports plain logs but cannot resume
compressed sessions.
([#1428](https://github.com/openai/codex-security/pull/1428))

### Owner suggestion consumers

The owner-suggestion JSON report now uses `schemaVersion: 2`. Owners can be GitHub users, teams, or
email-only identities. Check for a non-null owner, then use `"handle" in owner`
before reading `owner.handle` or `owner.email`. Do not assume every owner
has a Git name/email pair.
([#1519](https://github.com/openai/codex-security/pull/1519))

### Installation and Windows settings

Global installs now create the `cs` alias. If npm reports `EEXIST`
because another tool owns that name, use `npx @openai/codex-security`.
Windows defaults to the elevated sandbox backend and honors an explicit backend
selection.
([#1415](https://github.com/openai/codex-security/pull/1415),
[#1281](https://github.com/openai/codex-security/pull/1281))

### Custom plugins and direct helper users

Upgrade custom plugins to the current archive/comparison protocols. New and
resumed Deep scans also require `directDeepScanEngine: 1`,
`workerProviderSnapshot: 4`, and isolated workers. Alternatively, omit
`pluginPath`/`--plugin-path` to use
the bundled plugin. Replace direct `node ./mcp/server.mjs` launches with
the current plugin launcher.

For retained findings-storage and severity operations, replace direct calls to
retired Python helpers with
`scripts/launch_codex_security_mcp --helper COMMAND` (the `.cmd` launcher
on Windows). Pass JSON on stdin with an absolute `stateDirectory` and the
helper payload. Normal CLI/SDK callers need no helper migration. The selected
state directory must be writable; the temporary-state fallback is removed.
See the [SDK compatibility notes](https://github.com/openai/codex-security/blob/npm-v0.3.0/sdk/typescript/README.md)
and [helper reference](https://github.com/openai/codex-security/blob/npm-v0.3.0/sdk/typescript/docs/findings-service.md#direct-storage-helpers).
([#1548](https://github.com/openai/codex-security/pull/1548),
[#1408](https://github.com/openai/codex-security/pull/1408),
[#1543](https://github.com/openai/codex-security/pull/1543))

### Local deduplication and findings service removal

Saved-scan deduplication now uses local SQLite storage by default, without a
running service. It caches embeddings and review progress so interrupted work
can resume.

The `serve` command, its `--port` option, `start:server`,
`startFindingsServer`, browser dashboard, and findings-service Compose
deployment are removed. Use `codex-security dedupe --scan SCAN_ID` locally, or supply `--findings-url` for an independently hosted compatible
service.

Keep existing state directories and volumes. Select the local database through
`CODEX_SECURITY_STATE_DIR`; a separate service volume is not selected
automatically. Generating or refreshing embeddings with the built-in embedder
requires an API key. The `@openai/codex-security/server` entrypoint retains
its storage and embedding exports. See the
[findings guide](https://github.com/openai/codex-security/blob/npm-v0.3.0/sdk/typescript/docs/findings-service.md).
([#1340](https://github.com/openai/codex-security/pull/1340),
[#1338](https://github.com/openai/codex-security/pull/1338))

<!-- release-section: upgrades:end -->
