<!-- release-version: 0.3.0 -->

<!-- release-section: highlights:start -->

## Highlights

- Automate repository and pull-request scans with the new
  [GitHub Action](https://github.com/openai/codex-security/blob/npm-v0.3.0/github-action/README.md).
  It supports explicit scope and budgets, job summaries, saved artifacts, and
  optional SARIF uploads. Action releases follow the verified npm release.
  ([#1015](https://github.com/openai/codex-security/pull/1015),
  [#1418](https://github.com/openai/codex-security/pull/1418))
- Use `cs` as a shorter alias for `codex-security`. Policy onboarding works
  better with global installs, and display surfaces now use the name
  **Codex Security Local**. Package and command names remain available.
  ([#1415](https://github.com/openai/codex-security/pull/1415),
  [#1416](https://github.com/openai/codex-security/pull/1416),
  [#1644](https://github.com/openai/codex-security/pull/1644))
- Deduplicate saved scans directly against local SQLite storage without running
  a findings service. Explicit remote endpoints remain supported. Owner
  suggestions now consult committed CODEOWNERS before falling back to Git history.
  ([#1338](https://github.com/openai/codex-security/pull/1338),
  [#1519](https://github.com/openai/codex-security/pull/1519))
- Generate patches from TypeScript with `security.patch()`. CLI results now
  include pull-request details for supplied-issue patches. The new `$cloud-findings`
  skill reads saved Cloud findings in Codex, and GitLab patch publication now
  creates merge requests correctly.
  ([#1635](https://github.com/openai/codex-security/pull/1635),
  [#1645](https://github.com/openai/codex-security/pull/1645),
  [#1422](https://github.com/openai/codex-security/pull/1422),
  [#817](https://github.com/openai/codex-security/pull/817))
- Deep Scans using API keys or Amazon Bedrock run through the direct coordinator.
  Discovery, reducer, and resumed workers preserve per-scan providers,
  endpoints, permissions, executables, context limits, and request attribution.
  Scope survives recovery, replaced coordinators cannot overwrite results, and
  exhausted usage stops workers.
  ([#1555](https://github.com/openai/codex-security/pull/1555),
  [#1281](https://github.com/openai/codex-security/pull/1281),
  [#1501](https://github.com/openai/codex-security/pull/1501),
  [#1424](https://github.com/openai/codex-security/pull/1424),
  [#1602](https://github.com/openai/codex-security/pull/1602),
  [#916](https://github.com/openai/codex-security/pull/916),
  [#1638](https://github.com/openai/codex-security/pull/1638))
- Scans include text source regardless of extension, including build and test
  files and additional server templates. Source excerpts, unusual Git paths,
  scoped inventories, and directory snapshots retain the selected target's
  contents and provenance.
  ([#1347](https://github.com/openai/codex-security/pull/1347),
  [#1414](https://github.com/openai/codex-security/pull/1414),
  [#1345](https://github.com/openai/codex-security/pull/1345),
  [#1063](https://github.com/openai/codex-security/pull/1063),
  [#1280](https://github.com/openai/codex-security/pull/1280),
  [#1288](https://github.com/openai/codex-security/pull/1288))
- Interrupted scans retain usable results, history, publication outcomes, and
  cancellation state. Resume preserves captured knowledge context; scan activity
  can read compressed Codex session logs. Progress displays show active reviews,
  consolidation, and observed usage.
  ([#1269](https://github.com/openai/codex-security/pull/1269),
  [#1270](https://github.com/openai/codex-security/pull/1270),
  [#1260](https://github.com/openai/codex-security/pull/1260),
  [#1556](https://github.com/openai/codex-security/pull/1556),
  [#1428](https://github.com/openai/codex-security/pull/1428),
  [#1253](https://github.com/openai/codex-security/pull/1253),
  [#1276](https://github.com/openai/codex-security/pull/1276))
- Standalone validation produces a source-only assessment and supports supplied
  context, knowledge bases, and an optional output schema. Completed scan status
  now describes execution separately from coverage warnings and optional writeups.
  ([#1423](https://github.com/openai/codex-security/pull/1423),
  [#1633](https://github.com/openai/codex-security/pull/1633),
  [#1624](https://github.com/openai/codex-security/pull/1624))
- The package includes Codex CLI/SDK 0.162.1 and dependency updates. Cost reporting
  supports Cyber pricing and GPT-6 Sol estimates, and omits unavailable prices.
  Windows process launch, UNC database reads, configuration errors, YAML
  diagnostics, and plugin integrity after Python cache creation are fixed.
  ([#1563](https://github.com/openai/codex-security/pull/1563),
  [#1336](https://github.com/openai/codex-security/pull/1336),
  [#1585](https://github.com/openai/codex-security/pull/1585),
  [#1601](https://github.com/openai/codex-security/pull/1601),
  [#1648](https://github.com/openai/codex-security/pull/1648),
  [#1634](https://github.com/openai/codex-security/pull/1634),
  [#1613](https://github.com/openai/codex-security/pull/1613),
  [#1625](https://github.com/openai/codex-security/pull/1625))

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

This is a breaking release under the pre-1.0 version policy. Review these changes
before updating integrations from 0.2.0.

- **Scan outcomes and findings contracts:** completed scans return exit code
  `0`; a configured `--fail-on-severity` threshold returns `1`; execution,
  integrity, or required-output failures return `2`. Coverage warnings and
  missing optional reports do not make a completed scan fail. Replace consumers
  of `coverage.completeness`, `CoverageCompleteness`, bulk/component
  `incomplete` counters, comparison `comparable`, or Action
  `scan-status: incomplete` with execution status and exit-code handling.
  A finding absent from a later scan is `not_observed`; `resolved` requires
  explicit closure as already fixed. New drafts, imports, worker output, and
  custom-validation results must use current `codeEvidence`, `rootCause`,
  `attackPath.dataflow`, and `evidenceRefs` fields. Migrate unfinished drafts
  or finish them with their original version; sealed historical reports remain
  readable and exportable.
  ([#1633](https://github.com/openai/codex-security/pull/1633))
- **Local findings service removal and deduplication:** `serve`, its
  `--port` option, `start:server`, `startFindingsServer`, the browser
  dashboard, and the findings-service Compose deployment are removed.
  Keep existing state directories and volumes; select the existing local database
  with `CODEX_SECURITY_STATE_DIR` and use `dedupe --scan SCAN_ID`.
  Local deduplication does not automatically read a separate service volume and
  requires an API key when embeddings must be generated or refreshed.
  Use an explicit `--findings-url` for an independently hosted compatible
  service. The `@openai/codex-security/server` entrypoint retains its storage
  and embedding exports. See the
  [findings guide](https://github.com/openai/codex-security/blob/npm-v0.3.0/sdk/typescript/docs/findings-service.md).
  ([#1340](https://github.com/openai/codex-security/pull/1340),
  [#1338](https://github.com/openai/codex-security/pull/1338))
- **Custom plugins and direct helpers:** upgrade custom plugins to the current
  archive/comparison protocols and Deep Scan capabilities
  `directDeepScanEngine: 1`, `workerProviderSnapshot: 4`, and isolated
  workers, or omit `pluginPath`/`--plugin-path` to use the bundled plugin.
  Replace direct `node ./mcp/server.mjs` launches with the plugin's launcher.
  Direct users of retired Python findings and severity helpers must use
  `scripts/launch_codex_security_mcp --helper COMMAND` (the `.cmd`
  launcher on Windows), with JSON stdin containing an absolute
  `stateDirectory` and the helper payload. Normal CLI/SDK callers need no
  helper migration. The selected state directory must be writable; the
  temporary-state fallback is removed. See the
  [SDK compatibility notes](https://github.com/openai/codex-security/blob/npm-v0.3.0/sdk/typescript/README.md)
  and [direct storage helpers](https://github.com/openai/codex-security/blob/npm-v0.3.0/sdk/typescript/docs/findings-service.md#direct-storage-helpers).
  ([#1548](https://github.com/openai/codex-security/pull/1548),
  [#1408](https://github.com/openai/codex-security/pull/1408),
  [#1543](https://github.com/openai/codex-security/pull/1543))
- **Resuming scans with knowledge bases:** retain the private
  `.scan-knowledge.json` file alongside scan artifacts. Resume uses captured
  context even if original documents change or disappear. Older individual
  knowledge-bearing scans without that snapshot require a new scan; scans
  without knowledge bases and bulk scans with captured context remain resumable.
  Reruns use current inputs.
  ([#1556](https://github.com/openai/codex-security/pull/1556))
- **Owner suggestions:** accept `schemaVersion: 2` and GitHub user/team
  handles or email-only owners. After checking an owner is non-null, use
  `"handle" in owner` before accessing `owner.handle` or `owner.email`;
  do not assume every owner has a Git name/email pair. Committed CODEOWNERS
  takes priority over Git history.
  ([#1519](https://github.com/openai/codex-security/pull/1519))
- **Standalone validation:** `validate` now assesses source without executing
  the target, using network or web search, or writing a report into the target.
  Save CLI stdout or SDK `result.report`; run a separate reproduction when
  runtime proof is needed. Standard, Deep, and Diff scan validation workflows
  retain their existing behavior. See the
  [validation reference](https://github.com/openai/codex-security/blob/npm-v0.3.0/sdk/typescript/docs/cli.md#validate-and-patch-findings).
  ([#1423](https://github.com/openai/codex-security/pull/1423))
- **Runtime and installation details:** reading compressed `.jsonl.zst`
  sessions requires Node 22.15+ within 22.x, or Node 24/26. Node 22.13–22.14
  continues to support plain logs, but cannot resume compressed sessions.
  Global installs also create `cs`; if another tool owns that name and npm
  reports `EEXIST`, use `npx @openai/codex-security`.
  Windows uses the elevated sandbox backend by default and honors an explicit
  backend selection.
  ([#1428](https://github.com/openai/codex-security/pull/1428),
  [#1415](https://github.com/openai/codex-security/pull/1415),
  [#1281](https://github.com/openai/codex-security/pull/1281))

<!-- release-section: upgrades:end -->
