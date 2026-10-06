<!-- release-version: 0.2.0 -->

<!-- release-section: highlights:start -->

## Highlights

- **Save and export threat models.** Standard, Deep, Diff, and policy workflows
  retain threat models with their results. Export a saved model without another
  model call using `codex-security export --artifact threat-model`, select a run
  with `--scan`, or use the SDK's `exportArtifact` helper. Retained content remains
  exportable if its Markdown document could not be written.
  ([#1133](https://github.com/openai/codex-security/pull/1133))
- **Detect credentials exposed in source.** Scans now explicitly assess
  credentials embedded in source, including unused code and tests, and distinguish
  supported exposures from placeholders and public material. This assessment runs
  offline and does not use discovered credentials or contact their services.
  ([#1134](https://github.com/openai/codex-security/pull/1134))
- **Use consistent model controls across workflows.** Choose `--model` and
  `--effort` for patching, validation, fix verification, and saved-scan matching and
  comparison. Reasoning-effort values pass through to Codex instead of being
  restricted to a fixed wrapper list. Deep Scan workers and inline patches retain
  the scan's configured service tier.
  ([#1143](https://github.com/openai/codex-security/pull/1143),
  [#1237](https://github.com/openai/codex-security/pull/1237),
  [#1238](https://github.com/openai/codex-security/pull/1238),
  [#1274](https://github.com/openai/codex-security/pull/1274))
- **Improve provider and authentication support.** Standalone patch, validation,
  and fix-verification commands honor custom provider configuration and
  authentication. Native Amazon Bedrock scans provide more relevant authentication
  diagnostics and Blue/Red cost estimates. Eligible OpenAI API-key scans can select
  a Cyber access program per scan, including resumed Deep Scan workers.
  ([#1131](https://github.com/openai/codex-security/pull/1131),
  [#1187](https://github.com/openai/codex-security/pull/1187),
  [#1188](https://github.com/openai/codex-security/pull/1188),
  [#1185](https://github.com/openai/codex-security/pull/1185))
- **Cover more source files accurately.** Scan inventories and ranking include
  previously omitted C++ headers, EJS/ERB/PHTML templates, and Vyper sources.
  Source previews also handle C++ raw strings, Go raw strings, and PHP heredocs
  more accurately.
  ([#1079](https://github.com/openai/codex-security/pull/1079),
  [#1197](https://github.com/openai/codex-security/pull/1197),
  [#1306](https://github.com/openai/codex-security/pull/1306),
  [#1279](https://github.com/openai/codex-security/pull/1279),
  [#1235](https://github.com/openai/codex-security/pull/1235),
  [#1236](https://github.com/openai/codex-security/pull/1236))
- **Make scan startup and saved results more reliable.** Unix sandbox readiness
  is checked before billed inference starts, and concurrent scans reuse unchanged
  plugin installations. Completed artifacts survive follow-up cancellation, scan
  history remains readable during registration, and CSV round trips preserve
  distinct finding occurrences and literal leading apostrophes.
  ([#1084](https://github.com/openai/codex-security/pull/1084),
  [#1082](https://github.com/openai/codex-security/pull/1082),
  [#1057](https://github.com/openai/codex-security/pull/1057),
  [#1272](https://github.com/openai/codex-security/pull/1272),
  [#1247](https://github.com/openai/codex-security/pull/1247))

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

- **Threat-model consumers:** `SecurityPolicyDraft.threatModelPath` is now
  `string | null`; check it before opening the document. Policy generation writes
  `threatmodel.md` instead of `THREAT_MODEL.md`, so prefer the returned path over a
  hard-coded filename. Readers of saved model data must handle Markdown content
  (`format: "markdown"`, `content`) as well as legacy structured models.
  Historical structured models remain readable and exportable; no saved-data
  migration is required.
  ([#1133](https://github.com/openai/codex-security/pull/1133))
- **Findings service clients:** send `Content-Type: application/json` to
  `POST /v1/bulk/findings` and `POST /v1/dedupe-groups`. Missing or other media types
  now return HTTP 400 `invalid_request`; JSON with a charset parameter is accepted.
  ([#1277](https://github.com/openai/codex-security/pull/1277))
- **Diagnostic output:** the wrapper now preserves original diagnostic text,
  including credential-shaped values, in CLI output and saved failure,
  publication, and patch-risk summaries. Review logs and artifacts for sensitive
  information before sharing them.
  ([#1179](https://github.com/openai/codex-security/pull/1179))
- **Effort schemas:** reasoning effort is a nonempty string rather than a closed
  enum. Supported values still depend on Codex and the chosen model/provider.
  ([#1237](https://github.com/openai/codex-security/pull/1237))
- **Older CSV exports:** new exports preserve leading apostrophes, but ambiguous
  prefixes in older CSV files cannot be reconstructed. Use JSON export when those
  original values are needed.
  ([#1247](https://github.com/openai/codex-security/pull/1247))

<!-- release-section: upgrades:end -->
