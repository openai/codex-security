<!-- release-version: 0.2.0 -->

<!-- release-section: highlights:start -->

## Highlights

- Threat models are now saved with Standard, Deep, and Diff scan results and
  generated security policies. Export a saved model without another model call
  using `codex-security export --artifact threat-model` or the SDK's
  `exportArtifact` helper.
  ([#1133](https://github.com/openai/codex-security/pull/1133))
- Scans now check for exposed credentials in source code, including unused code
  and tests, and distinguish suspected exposures from placeholders. This check
  runs offline, without trying discovered credentials against a service.
  ([#1134](https://github.com/openai/codex-security/pull/1134))
- Use `--model` and `--effort` when generating patches, validating findings,
  verifying fixes, or matching and comparing saved scans. Deep Scan workers and
  patches generated during a scan also respect your selected service tier.
  ([#1143](https://github.com/openai/codex-security/pull/1143),
  [#1238](https://github.com/openai/codex-security/pull/1238),
  [#1274](https://github.com/openai/codex-security/pull/1274))
- Patch, validation, and fix-verification commands now respect custom model
  providers and their authentication settings. Amazon Bedrock users get clearer
  authentication errors and cost estimates for Daybreak Blue and Red. Eligible
  OpenAI API-key users can select a Cyber access program for each scan.
  ([#1131](https://github.com/openai/codex-security/pull/1131),
  [#1187](https://github.com/openai/codex-security/pull/1187),
  [#1188](https://github.com/openai/codex-security/pull/1188),
  [#1185](https://github.com/openai/codex-security/pull/1185))
- Scans include previously overlooked C++ headers (`.hh` and `.hxx`),
  server-rendered templates (EJS, ERB, and PHTML), and Vyper source files when
  selecting code to review.
  ([#1079](https://github.com/openai/codex-security/pull/1079),
  [#1197](https://github.com/openai/codex-security/pull/1197),
  [#1306](https://github.com/openai/codex-security/pull/1306))
- On Unix, scans check that the sandbox works before starting paid model calls.
  Completed results are kept if you cancel follow-up work. CSV exports can now be
  reimported without rejecting multiple occurrences of a finding or losing
  leading apostrophes.
  ([#1084](https://github.com/openai/codex-security/pull/1084),
  [#1057](https://github.com/openai/codex-security/pull/1057),
  [#1247](https://github.com/openai/codex-security/pull/1247))

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

- If your integration reads threat models, check `SecurityPolicyDraft.threatModelPath`
  for `null` before opening the file. Policy generation now writes `threatmodel.md`
  instead of `THREAT_MODEL.md`; use the returned path. Saved models can contain
  Markdown (`format: "markdown"`, `content`) or the previous structured format, so
  readers must handle both. Existing models remain readable and exportable
  without migration.
  ([#1133](https://github.com/openai/codex-security/pull/1133))
- Findings service clients must send `Content-Type: application/json` to
  `POST /v1/bulk/findings` and `POST /v1/dedupe-groups`. Missing or other content
  types return HTTP 400 `invalid_request`. A charset parameter is accepted.
  ([#1277](https://github.com/openai/codex-security/pull/1277))
- Codex Security no longer masks diagnostic text that looks like credentials.
  CLI output and saved error, publication, and patch-risk summaries can contain
  sensitive values. Review them before sharing.
  ([#1179](https://github.com/openai/codex-security/pull/1179))
- SDK types and CLI schemas now accept any nonempty string for reasoning effort.
  Update integrations that assume a fixed list. The chosen value must still be
  supported by Codex and your model provider.
  ([#1237](https://github.com/openai/codex-security/pull/1237))
- Older CSV exports may have ambiguous leading apostrophes that cannot be
  recovered from the CSV alone. Export the original saved results as JSON if you
  need those exact values.
  ([#1247](https://github.com/openai/codex-security/pull/1247))

<!-- release-section: upgrades:end -->
