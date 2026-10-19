<!-- release-version: 0.5.0 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security 0.5.0 adds host-provided finding reviews and more inference
provider options, and improves scan progress, configuration, and document
handling. The minor version marks the retirement of advisory capability
preflight; custom integrations should follow the migration guidance below.

- Hosts can validate findings against source with `codex-security validate --records`
  and `validateRecords()`, or classify canonical reports against a supplied
  severity rubric with `codex-security classify-severity --records` and
  `classifySeverityRecords()`. Both use host-provided model execution;
  classification requires no repository or saved scan. See the
  [validation guide](https://github.com/openai/codex-security/blob/npm-v0.5.0/sdk/typescript/docs/validate-records.md)
  and [classification guide](https://github.com/openai/codex-security/blob/npm-v0.5.0/sdk/typescript/docs/classify-severity-records.md)
  for input contracts and host responsibilities.
  ([#1682](https://github.com/openai/codex-security/pull/1682),
  [#1662](https://github.com/openai/codex-security/pull/1662))
- Scans support Cheaper Inference through `--provider cheaperinference`, an
  explicit model, and `CHEAPER_INFERENCE_API_KEY`. The GitHub Action adds a
  `provider` input for Amazon Bedrock, OpenRouter, and Fireworks alongside the
  default OpenAI provider; non-OpenAI providers require an explicit model and
  the selected provider's credentials. See the
  [CLI provider documentation](https://github.com/openai/codex-security/blob/npm-v0.5.0/sdk/typescript/docs/cli.md)
  and [Action setup guide](https://github.com/openai/codex-security/blob/npm-v0.5.0/github-action/README.md#inference-providers).
  ([#1623](https://github.com/openai/codex-security/pull/1623),
  [#1677](https://github.com/openai/codex-security/pull/1677))
- Hosted scans pass `reasoningEffort` strings through to the executor, including
  `max` and future values supported by the selected model or provider.
  ([#1712](https://github.com/openai/codex-security/pull/1712))
- Standard and diff scans use available workers and continue review in the
  parent when delegation is unavailable. Optional worker or goal-tool
  availability no longer depends on the removed capability registry.
  ([#1609](https://github.com/openai/codex-security/pull/1609))
- Failed or canceled `dedupe --json --full-output` commands no longer print a
  false success envelope. Diff scans handle root commits in SHA-256
  repositories and read blobs with Git versions older than 2.38.
  ([#1071](https://github.com/openai/codex-security/pull/1071),
  [#1716](https://github.com/openai/codex-security/pull/1716),
  [#1715](https://github.com/openai/codex-security/pull/1715))
- DOCX knowledge-base extraction excludes deleted revisions and field
  instructions while preserving visible field results.
  ([#1714](https://github.com/openai/codex-security/pull/1714))

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

### Custom capability-preflight integrations

The plugin's `scripts/config_preflight.py` helper and
`preflight/capability-profiles.toml` registry are removed. Custom capability
registries and helper-derived progress inputs and events are no longer supported.
Update integrations as follows:

1. Remove helper invocations, custom-registry arguments, and gates that wait for
   a helper `ready` result. Replace references to `config-preflight.md` and
   `desktop-config-preflight.md` with the
   [scan runtime guidance](https://github.com/openai/codex-security/blob/npm-v0.5.0/plugins/codex-security/references/scan-runtime.md).
   Use available delegation tools and successful spawn results; continue in the
   parent when workers cannot start. Do not edit persistent configuration to
   enable optional workers or goal tools.
2. Remove `kind: "preflight"` handling from `onWorkerStatus` consumers,
   including reads of `delegation` and `configuredSlots`, and stop waiting for
   the CLI's `worker.preflight` diagnostic. `onWorkerStatus` still emits
   `kind: "dispatch"` with `phase`, `planned`, and `started`. These counts are
   best-effort model reports; a missing event does not prove no worker ran.
3. Stop sending `preflightChecks` to
   `update_codex_security_scan_progress` and remove the workbench arguments
   `--preflight-issues-json` and `--preflight-issues-json-stdin`. For host-backed
   Standard and diff scans, use the authoritative scan context and advance to
   `threat_model` before architecture mapping. Deep Scan's coordinator continues
   to own its setup and progress.

Saved preflight history remains readable, and the scan lifecycle still includes
a `preflight` phase. Local SDK `preflight()` input checks, authentication,
sandbox enforcement, and Deep worker configuration remain in effect. Normal
CLI and SDK scans need no capability-preflight configuration migration.
([#1609](https://github.com/openai/codex-security/pull/1609))

### Selected-profile approval policy

An explicitly selected Codex profile's `approval_policy` now takes precedence
over the root policy. If you previously relied on a root `never` policy despite
a selected profile specifying `on-request`, set the selected profile's policy
to `never` to continue denying permission requests. An absent or null profile
policy still inherits the root value; Deep Scan workers retain their explicit
`never` policy.
([#530](https://github.com/openai/codex-security/pull/530))

<!-- release-section: upgrades:end -->
