<!-- release-version: 0.5.0 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security 0.5.0 adds investigation time budgets, host-provided finding
reviews, and more inference provider options. It also improves saved finding
evidence, usage reporting, and recovery after interrupted scans and publication.
The minor version marks the retirement of advisory capability preflight;
custom integrations should follow the migration guidance below.

- Set an investigation allowance with `codex-security scan . --max-time 15`,
  SDK `maxTimeMinutes`, or project setting `scan.max_time_minutes`. Values are
  positive minutes, including fractions. Standard and diff scans treat the
  allowance as advisory; Deep Scan enforces it for discovery, then combines
  completed findings. Reporting can continue beyond the deadline. See the
  [time-budget guide](https://github.com/openai/codex-security/blob/npm-v0.5.0/sdk/typescript/docs/cli.md#set-investigation-time).
  ([#1674](https://github.com/openai/codex-security/pull/1674))
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
  `max` and future values supported by the selected model or provider. The
  GitHub Action's `effort` input also accepts provider-supported strings and
  retains its `xhigh` default. Deep Scan forwards resolved native settings to
  fresh and resumed workers while retaining worker-specific permissions.
  ([#1712](https://github.com/openai/codex-security/pull/1712),
  [#1717](https://github.com/openai/codex-security/pull/1717))
- Standard and diff scans use available workers and continue review in the
  parent when delegation is unavailable. Optional worker or goal-tool
  availability no longer depends on the removed capability registry.
  ([#1609](https://github.com/openai/codex-security/pull/1609))
- Patching and fix verification use complete sealed findings from saved scans,
  preserving current triage and remediation state. Workbench excerpts stay
  tied to the source and scope of the saved scan, and publishing older findings
  preserves their historical root-cause details and code evidence.
  ([#1608](https://github.com/openai/codex-security/pull/1608),
  [#488](https://github.com/openai/codex-security/pull/488),
  [#1756](https://github.com/openai/codex-security/pull/1756))
- Usage reporting distinguishes recorded tokens from missing worker receipts
  or unfinished turns. Partial totals display as "at least X tokens; some usage
  unavailable." Saved scan history includes parent/worker totals and
  measurement times alongside cost estimates; historical account-limit readings
  are not a live allowance check. See
  [progress and cost](https://github.com/openai/codex-security/blob/npm-v0.5.0/sdk/typescript/docs/cli.md#progress-and-cost).
  ([#1640](https://github.com/openai/codex-security/pull/1640))
- Bulk-scan recovery validates completed artifacts before reusing them and
  preserves interrupted receipt bytes. Parallel workers serialize receipt
  writes, and publication replaces its latest receipt atomically. Completed
  Linear publication results remain available after late cancellation during
  a failed final receipt write.
  ([#1720](https://github.com/openai/codex-security/pull/1720),
  [#1748](https://github.com/openai/codex-security/pull/1748),
  [#1735](https://github.com/openai/codex-security/pull/1735),
  [#1738](https://github.com/openai/codex-security/pull/1738),
  [#1725](https://github.com/openai/codex-security/pull/1725))
- Matching GitHub Action distributions publish their manifest, SBOM, and full
  distribution commit SHA in a companion `action-vX.Y.Z` release. Artifact
  upload failures propagate the original stream error and cancel active streams.
  ([#1711](https://github.com/openai/codex-security/pull/1711),
  [#1671](https://github.com/openai/codex-security/pull/1671))
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

### Investigation time settings

Prefer the new minute-based settings for Standard, diff, and Deep scans. For
existing Deep Scan configurations, convert hours to minutes:

| Previous setting                      | Preferred setting                    |
| ------------------------------------- | ------------------------------------ |
| `--max-time-hours 2`                  | `--max-time 120`                     |
| SDK `maxTimeHours: 2`                 | SDK `maxTimeMinutes: 120`            |
| Project `scan.deep.max_time_hours: 2` | Project `scan.max_time_minutes: 120` |

The hour-based settings, including legacy TOML `deep_scan.max_time_hours`, remain
accepted as deprecated Deep-only aliases. Explicit settings override
lower-priority configuration across units. At the winning configuration source,
equivalent durations are accepted; conflicting minute/hour values are errors.

Standard scans still have no time allowance by default. An allowance is neither
a hard timeout nor a minimum runtime. Deep Scan's default and maximum discovery
duration remain 5760 minutes (96 hours). Resuming Deep Scan retains its original
deadline; rerunning starts a new allowance. For batch and component scans,
project time settings apply separately to each scan attempt, not the campaign
as a whole. See the
[time-budget guide](https://github.com/openai/codex-security/blob/npm-v0.5.0/sdk/typescript/docs/cli.md#set-investigation-time).
([#1674](https://github.com/openai/codex-security/pull/1674))

### Saved scan evidence and recovery

Keep the complete sealed artifacts with saved scans used for patching or fix
verification. Missing or mismatched evidence now stops those tasks instead of
passing a shortened preview to the model. Bulk-scan resume validates saved
contracts and seals before reusing a completed result; invalid or unsuccessful
results start a new attempt while preserving the old artifacts.
([#1608](https://github.com/openai/codex-security/pull/1608),
[#1720](https://github.com/openai/codex-security/pull/1720))

### GitHub Action release assets

If automation downloads the Action manifest or SBOM from an `npm-vX.Y.Z`
release, switch those downloads to the matching `action-vX.Y.Z` release. The npm
release remains the canonical changelog and Latest release; Action version tags
and workflow usage syntax are unchanged. See the
[Action release documentation](https://github.com/openai/codex-security/blob/npm-v0.5.0/github-action/README.md#development).
([#1711](https://github.com/openai/codex-security/pull/1711))

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
