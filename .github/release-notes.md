<!-- release-version: 0.9.1 -->

<!-- release-section: highlights:start -->

## Highlights

- The npm package includes Developer ID-signed native addons for Apple Silicon and Intel Macs. This lets Codex Desktop load the addon when preparing review items.
- Deep Scan runs independent Standard reviews in batches. Workers can share leads and verify each other's evidence. The final report groups observations that have the same fix and retains the source locations from each review. [Deep Scan guide](https://github.com/openai/codex-security/blob/main/sdk/typescript/docs/cli.md#configure-deep-scans)
- External scanner imports are enabled by default in the CLI, SDK, and plugin. You can preview supported reports, save findings locally, and publish supported findings to Cloud. The scanner guides list the accepted formats and which inputs are local-only. [Scanner import guides](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/README.md)
- `scans logs` finds sessions faster in large compressed histories. The GitHub Action also includes scan scope limitations in its job summary, including when a scan returns zero findings.

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

- **Deep Scan budgets.** `--stop-after-no-new` now counts consecutive completed Standard reviews that add no findings. If you depend on a particular run length, review this threshold alongside `--max-discovery-runs` and `--max-time`. [Deep Scan settings](https://github.com/openai/codex-security/blob/main/docs/project-configuration.md#deep-settings-and-limits)
- **Scanner imports.** Remove `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS` from launch scripts. A legacy value of `0` no longer disables imports. [Scanner import guides](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/README.md)
- **Linux Compose deployments.** The bundled seccomp profile restricts direct socket families and blocks `ptrace`, `process_vm_readv`, and `process_vm_writev`. If a custom tool needs one of these operations, test it against your deployment's profile before upgrading. [Container guide](https://github.com/openai/codex-security/blob/main/docker/README.md)
- **Source builds.** Sparse SDK checkouts must include `plugins/codex-security/mcp-app/src/deep-scan-settings.ts`. Upgrade or roll back the bundled plugin as a unit. [Source build change](https://github.com/openai/codex-security/pull/2452)
- **Package verification.** The source package checker rejects sparse tar entries. If an unsigned candidate was built with a sparse-aware archiver, recreate it with `pnpm pack` from `sdk/typescript`. Use the original published archive for release recovery. [Package verification change](https://github.com/openai/codex-security/pull/2456)

<!-- release-section: upgrades:end -->
