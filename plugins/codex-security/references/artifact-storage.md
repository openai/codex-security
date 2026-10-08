# Artifact Storage

Apply this policy to plugin-managed scans and standalone artifact-producing skills. An explicitly SDK-owned workflow keeps its SDK-provided directories and existing artifact-writing and completion behavior; follow its existing instructions instead of this policy. Bound Deep workers keep their existing narrow artifact tools and read-only execution profile.

## Scan ownership

For a full scan, obtain the authoritative `scanId` before creating artifacts. Standard uses `start_codex_security_standard_scan`; a headless Diff without a scan uses `start_codex_security_prompt_only_scan` with its exact target, `mode: "diff"`, `scope: "."` and `diffTarget`. Deep uses its existing coordinator. Preserve an existing scan and handoff token. If the required MCP is unavailable or the selected baseline is unsupported, report the blocker; do not fall back to shell-authored canonical files. These rules take precedence over older terminal file-authoring fallbacks.

Keep structured outputs on their existing tools: inventories, candidate discovery, validation, attack paths, semantic drafts, checkpoints and completion. Canonical results and recovery checkpoints are persistent even while a scan is running. Never use the supplemental file tool to replace them or generate `report.md`.

## Supplemental files

Use the existing plugin MCP's `save_codex_security_artifact` and `read_codex_security_artifact` for standalone Markdown, optional finding write-ups, hardening documents/diagrams, validation evidence and retained helper output. The host derives a scan's root-level `threatmodel.md` from its canonical `threatModel`; submit that model through the existing semantic draft tool instead of authoring a second document. Do not write retained supplemental files with shell redirection, `apply_patch`, Python or other ordinary file-writing tools.

Identify the owner with exactly one of:

- `scanId` and the current `handoffClaimToken` when required, for a running scan;
- `targetPath`, for a standalone phase or a derived document requested after a scan completes. Use the authorized repository or input-document directory. This creates a target-bound artifact collection without starting a scan. Never invent a scan ID.

Select `storage` explicitly:

- `persistent`: retained documents/evidence under the authoritative scan directory or standalone collection. The default root is `$CODEX_SECURITY_STATE_DIR/scans`, or `$CODEX_HOME/state/plugins/codex-security/scans` when no state override is set; `CODEX_HOME` defaults to `~/.codex`. The existing `CODEX_SECURITY_SCAN_ROOT` override still takes precedence for plugin-created output. If the default workbench state is unwritable, retained artifacts follow its temporary fallback state's `scans` directory and can be removed by OS temporary-directory cleanup. Preserve an existing scan's saved path, including older temporary paths.
- `temporary`: disposable staging and execution output in a context-specific OS temporary directory. Standalone temporary saves and reads do not create or require the persistent collection. It is not part of the completed result and must not be referenced from canonical findings or coverage. It can disappear independently of retained files.

Relative storage overrides resolve from the plugin directory, matching the workbench, regardless of the MCP launch directory.

Omit `path`, `content` and `sourcePath` to prepare the selected directory. Use the returned `directory`; never construct or guess the physical path. A save with a file requires `path` plus exactly one of `content` or `sourcePath`.

Example for a running scan:

```text
read_codex_security_artifact({ scanId, handoffClaimToken?, storage: "persistent", path: "threatmodel.md" })
save_codex_security_artifact({ scanId, handoffClaimToken?, storage: "temporary" })
save_codex_security_artifact({ scanId, handoffClaimToken?, storage: "persistent", path: "artifacts/02_discovery/validation_artifacts/<candidate_id>/poc.bin", sourcePath: "<returned temporary directory>/poc.bin" })
```

`path` is a portable relative filename under `artifacts/`, `findings/` or `hardening/`; `report_validation.md` is also supported. Standalone collections additionally support saving `threatmodel.md`; the former `threat_model.md` remains readable. Running scans can read the host-generated `threatmodel.md`, but cannot replace it through the supplemental save tool. Use the existing relative artifact layouts for each phase. The tool returns the physical `path`, canonical `relativePath` and content digest. Use persistent evidence paths in scan evidence references; the derived threat-model document is not a coverage receipt. Read with the same identity, `storage` and relative `path`; request `encoding: "base64"` only for binary content.

Source/configuration edits and external-publication request bodies are separate from scan artifacts and retain their existing tools and authorization. Explicit user instructions still take precedence. If a required output destination cannot be represented by managed storage, explain that limitation instead of silently substituting a different destination or claiming it was written.

## Generated evidence and legacy helpers

PoC execution and builds can create files. Prepare `temporary` storage first and run authorized build/test/generation commands only in that workspace or its disposable repository copy. Author PoC source/input files with the save tool using `storage: "temporary"`. Tools that generate inventories, normalization output or other files must receive temporary output paths. Import each file needed in the final record with `storage: "persistent"` and `sourcePath` inside the same returned temporary directory. Import the actual bytes, not a model transcription of binary output or logs. Do not retain entire dependency/build trees without a reason.

For standalone/legacy mutable ledgers, use the save tool to replace their complete contents, or import a helper-produced temporary file. Do not append directly into the retained scan directory. Current Standard and Deep scans do not introduce legacy inventories or ledgers.

## Threat-model cache and completed results

For a standalone repository threat model, use `targetPath: <repo_root>`, `storage: "persistent"`, `path: "threatmodel.md"`. Read a shared cached file only when the threat-model workflow allows cache reuse and its exact repository/version footer matches; if the new filename is absent, the legacy `threat_model.md` may be read under the same rules. For a running scan, retain the selected text as `{ "format": "markdown", "content": "<exact Markdown>" }` in its canonical `threatModel`, using an early `complete: false` semantic checkpoint with partial coverage. The host writes `<scan_dir>/threatmodel.md` from that content. Preserve the workflow's conditions that forbid reading or replacing the shared cache; saving or exporting a scan's model does not authorize a cache update.

End each shared threat model with these two lines:

- `Repository: <stable target identity from scan-contract.md>`
- `Version: <revision for an immutable Git tree; snapshot digest otherwise>`

Completed/sealed scan files cannot be edited through the save tool. For later write-ups or hardening requests, use the standalone target collection and link those returned files separately. Preserve the original result and its references. Temporary cleanup must not remove retained files or recovery checkpoints. The save tool publishes running-scan files under the same completion lock as finalization; surface a stopped/sealed-scan rejection and preserve existing output.
