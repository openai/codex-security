# Checkmarx SAST import reference

## Select a report or completed scan

Use a supplied Checkmarx One CLI JSON or CxSAST XML file directly. For collection, confirm the product, tenant or server, completed scan ID, project, repository URL and ref. Confirm the user wants the full scan before fetching. For a subset by severity, query or engine, ask for a native report exported to that scope.

CxFlow requests XML by scan ID. On the selected server, verify the completed ID, exact project name and full path of the scan's owning team against the same **Projects & Scans → All Scans** row. Use trusted read-only vendor metadata or ask the operator to confirm those values from that view. If names repeat, check **View Project Scans** under the intended team. If the mapping cannot be verified, ask for XML exported from the selected scan. CxFlow's raw XML includes findings and snippets excluded by issue-tracker filters. [CxSAST All Scans view](https://docs.checkmarx.com/en/34965-46419-viewing-results-from-all-scans.html)

Checkmarx One downloads all engines from the selected scan before the importer selects SAST results. For mixed-engine scans, its CLI can generate and download an SCA package report while assembling the JSON.

## Set up collection

Start in the operator's trusted Codex session. Set the command tool's working directory to a private directory outside the source tree before starting any process. Use a trusted noninteractive, non-login system shell (on POSIX, `/bin/sh` with `login: false` where supported). Do not source project environment files or run a repository build to collect findings.

If an IDE or build can supply startup settings from the checkout, use a clean session. The operator can add `LD_*`, `DYLD_*`, `BASH_ENV` and `ENV` to that session's trusted `shell_environment_policy.exclude`, keeping existing exclusions. A trusted host can also pass Python an argument vector and remove those variables before spawning it. Do not start a suspect shell to inspect or unset its environment. If a terminal integration, policy override or shell snapshot can restore the settings, use a known-clean session or an exported report. [Codex shell environment policy](https://developers.openai.com/codex/config-advanced/)

- Resolve the bundled [collector script](../scripts/collect_checkmarx.py) to its absolute path as `collector`.
- Use the operator's trusted native Python 3.10+ installation. From outside the source tree, use trusted system tools to resolve symlinks and inspect the file type without running the candidate. Verify the configured path and resolution stay outside the source tree. Set `python_path` to the resolved native interpreter and use `-I -S`. If the operator supplies a wrapper or version-manager shim, ask for the native interpreter's path.
- For Checkmarx One, use the installed native `cx` executable (`cx_path`). For CxSAST, use the native Java executable (`java_path`) and CxFlow JAR (`jar_path`). Use trusted absolute installation paths or symlinks to the native binaries, all outside the source tree. Ask for missing paths instead of discovering executables from the checkout. If a shell launcher is required, use a report exported with it.

## Checkmarx One sign-in

Use a native `cx` 2.3.23 or later. An explicit trusted absolute `CX_CONFIG_FILE_PATH` selects the operator's saved profile and its sign-in. Otherwise the helper uses a complete environment login if present, or the usual `~/.checkmarx/checkmarxcli.yaml`. For other profile locations or formats, ask for the actual trusted file path. For an older CLI or credential-store-only sign-in without a profile file, use an exported JSON report.

Confirm the operator selected the credentials and destination together for an environment login. Use `CX_APIKEY` or the complete `CX_CLIENT_ID`, `CX_CLIENT_SECRET`, `CX_BASE_URI` and `CX_TENANT` configuration, with `CX_BASE_AUTH_URI` for a separate OAuth server. The helper passes that login to a private, empty profile. Keep secret values in the operator's environment.

## CxSAST configuration

Use a released CxFlow JAR, version 1.6.37 or later, and the operator's trusted SAST-only configuration with `CxXml` enabled. If the helper cannot verify a compatible version, ask for XML exported from the selected scan. Keep the profile and all configuration or resources it imports outside the source tree and under operator control. Use the server address and any custom `checkmarx.client-id` from that profile. Ask for the profile's absolute path, the full team path and the project name if necessary. Pass the project name and full team path exactly as verified. If the installed CxFlow version cannot look up that project name, ask for XML from the selected scan. CxFlow 1.7.14 has this limitation for project names containing Chinese, Japanese or Korean characters.

The helper starts CxFlow in a fresh environment with the selected profile's authentication, private log paths and branch comparison disabled. If the operator wants credentials from their session, confirm those credentials belong to the server in that verified profile. The helper can pass `CHECKMARX_USERNAME`, `CHECKMARX_PASSWORD` and `CHECKMARX_CLIENT_SECRET` when set. After confirmation, append `--use-env-credentials` to the helper's `cxsast` command below. If CxFlow needs additional environment variables, custom JVM options or an agent, use XML exported in the operator's usual environment. [CxFlow credential settings](https://github.com/checkmarx-ltd/cx-flow/blob/v1.7.14/docs/Tutorials.md#L382-L390)

## Collect the report

Run the helper once with the external-import opt-in enabled. For local and Cloud imports, pass the absolute checkout or unpacked source root as `--source-root` before the product name. Omit this option only when no local source tree exists. Use a temporary directory outside the source tree for report output. The helper calls `cx results show` or CxFlow's project mode with only the `CxXml` writer. [Checkmarx One results](https://docs.checkmarx.com/en/34965-68640-results.html) · [CxFlow project retrieval](https://github.com/checkmarx-ltd/cx-flow/blob/v1.7.14/docs/Execution.md) · [CxFlow XML output](https://github.com/checkmarx-ltd/cx-flow/blob/v1.7.14/docs/Bug-Trackers-and-Feedback-Channels.md#cxxml)

```sh
# Checkmarx One
"$python_path" -I -S "$collector" --source-root "$source_root" one "$scan_id" --cx "$cx_path"
```

```sh
# Self-managed CxSAST
"$python_path" -I -S "$collector" --source-root "$source_root" cxsast "$scan_id" \
  --java "$java_path" --jar "$jar_path" --config "$config_path" --team "$cx_team" --project "$cx_project"
```

## Preview and import

Copy the absolute report path printed by the successful helper. In the next tool call, pass it as the quoted file argument to `codex-security publish findings`. Select `--provider checkmarx`, the requested destination, the verified `--source-repository-url`, a stable product/tenant/project/ref `--source-key`, and `--dry-run --format json`.

Review the source, destination, SAST results and exclusions with the user. The report can describe a directory or uploaded archive. Its native evidence retains the reported paths and lines. Verify how the scanned sources map to the checkout before navigating to a file.

After confirmation, reuse the exact report path and options for [local import](../SKILL.md#import-locally), [Cloud publication](../SKILL.md#publish-to-cloud) and retries. Remove the helper's report directory after readback unless the user wants it retained. Preserve any report the user originally supplied. [Checkmarx SAST import guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/checkmarx.md)
