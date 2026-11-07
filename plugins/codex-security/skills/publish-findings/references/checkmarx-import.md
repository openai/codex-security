# Collect and import Checkmarx SAST findings

Use a supplied One CLI JSON or CxSAST XML report directly. For collection, confirm the product, tenant or server, completed scan ID, project, repository URL and ref. Both collectors retrieve the full scan. If the operator wants a subset, ask for an export scoped to that selection.

## Before launching a vendor tool

- Use a trusted session and a private working and temporary directory outside the source tree, for both local and Cloud imports. Set the working directory **before** starting a process. Use a noninteractive, non-login system shell such as `/bin/sh` with `login: false`.
- If an IDE or build supplies checkout-controlled startup settings, use a known-clean session or a saved export. A trusted host can exclude `LD_*`, `DYLD_*`, `BASH_ENV` and `ENV` before launching a shell or interpreter. Keep existing exclusions and account for restored shell snapshots. Never start a suspect shell to unset variables or source project files. [Codex shell environment policy](https://developers.openai.com/codex/config-advanced/)
- Resolve the installed [collector](../scripts/collect_checkmarx.py) and vendor tools to trusted absolute paths outside the source tree. For `python_path`, use trusted system tools to inspect the executable and resolve symlinks without running it. Use the native Python 3.10+ interpreter with `-I -S`. Ask for native installation paths if given a shim or shell launcher.
- Pass the absolute checkout or unpacked source as `--source-root` before the product. Omit it only when there is no local source tree.

## Checkmarx One

Use native `cx` 2.3.23+. An explicit `CX_CONFIG_FILE_PATH` selects that trusted profile. Without an explicit profile, the helper uses a complete environment login if present, or `~/.checkmarx/checkmarxcli.yaml`. For an environment login, confirm the destination and keep `CX_APIKEY` or `CX_CLIENT_ID`, `CX_CLIENT_SECRET`, `CX_BASE_URI` and `CX_TENANT` in the operator's environment. A separate OAuth server also uses `CX_BASE_AUTH_URI`. For an older client or a credential-store-only login with no profile file, ask for JSON exported with the operator’s usual setup.

`cx results show` retrieves every engine in a mixed scan and can generate and download an SCA package report. [Checkmarx One results](https://docs.checkmarx.com/en/34965-68640-results.html)

```sh
"$python_path" -I -S "$collector" --source-root "$source_root" one "$scan_id" --cx "$cx_path"
```

## Self-managed CxSAST

**Verify ownership before fetching.** CxFlow requests XML by scan ID. Confirm the completed ID, exact project and full owning team path from the same **Projects & Scans → All Scans** row on the selected server. Use trusted read-only metadata or ask the operator to confirm those values from that view. For repeated names, check **View Project Scans** under the intended team. Without confirmation, ask for selected XML. Issue-tracker filters do not narrow the raw XML. [All Scans](https://docs.checkmarx.com/en/34965-46419-viewing-results-from-all-scans.html)

Use native Java, a released CxFlow JAR (1.6.37+), and a trusted SAST-only profile with `CxXml` enabled. Keep the profile and everything it loads outside the checkout. Take the server, authentication and any custom `checkmarx.client-id` from that profile. Only append `--use-env-credentials` when the operator confirms the session's `CHECKMARX_USERNAME`, `CHECKMARX_PASSWORD` or `CHECKMARX_CLIENT_SECRET` belong to that server. For custom JVM settings or project names the installed CxFlow cannot resolve, ask for an XML export. [CxFlow credentials](https://github.com/checkmarx-ltd/cx-flow/blob/v1.7.14/docs/Tutorials.md#L382-L390) · [CxXml writer](https://github.com/checkmarx-ltd/cx-flow/blob/v1.7.14/docs/Bug-Trackers-and-Feedback-Channels.md#cxxml)

```sh
"$python_path" -I -S "$collector" --source-root "$source_root" cxsast "$scan_id" \
  --java "$java_path" --jar "$jar_path" --config "$config_path" --team "$cx_team" --project "$cx_project"
```

## Preview and import

Pass the successful helper's printed path as the quoted file argument to `codex-security publish findings` in the next tool call. Use `--provider checkmarx`, the requested destination, verified `--source-repository-url`, a stable product/tenant/project/ref `--source-key`, and `--dry-run --format json`. Review the scope, findings and exclusions. Verify native paths against the checkout before opening source files.

After confirmation, reuse that file and those options for [local import](../SKILL.md#import-locally), [Cloud publication](../SKILL.md#publish-to-cloud) and retries. Remove the helper’s temporary directory after readback unless the operator wants it retained. Keep operator-supplied files. [User guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/checkmarx.md)
