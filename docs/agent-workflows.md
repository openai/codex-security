# Security workflows in Codex

Use Codex Security to scan code, investigate a supplied finding, or make and
verify a security fix. Choose the task that matches the evidence you already
have; a repository scan is the default when you are looking for new findings.

## Get started

Open your repository in Codex. Find **Codex Security** in the desktop plugin
browser, or enter `/plugins` in the interactive Codex CLI. Install the plugin,
confirm it is enabled, and start a new chat. See the
[plugin quickstart](https://learn.chatgpt.com/docs/security/plugin) for host setup
and access requirements.

Ask for the task in plain language, including the repository or paths and any
security context:

> Scan this repository with Codex Security. Focus on authorization boundaries,
> use the existing SECURITY.md, and return the saved report and coverage limits.

The [task map](#choose-a-task) below also gives explicit skill names. Local scans
do not require the optional Cloud connection. To read existing Cloud findings,
follow the separate [Cloud setup](../sdk/typescript/README.md#read-existing-cloud-findings).

The terminal package includes the plugin used by its own scans. You can follow
[the CLI quick start](../README.md#quick-start) without setting up an interactive
Codex plugin session.

## Choose a task

| Task                                                    | In Codex                                                                                                                                                                                 | From the terminal                                                                                                                                                                                             |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Find vulnerabilities in a repository or selected paths  | [`$security-scan`](../plugins/codex-security/skills/security-scan/SKILL.md): one Standard audit.                                                                                         | `cs scan .`, optionally `--path src`.                                                                                                                                                                         |
| Review a PR, commit, branch diff, or working-tree patch | [`$security-diff-scan`](../plugins/codex-security/skills/security-diff-scan/SKILL.md): review changes and trace their supporting code.                                                   | `cs scan . --diff origin/main` for committed changes, or `cs scan . --working-tree` for local changes.                                                                                                        |
| Investigate a repository or paths deeply                | [`$deep-security-scan`](../plugins/codex-security/skills/deep-security-scan/SKILL.md): repeated independent audits; excludes diff reviews.                                               | `cs scan . --mode deep`.                                                                                                                                                                                      |
| Triage supplied reports or claims                       | [`$triage-finding`](../plugins/codex-security/skills/triage-finding/SKILL.md): one static-evidence verdict per finding, with proof gaps.                                                 | `cs validate findings.json` also assesses supplied claims using static evidence; its output contract differs from plugin triage. See [validation](../sdk/typescript/docs/cli.md#validate-and-patch-findings). |
| Resolve a vulnerable dependency                         | [`$resolve-dependency-alert`](../plugins/codex-security/skills/resolve-dependency-alert/SKILL.md) traces affected versions and prepares an upgrade or dismissal proposal.                | With external imports enabled, read saved alerts with `cs findings imported ./project --format json`.                                                                                                         |
| Fix a security finding                                  | Explicitly request [`$fix-finding`](../plugins/codex-security/skills/fix-finding/SKILL.md) with the finding and affected repository.                                                     | `cs patch --scan SCAN_ID`; see [patching](../sdk/typescript/docs/cli.md#patch-existing-findings) for individual findings and options.                                                                         |
| Check an existing security fix                          | Explicitly request [`$verify-fix`](../plugins/codex-security/skills/verify-fix/SKILL.md) with the original finding and current checkout. Verification leaves repository files unchanged. | `cs verify-fix --scan SCAN_ID`; see [fix verification](../sdk/typescript/docs/cli.md#verify-fixes).                                                                                                           |

A scan or triage request does not request a code change. Ask to fix a specific
finding when you want a patch. Standalone fix verification is a separate request
and reports `fixed`, `still_vulnerable`, or `inconclusive` with evidence.

Policy generation is optional. Existing root and component `SECURITY.md` files
already guide scans. Use [policy generation](../README.md#generate-securitymd)
when that guidance needs to be drafted or updated.

## Read the result

For a completed scan, start with the generated report and its saved findings,
coverage, and threat model when present. Use the completion summary to locate the
saved results. Use source locations and validation evidence to assess a finding;
review coverage for assessed surfaces, exclusions, deferred candidates,
and remaining questions.

A completed scan can retain unresolved questions. No reported findings does not
establish that every path was reviewed or that the repository is secure. Static
triage establishes what the source supports; it does not claim runtime testing.
An inconclusive fix verification identifies the evidence still needed.

For automation, scan exit codes distinguish these outcomes:

- `0`: the scan completed without triggering a configured findings threshold.
- `1`: findings meet the configured `--fail-on-severity` threshold.
- `2`: execution, target-integrity, or required-output failure.

Coverage gaps and investigation notes do not by themselves fail a completed
scan. See [scan output](../sdk/typescript/docs/cli.md#scan-options-and-output)
and [SDK results](../sdk/typescript/README.md#read-results) for the saved fields
and failure output.

### Check a revision-range scan for missing files

If your scan retained `artifacts/02_discovery/in_scope_files.txt`, open it in
the saved results directory. It lists the paths selected for discovery. For a
scan between two commits, find `baseRevision` and `headRevision` under
`scan.target` in the saved `scan-manifest.json`. In your Git client, compare
the two commit trees directly (`base..head`). A three-dot PR comparison uses
the merge base and can show different files when the commits have diverged.
Current diff scans select regular text files regardless of extension. Git can
also list changes to binary files, symlinks, and submodules.

Plugin 0.1.32 could omit changed Perl files (`.cgi`, `.pl`, `.pm`, and `.t`).
CLI 0.3.0 was the first release to bundle the fix. To repeat the scan with
that version or later, use a clean, full checkout at the original head.
Select the same two commits from your repository,
passing the base to `--diff` and the head to `--head`. See the
[CLI quick start](../README.md#quick-start).

## Give an agent CLI guidance

The full plugin, generated CLI skills, and CLI MCP registration serve different
purposes:

| Integration           | What it provides                                                                                                       |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Codex Security plugin | The security workflow skills above, their MCP tools, and optional connected apps.                                      |
| `cs skills add`       | Generated guidance for an agent using CLI commands. This does not install the full security plugin.                    |
| `cs mcp add`          | The CLI's read-only `info` tool. It does not expose scan or patch tools; this transport cannot cancel active commands. |

An agent using the terminal can discover current commands and their schemas:

```bash
cs --llms
cs scan --schema --format json
cs scan --help
```

Use [the CLI reference](../sdk/typescript/docs/cli.md#command-discovery-and-integrations)
for integrations and output formats.

## Recover an interrupted task

| Symptom                                                      | Next step                                                                                                                                                                                       |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cs` is missing or resolves to another program               | Check the npm executable directory on `PATH`, or use `codex-security` or `npx @openai/codex-security`. See [CLI setup](../README.md#quick-start).                                               |
| The session has CLI guidance but no security workflow skills | Install and enable the full plugin through your host when available, then start a new chat. `skills add` and `mcp add` do not install it.                                                       |
| A skill is visible but required scan tools are unavailable   | Resolve the plugin server/setup error before starting the scan. Preserve any existing scan identity and report the blocker. A skill alone does not establish working tools or a completed scan. |
| Authentication fails on a headless machine                   | Use the documented [device or SSH login](../sdk/typescript/docs/cli.md#authentication), or configured API credentials for CI.                                                                   |
| A Deep Scan stops waiting in chat                            | Keep the existing scan ID. Ending a turn or detaching a waiter does not cancel the durable scan; ask Codex to continue that same scan.                                                          |
| A scan fails or completion reports an error                  | Preserve its ID, output directory, and exact error. Inspect that run before choosing recovery; retained artifacts do not imply successful completion.                                           |

For terminal scans, inspect an explicit ID so history commands refer to the same
run:

```bash
cs scans show SCAN_ID
cs scans logs SCAN_ID
```

Without an ID, `scans show` selects the latest completed scan, while `scans logs`
selects the latest scan of any status. An interrupted Deep Scan still marked
`running` can use `cs scans resume SCAN_ID` with its original checkout, output,
session, and state directory. Completed, failed, and canceled scans need a new
attempt with `cs scans rerun SCAN_ID`. A rerun uses the current checkout and may
need the original custom prompt files supplied again. See
[resume requirements](../sdk/typescript/docs/cli.md#resuming-an-interrupted-deep-scan)
and [runtime troubleshooting](../sdk/typescript/docs/cli.md#troubleshooting).
