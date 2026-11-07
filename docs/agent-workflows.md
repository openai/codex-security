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

| Task                                                    | In Codex                                                                                                                                                                                                                                   | From the terminal                                                                                                     |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| Scan a repository or selected paths                     | Ask for a [Standard scan](../plugins/codex-security/skills/security-scan/SKILL.md) (`$security-scan`).                                                                                                                                     | `cs scan .` or `cs scan . --path src`                                                                                 |
| Review a PR, commit, branch diff, or working-tree patch | Ask for [`$security-diff-scan`](../plugins/codex-security/skills/security-diff-scan/SKILL.md) with the change to review.                                                                                                                   | `cs scan . --diff origin/main` for committed changes, or `cs scan . --working-tree` for local changes.                |
| Run repeated audits of the same target                  | Ask for [`$deep-security-scan`](../plugins/codex-security/skills/deep-security-scan/SKILL.md). Later audits use findings from earlier ones.                                                                                                | `cs scan . --mode deep`                                                                                               |
| Assess supplied findings against the source             | [`$triage-finding`](../plugins/codex-security/skills/triage-finding/SKILL.md) returns a verdict and any missing evidence for each claim.                                                                                                   | `cs validate findings.json` returns a [validation report](../sdk/typescript/docs/cli.md#validate-and-patch-findings). |
| Investigate a dependency alert                          | Give [`$resolve-dependency-alert`](../plugins/codex-security/skills/resolve-dependency-alert/SKILL.md) the alert and the checkout or image. It traces the dependency and proposes an upgrade or dismissal where the evidence supports one. | To retrieve a saved alert for that review, see below.                                                                 |
| Prepare a fix                                           | Ask [`$fix-finding`](../plugins/codex-security/skills/fix-finding/SKILL.md) to patch a specific finding in the affected repository.                                                                                                        | [`cs patch --scan SCAN_ID`](../sdk/typescript/docs/cli.md#patch-existing-findings)                                    |
| Check an existing fix                                   | Give [`$verify-fix`](../plugins/codex-security/skills/verify-fix/SKILL.md) the finding and current checkout.                                                                                                                               | [`cs verify-fix --scan SCAN_ID`](../sdk/typescript/docs/cli.md#verify-fixes)                                          |
| Track a validated finding                               | Give [`$track-findings`](../plugins/codex-security/skills/track-findings/SKILL.md) the finding and destination. See [plugin connectors](plugin-connectors.md).                                                                             | For completed scans, see [publishing to Linear](../sdk/typescript/docs/cli.md#publish-completed-scans-to-linear).     |
| Inspect a downloaded skill                              | [Review the skill before installation](#review-a-skill-before-installation) in a trusted Codex chat.                                                                                                                                       | Use the interactive Codex CLI with the plugin enabled.                                                                |

**Read a saved dependency alert.** Run `cs findings imported ./project --format json`
to list the records saved for that checkout. Give the relevant record to
`$resolve-dependency-alert` to check installed versions and upgrade options.
To bring in an alert from your scanner, use the [scanner import guides](scanner-imports/README.md).

A scan or triage request produces findings. Ask to fix a specific finding when
you want a patch. A separate fix verification reports `fixed`,
`still_vulnerable`, or `inconclusive` with evidence.

For a Standard or diff scan in Codex, you can ask for an investigation allowance,
such as “spend 15 minutes reviewing this change.” The workbench saves the advisory
deadline and returns it when you resume. Before starting another Deep Scan,
Codex lists the active Deep Scans and asks whether to run them concurrently.

Existing root and component `SECURITY.md` files already guide scans. Use
[policy generation](../README.md#generate-securitymd) to draft or update one.

### Review a skill before installation

To review a skill before giving it to a coding agent, ask
[`$check-skills`](../plugins/codex-security/skills/check-skills/SKILL.md) directly:

> Use $check-skills on ../downloaded-skills before I install them in Claude Code.

Start the chat in a trusted workspace with the Codex Security checker enabled.
Keep the downloaded checkout outside the host's skill discovery paths and pass
its path to the checker. If you already opened the checkout as your workspace
or enabled its skills, start a clean chat with the target outside discovery.
The previous chat may have loaded its `AGENTS.md` or a replacement checker.

Point it at a file, an extracted bundle, a checkout containing several skills,
or paste the skill text. It returns a per-skill **PASS**, **REVIEW**, **BLOCK**,
or **INCOMPLETE** with source evidence and coverage limits. A file review covers
only that file. Supply the folder to include helpers and references. The review
does not install the target or require the plugin MCP server.

## Read the result

Open the report at the path in the completion summary. Read the source
locations and validation evidence for each finding. Check the
`scan.review.excludedPaths` list in `scan-manifest.json` for additional
exclusions. To find the files selected for discovery, [check the retained
scope list](#check-a-revision-range-scan-for-missing-files).

For new plugin-managed output, set `CODEX_SECURITY_SCAN_ROOT` to override the
scan directory root. The default is `scans/` under `CODEX_SECURITY_STATE_DIR`,
which defaults to `$CODEX_HOME/state/plugins/codex-security`. Relative overrides
resolve from the plugin directory. Existing scans keep their saved paths.

A report with zero findings can still list exclusions or unresolved questions.
Static triage reports what the source supports. An inconclusive fix verification
identifies what evidence would resolve the question.

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

#### Missing Perl files with plugin 0.1.32

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

Choose a [connected app or CLI integration](plugin-connectors.md) for your
destination. See the [CLI reference](../sdk/typescript/docs/cli.md#command-discovery-and-integrations)
for command discovery and output formats.

## Troubleshoot setup

| Symptom                                                  | Next step                                                                                                                                               |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cs` is missing or opens another program                 | Check that npm’s executable directory is on `PATH`, or use `codex-security` or `npx @openai/codex-security`. See [CLI setup](../README.md#quick-start). |
| Codex shows CLI guidance but no security workflow skills | Install and enable the full plugin in your host, then start a new chat.                                                                                 |
| A skill is visible but its scan tools are unavailable    | Check the plugin server’s setup error and resolve it before starting a scan.                                                                            |
| Authentication fails on a headless machine               | Use [device or SSH login](../sdk/typescript/docs/cli.md#authentication), or configured API credentials for CI.                                          |

## Recover an interrupted task

If Codex stops waiting for a Deep Scan in chat, ask it to continue the same
scan ID. The scan can keep running after the turn ends. If a scan reports an
error, keep its ID, output directory, and error message.

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
