# Claude Security (`claude-security`)

> **This is an unofficial port of OpenAI's [Codex Security](https://github.com/openai/codex-security) to Claude Code.**
> It is not affiliated with, endorsed by, or supported by OpenAI or Anthropic.
> The original is Copyright 2025 OpenAI, Apache-2.0. See [`NOTICE`](NOTICE) for the
> attribution and the full list of modifications.

A security scanning CLI that finds, validates, and reports vulnerabilities in your code — driven by **Claude Code** on your **Claude subscription**. No OpenAI account, no OpenAI API key, no per-token billing.

## Provenance: what is ported and what is new

Codex Security is two things stacked together: a **security methodology** (how to threat-model a repository, how to prove a candidate finding is real, how to calibrate severity, what a defensible scan contract looks like) and a **Codex runtime** (the `@openai/codex-sdk` thread runner, ChatGPT sign-in, `$CODEX_HOME` plugin installation, the desktop MCP app).

The methodology is the valuable part, and it is model-agnostic. This port keeps it essentially verbatim:

| Kept from Codex Security | What it is |
| --- | --- |
| 13 phase skills | threat-model, finding-discovery, validation, attack-path-analysis, vulnerability-writeup, propose-security-hardening, triage-finding, track-findings, fix-finding, define-security-policy, and the three top-level scan workflows |
| `references/validation-guidance.md` | ~27 KB of rules for proving a candidate is real |
| `references/severity-policy.md` | ~15 KB of severity calibration |
| The scan contract + JSON schemas | `scan-manifest.json`, `findings.json`, `coverage.json` |
| The Python workbench (~500 KB) | SQLite scan history, candidate ledger, ranking, scan comparison |
| The deterministic finalizer | Generates `report.md` and SARIF from canonical JSON — the model never writes either |

The Codex runtime is what was rewritten. `Claude Security` is the name this port uses for the resulting tool; upstream, the same thing is called `Codex Security`.

Naming inside the code follows one rule: **anything a human reads was rebranded; anything written to disk as a data contract was not.** So the CLI, skills, reports, and SARIF driver all say *Claude Security*, while `documentType: "codex-security.scan-manifest"` and `fingerprints.algorithm: "codex-security/v1"` are unchanged — those are schema `const` values shared by the validators, the SARIF adapter, and the scan-comparison logic, and keeping them means a bundle produced here stays readable by upstream tooling. See [What changed](#what-changed-from-codex-security) for the full list.

## Requirements

- **Claude Code** installed and signed in (`claude`), on a Pro or Max plan
- **Node.js** 22.13+
- **Python** 3.10+ (3.10 also needs `tomli`; 3.11+ works out of the box)

No `npm install` step: the CLI has zero runtime dependencies, and the plugin's Python helpers use only the standard library.

## Quick start

```bash
node bin/claude-security.mjs auth status
node bin/claude-security.mjs scan .
node bin/claude-security.mjs scan . --effort max
node bin/claude-security.mjs scan . --diff origin/main
node bin/claude-security.mjs scan . --mode deep --workers 3
```

Or link it onto your PATH:

```bash
npm link            # then: claude-security scan .
```

Scans bill against whatever plan the local `claude` CLI is signed in to. If `ANTHROPIC_API_KEY` is set in your environment it is **stripped** from every scan session, so a stray key can't silently move you onto API billing. Set `CLAUDE_SECURITY_ALLOW_API_KEY=1` if you actually want that.

## Commands

```
claude-security scan <repository> [options]
claude-security scans list [repository] [--json]
claude-security scans show <scan-id>
claude-security scans compare <before-scan-id> <after-scan-id>
claude-security auth status
```

### Scan options

| Option | Meaning |
| --- | --- |
| `--path <path>` | Limit the scan to a path (repeatable) |
| `--diff <base>[..<head>]` | Scan a commit, branch, or revision range |
| `--working-tree [<base>]` | Scan uncommitted changes (default base `HEAD`) |
| `--mode standard\|deep` | Scan depth (default `standard`) |
| `--model <model>` | Claude model (default `claude-opus-5`) |
| `--effort <level>` | `low`, `medium`, `high`, `xhigh`, `max` (default `high`) |
| `--knowledge-base <path>` | Architecture / threat-model documents (repeatable) |
| `--output-dir <dir>` | Where scan bundles go (must be outside the repo) |
| `--archive-existing` | Move earlier bundles into an archive directory first |
| `--fail-on-severity <level>` | Exit `3` when a finding is at or above this level |
| `--workers <n>` | Deep mode: parallel discovery workers per pass |
| `--stop-after-no-new <n>` | Deep mode: stop after this many quiet passes |
| `--max-discovery-runs <n>` | Deep mode: hard ceiling on discovery passes |
| `--dry-run` | Print what would be scanned and exit |
| `--json` | Machine-readable output |

Exit codes: `0` clean, `1` error, `2` scan finished without a complete contract, `3` severity gate failed, `130` interrupted.

## What a scan produces

Every scan writes a self-contained bundle outside your repository:

```
<scan-dir>/
  report.md                 generated, never hand-authored
  scan-manifest.json        sealed scan contract
  findings.json             every reported finding
  coverage.json             what was reviewed, and what wasn't
  exports/results.sarif     SARIF 2.1.0
  artifacts/                threat model, candidate ledger, evidence
  findings/<slug>/          per-finding write-ups and PoCs
  hardening/                structural hardening proposals
```

`report.md` and the SARIF are generated deterministically by the Python finalizer from the canonical JSON — the model never writes them. That's what keeps the report faithful to the evidence rather than to the model's summary of it.

## How it works

```
claude-security scan .
   │
   ├─ registers the scan in a SQLite workbench (Python)
   ├─ resolves the target: repository | scoped paths | git diff | working tree
   │
   ├─ starts `claude --print` with:
   │     --model claude-opus-5   --effort high
   │     --plugin-dir <plugin>   (registers the 13 security skills)
   │     --setting-sources ""    (your hooks/CLAUDE.md can't perturb a scan)
   │     deny rules on Write/Edit inside the scanned repository
   │
   ├─ the session runs threat-model → discovery → validation →
   │  attack-path analysis, and writes an *unsealed* canonical JSON draft
   │
   └─ the CLI seals the contract, generates report.md + SARIF, indexes findings
```

Deep mode adds repeated discovery in front of that. The CLI coordinator dispatches N independent discovery workers per pass, runs a reducer session to merge them into one canonical candidate set, and repeats until the search **saturates** (no new candidates for the configured number of passes) or hits the pass ceiling. Only then does the parent session run the single centralized tail.

The fan-out is deterministic and lives in the CLI rather than in the model's hands, because the workbench enforces a strict state machine — a reduction may only claim an ordered prefix of buffered discovery results, `saturated` may only be declared at the no-new threshold, `capped` only at the dispatch ceiling. A coordinator can honor that exactly and respect `--workers`; a model asked to orchestrate its own fan-out can't promise either.

## Verified end to end

A standard scan of a small Express service with four planted vulnerabilities, on `claude-opus-5` at `--effort medium`:

```
6 finding(s) — 1 critical, 2 high, 2 medium, 1 low — coverage: complete — 14m 54s

  critical      Unauthenticated command injection in GET /ping ... (src/app.js:24)
  high          Unauthenticated SQL injection in GET /user ...    (src/app.js:10)
  high          Hardcoded MySQL root password ...                 (src/app.js:6)
  medium        Reflected cross-site scripting in GET /greet ...  (src/app.js:19)
  medium        Database driver error text returned to callers    (src/app.js:12)
  low           GET /ping spawns an unbounded shell process ...   (src/app.js:24)
```

All four planted bugs were found, plus two genuine ones that were not planted. During validation the scan installed `express` and `mysql` into a scan-local sandbox, served the unmodified app over real HTTP on loopback, and exercised the routes with crafted requests — the SARIF results carry executed-harness evidence, not just static reasoning. The scanned repository's working tree was untouched (`git status` clean). The sealed manifest carries 9 artifact digests; the SARIF is valid 2.1.0 with 6 rules and 6 results.

Deep mode was verified separately on the same target with `--workers 2 --stop-after-no-new 2 --max-discovery-runs 4`:

```
terminalReason: capped   discoveryPasses: 4   reductionRounds: 2
mergedWorkerIds: 4       failedWorkerIds: 0   omittedWorkerIds: 0
coverage: complete       mode: deep_repository
sealed artifacts: 25     hardening: hardening/hardening.md
```

Both reductions claimed their discovery results in the order the workbench buffered them, four discovery workers merged cleanly, and the run went terminal at the configured pass ceiling. The tail produced six per-finding write-ups and a full hardening portfolio. Deep mode is meaningfully more expensive than a standard scan — seven Claude sessions instead of one — so its pass ceiling and worker count are worth setting deliberately.

## What changed from Codex Security

**Replaced**

| Codex | Here |
| --- | --- |
| `@openai/codex-sdk` thread runner | `claude --print --output-format stream-json` |
| ChatGPT / `OPENAI_API_KEY` sign-in | Claude Code subscription OAuth |
| Plugin install into `$CODEX_HOME` via a synthetic marketplace | `--plugin-dir`, session-scoped |
| MCP app tools (`open_codex_security_workspace`, `complete_codex_security_scan`, …) | The CLI owns registration, sealing, and reporting |
| `config_preflight.py` reading Codex `config.toml` (sandbox, approval policy, multi-agent v2) | Capability preflight over the session's actual tool surface |
| `start_codex_security_deep_scan` spawning `codex exec` workers | CLI deep-scan coordinator spawning `claude --print` workers |
| `gpt-5.6-terra` + `--effort` | `claude-opus-5` + `--effort` (Claude Code's own effort levels) |

**Kept unchanged** — the whole analytical core: all 13 phase skills, the validation guidance, the severity policy, the attack-path rubric, the scan contract and JSON schemas, the SQLite workbench, scan comparison and history, and the deterministic report/SARIF projection.

**Kept deliberately stable**: the on-disk contract identifiers (`documentType: "codex-security.*"`, `fingerprints.algorithm: "codex-security/v1"`). These are schema `const` values shared by the validators, the SARIF adapter, and the scan-comparison logic. Renaming them would buy nothing functional, risks subtle breakage across the Python, and would make results non-interchangeable with the upstream tool. The human-facing names (SARIF tool driver, producer, report text) are rebranded.

## Configuration

| Variable | Purpose |
| --- | --- |
| `CLAUDE_SECURITY_STATE_DIR` | Workbench database and scan history (default `~/.claude/state/plugins/claude-security`) |
| `CLAUDE_SECURITY_SCAN_ROOT` | Where scan bundles are written (default a temp directory) |
| `CLAUDE_SECURITY_CLAUDE_PATH` | Full path to the `claude` executable |
| `CLAUDE_SECURITY_ALLOW_API_KEY` | Set to `1` to allow `ANTHROPIC_API_KEY` and bill as API usage |
| `PYTHON` | Python interpreter for the plugin helpers |

## Safety properties

- The scan **cannot write into the repository it audits**: `Write`/`Edit`/`NotebookEdit` are denied under the repository root, and the output directory is rejected if it resolves inside the target.
- Scan sessions run with `--setting-sources ""`, so your personal hooks, `CLAUDE.md`, and project settings cannot inject instructions into a scan prompt or change what gets reported.
- Documents supplied with `--knowledge-base`, repository content, and stored reviewer feedback are all passed as **untrusted analysis data**, never as instructions.

## Limitations

- **Cost reporting** is the API-equivalent estimate Claude Code emits. On a subscription you aren't billed per token; treat it as a relative measure of scan size.
- **`--knowledge-base`** passes documents through by path rather than converting them. Claude Code reads PDFs and text natively; exotic binary formats that the upstream tool converted are not pre-processed.
- **Containerized bulk scans** and the `bulk-scan` / `install-hook` subcommands from the upstream CLI are not ported.
- **Resuming an interrupted deep scan** is not implemented; the workbench state survives, but the CLI starts a fresh scan.

## Re-porting from upstream

`tools/port-plugin.mjs` performs the mechanical rebranding pass over `plugin/` (skill invocation syntax, environment variable names, product naming). It is idempotent and documents what it deliberately does *not* rewrite. The orchestration-heavy files — the three top-level scan skills and the capability preflight — were rewritten by hand afterwards and should not be regenerated.

## License

Apache-2.0, inherited from the upstream project.
