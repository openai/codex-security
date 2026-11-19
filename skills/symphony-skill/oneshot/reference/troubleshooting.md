# Troubleshooting

## The orchestrator session keeps writing code

**Symptom**: You (the Claude session that ran `bootstrap.sh`) start
implementing files instead of dispatching tickets.

**Cause**: SYSTEM.md invariant #1 not re-read.

**Fix**: Stop. `cat .oneshot/SYSTEM.md`. Open `symphony-skill` skill's
delegation pattern. The orchestrator's only legal moves are:
`symphony board new`, `symphony board mv`, `cat .oneshot/vault/*`, polling
the API. If you need to change code, dispatch a Build ticket.

## Tickets created but no worker picks them up

```bash
# Diagnose
symphony doctor ./WORKFLOW.md
ps aux | grep symphony
PORT=$(python3 - <<'PY'
from pathlib import Path
import re
text = Path("WORKFLOW.md").read_text()
print(re.search(r"(?m)^  port: (\d+)$", text).group(1))
PY
)
curl -s "http://127.0.0.1:$PORT/api/v1/state" | jq '.counts, .running'
tail -50 log/symphony.log
```

Common causes:
- Server not running → `symphony ./WORKFLOW.md --port "$PORT" 2>> log/symphony.log &`
- Port collision → rerun bootstrap with `FORCE=1 SYMPHONY_ONESHOT_PORT=auto`, or set an explicit free `SYMPHONY_ONESHOT_PORT=<port>`
- `agent.kind` mismatched to installed CLI → `which claude`/`which codex`
- `tracker.active_states` doesn't include the lane name (e.g. typo `Build` vs `build`) → fix YAML

## Worker exits with `worker_exit reason=error`

```bash
# Find the failing ticket and read its workspace logs
curl -s "http://127.0.0.1:$PORT/api/v1/state" | jq '.errors'
ls ~/symphony_workspaces/<TICKET-ID>/.symphony/
```

Top causes:
- `after_create` hook failed (e.g. `git clone` against placeholder URL) → fix WORKFLOW.md hooks; the OneShot template uses `: noop` so this shouldn't apply unless you changed it
- Agent CLI authentication missing (`claude` not logged in, `codex` no API key) → fix and restart
- Workspace disk full → `du -sh ~/symphony_workspaces/*`

## Vault grows unbounded / claims.md is huge

**Cause**: Probably correct — append-only ledgers grow. If it's actually
problematic (>50MB), workers are doing too many turns per ticket. Check:
```bash
wc -l .oneshot/vault/claims.md .oneshot/vault/verification.md
```
If a single ticket has >20 entries, raise `agent.max_turns` is the wrong
fix — split the ticket via the Plan lane instead.

## Verify lane keeps RED'ing the same Build ticket

Look at `verification.md` — it must cite the *exact discrepancy*. If it
just says "tests failed" without specifics, the Verify prompt isn't being
followed. Re-paste the Verify lane prompt from `templates/WORKFLOW.oneshot.md`.

If the discrepancy is real and the Build worker can't reproduce it: there's
likely environment drift between Verify's workspace and Build's. Run:
```bash
diff <(ls ~/symphony_workspaces/BUILD-N) <(ls ~/symphony_workspaces/VERIFY-1)
```
The OneShot pattern assumes hooks bring both workspaces to the same
baseline. If `before_run: git fetch && git reset --hard origin/main` is
missing, add it.

## QA lane produces PDF but Deliver gate fails on hash

**Cause**: `qa-report.md` was edited after `qa-pdf.sh` ran, so the live
hash no longer matches the one logged to `verification.md`.

**Fix**: Re-run QA lane. Discipline: nobody edits `qa-report.md` after the
PDF is generated. If a real issue is found, set the Build ticket back to
`Build` and let it re-flow through QA.

## Deliver lane says `verify not green` but verification.md looks fine

```bash
grep '^verdict:' .oneshot/vault/verification.md
```
The gate looks for a line starting with `verdict: GREEN` (case-sensitive,
no leading whitespace). If your verifier wrote `Verdict: green` or
indented it, the grep fails. Either fix verification.md to match or relax
the gate (not recommended — strict gates are the point).

## Loop terminates with tickets still in non-terminal states

```bash
symphony board ls
```
If anything is in `Blocked` or has been retrying past `agent.max_turns`,
the loop won't make progress. Look at the kanban file's `## Blocker`
section — that's the agent telling you why. Common: external blocker
(needs API key, needs human decision). Resolve, then `symphony board mv
<ID> Build` (or whatever lane is appropriate) to unblock.

## Browser app QA — Playwright can't find the dev server

```bash
# Check the brief.md "How to run" section is correct
grep -A5 'How to run' .oneshot/vault/brief.md
# Test manually
curl -I http://localhost:3000   # or whatever port
```
The QA lane prompt assumes the app is running on a known URL. If
`brief.md` doesn't pin the URL, the QA worker either guesses wrong or
starts the app in a way that races with its own tests. Fix `brief.md`
(via the Brief lane re-running, or by hand) and re-flow.

## Cost is exploding

OneShot acknowledges: this pattern uses many tokens. Per-ticket fresh
context windows + autonomous looping + verify reruns multiply costs.

Mitigations:
- `agent.max_turns: 10` (default 20) caps runaway loops.
- Set `agent.kind: claude` with `claude.command` using Haiku for
  Build/Verify lanes if your decomposition is fine-grained — Haiku 4.5 is
  ~3× cheaper at ~90% Sonnet performance.
- Cap `agent.max_concurrent_agents_by_state.Build` to limit parallel burn.
- Stop the loop early once you're satisfied with delivery proof; the
  pattern doesn't require Polish/Deliver if the artifacts already meet
  your threshold.

## I want to abort the run

```bash
# Stop the orchestrator process you launched for this WORKFLOW.md.
ps aux | grep 'symphony ./WORKFLOW.md'
symphony board ls                 # see what's where
# Optionally archive vault for later inspection
mv .oneshot .oneshot.aborted-$(date +%s)
```

## Getting unstuck — escalation path

1. Read `.oneshot/vault/decisions.log` — recent design pivots may explain.
2. Read the failing ticket's kanban file's `## Blocker` / `## Issues`.
3. Read `verification.md` for the most recent verdict.
4. Read `qa-report.md` for the most recent QA findings.
5. If still stuck, manually transition the offending ticket back to an
   earlier lane and let it re-flow.
6. Last resort: `symphony board mv <ID> Cancelled` and re-decompose via
   a fresh Plan ticket.
