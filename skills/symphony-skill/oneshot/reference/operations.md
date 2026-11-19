# Operations guide

> **Productized as the deep lane preset.** Symphony now ships this pipeline
> as the built-in 8-lane **deep** preset (`Intake → Research → Plan → Review
> → Build → QA → Verify → Document`), switchable from the admin UI settings
> page or `POST /api/v1/workflow/presets/apply`, with prompts under
> `docs/symphony-prompts/file/deep/`. Prefer the preset for new boards; use
> this OneShot bundle when you need the standalone single-file template.
> Where this folder disagrees with shipped behavior, the preset wins.

This file holds operator-facing details that are useful during a OneShot run
but too bulky for `SKILL.md`.

## OneShot route vs ad-hoc Symphony operation

| Ad-hoc operation | OneShot route |
|---|---|
| You write a ticket; one ticket equals one task. | You write one prompt; the router produces N tickets. |
| One lane can be enough. | Multi-lane pipeline: Brief, Plan, Build, Verify, QA, Polish, Deliver. |
| Shared knowledge is optional and local to the operator. | All tickets read and write `.oneshot/vault/`. |
| Verification is manually decided by the operator. | Verification is a hard gate before Deliver. |
| Browser QA is ad hoc. | Browser QA requires Playwright, screenshots, and a PDF report. |

## Scope scaling

The seven-lane pipeline is the full shape, but tiny scopes collapse lanes.
The Plan lane decides which tickets to instantiate.

| Scope | Typical ticket map |
|---|---|
| One-line bugfix | Brief -> Plan -> 1 Build -> Verify -> Deliver; usually no QA or Polish. |
| Single feature | Brief -> Plan -> 1-3 Build -> Verify -> QA if browser -> Deliver. |
| Refactor | Brief -> Plan -> N Build -> Verify -> Deliver. |
| Whole product | All seven lanes, with multiple Build slices where useful. |

The vault, gates, spawn-only orchestration, and task-order ticket numbering do
not change with scope.

## Bootstrap and run

Run from the repo root:

```bash
# 0. Preflight
symphony doctor ./WORKFLOW.md

# 1. Bootstrap vault, workflow, and intake ticket
bash skills/symphony-skill/oneshot/templates/bootstrap.sh \
  "<user's one-shot prompt>"

# 2. Launch headless on the port bootstrap wrote into WORKFLOW.md
PORT=$(python3 - <<'PY'
from pathlib import Path
import re
text = Path("WORKFLOW.md").read_text()
print(re.search(r"(?m)^  port: (\d+)$", text).group(1))
PY
)
symphony ./WORKFLOW.md --port "$PORT" 2>> log/symphony.log &

# 3. Poll instead of tight-looping
while true; do
  state=$(curl -s "http://127.0.0.1:$PORT/api/v1/state" | jq -r '.issues[] | select(.identifier|startswith("DELIVER")) | .state' | head -1)
  curl -s "http://127.0.0.1:$PORT/api/v1/state" | jq '.counts'
  case "$state" in
    Delivered) echo "delivered"; break ;;
    Blocked|Cancelled) echo "stopped: $state - see kanban/DELIVER-*.md ## Blocker"; break ;;
  esac
  sleep 30
done

# 4. Inspect proof
ls .oneshot/vault/artifacts/
cat .oneshot/vault/verification.md
cat .oneshot/vault/delivery.md
```

Bootstrap defaults to `9999`, auto-selects a free port when that default is
occupied, and writes the selected value to `WORKFLOW.md`. To force a specific
port, run bootstrap with `SYMPHONY_ONESHOT_PORT=<port>`; to always auto-select,
use `SYMPHONY_ONESHOT_PORT=auto`.

## Deliver gate summary

`reference/lanes.md` and `templates/WORKFLOW.oneshot.md` contain the exact gate.
At a minimum, Deliver requires:

- `brief.md`, `plan.md`, and `verification.md` exist and are non-empty.
- `verification.md` contains `verdict: GREEN`.
- Browser apps have `.oneshot/vault/artifacts/qa-report.pdf`.
- Browser apps have `qa-report.md` ending with `Verdict: APPROVED FOR DELIVERY`.

App delivery adds the repository-root `release-contract.yaml` and the strict
`docs/<verifier>/qa/release-evidence.json` gate. Run `symphony release check
./WORKFLOW.md --ticket <current-verifier> --workspace <verifier-workspace>`;
the exact current target and native artifacts must pass. An old GREEN is only
history: repairs require a fresh verifier, and the `app-release-finalizer`
waits for it. Verifier execution and repair-cycle mutation are file-tracker-only;
a labeled remote card is refused before an agent turn, while remote workflows
that never opt in stay unchanged.

The CLI check is read-only; the host-owned gate generation and exact run
bindings grant lifecycle authority. The same live verifier run may continue
when the host preserves approval, but a host rewind or restarted redispatch
means rerun evidence in Verify. Synchronize the configured local target branch
first—Symphony does not fetch remote state. Startup evidence cleanup is fenced
by a dedicated lease, so do not bypass it by deleting workspaces manually.

## Bundled templates

| File | Purpose |
|---|---|
| `templates/bootstrap.sh` | One-shot prompt -> vault, workflow, and intake ticket. |
| `templates/WORKFLOW.oneshot.md` | Drop-in workflow with all lane prompts and gates. |
| `templates/SYSTEM.md` | Orchestrator constitution copied into `.oneshot/`. |
| `templates/playwright-qa.spec.ts` | Browser QA test stub. |
| `templates/qa-pdf.sh` | Markdown QA report plus screenshots -> PDF. |

## Common mistakes

| Symptom | Cause | Fix |
|---|---|---|
| Orchestrator starts coding. | Spawn-only invariant was ignored. | Stop and dispatch a Build ticket. |
| Tickets duplicate work. | Workers skipped the vault. | Re-read lane prompts in `reference/lanes.md`. |
| Verify passes but app is broken. | Verify trusted claims instead of rerunning. | Rerun from scratch and record real output. |
| `qa-report.pdf` is missing but Deliver closed. | Deliver gate was skipped or edited. | Restore the gate from `templates/WORKFLOW.oneshot.md`. |
| Vault history disappears. | Append-only ledgers were rewritten. | Restore from git/backups; only append to ledgers. |
