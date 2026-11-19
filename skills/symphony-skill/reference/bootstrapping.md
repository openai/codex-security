# Bootstrapping Symphony into another project

Use this when introducing Symphony to a repo that does not already carry the
standard operator bundle. The Symphony source checkout is protected and must
not be used as the project repository.

## Preferred: create or register a project

```bash
symphony project create "My App" --path ../my-app
# Or bootstrap an existing repository first, then register it:
symphony project add /path/to/existing-repo --name "My App"
symphony hub
```

`project create` copies the required bundle into a new Git repository and
registers its independent service. Use the manual copy procedure below only
when adapting an existing repository that needs a customized bundle.

## Manual: copy the full operator bundle

From inside the `oh-my-symphony` checkout:

```bash
TARGET=/path/to/target-project
cp tui-open.sh tui-open.bat "$TARGET/"
# Pick the example that matches the tracker you will use:
#   file board (Markdown tickets in the repo, the default) -> WORKFLOW.file.example.md
#   Linear                                                 -> WORKFLOW.example.md
cp WORKFLOW.file.example.md "$TARGET/WORKFLOW.md"         # then edit
mkdir -p "$TARGET/docs" "$TARGET/scripts"
cp -R docs/symphony-prompts "$TARGET/docs/"
cp scripts/symphony-setup-worktree.sh "$TARGET/scripts/"  # required by default after_create hook
chmod +x "$TARGET/scripts/symphony-setup-worktree.sh"
cp -R skills "$TARGET/"
cp AGENTS.md GEMINI.md "$TARGET/"
mkdir -p "$TARGET/.claude/skills"
ln -s ../../skills/symphony-skill "$TARGET/.claude/skills/symphony-skill"
chmod +x "$TARGET/tui-open.sh"
```

> Note: The browser board is the built-in admin web app served on the
> orchestrator `--port` — nothing extra to copy for it.

> Claude workers need `--permission-mode acceptEdits` (unattended file writes)
> and `--add-dir "$SYMPHONY_WORKFLOW_DIR/<board-root>"` (writes through the
> host-board link). Both shipped examples now carry them; if you hand-write a
> `claude.command`, keep them or the worker silently fails to move tickets and
> the orchestrator re-dispatches forever. The CLI-driven lanes
> (`symphony board new/update`) additionally need a permission mode that
> allows Bash — `symphony doctor` reports this as `board.cli`.

Copy `tui-open.sh` and `tui-open.bat` even for headless-first setups. The
launcher carries safety behavior that plain `symphony tui` does not: port
collision checks, doctor preflight, venv-first binary lookup, and real terminal
window spawning.

If the target project has no virtualenv, either install Symphony globally or
prepare a local one so the launcher can find it:

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e <oh-my-symphony>
```

## Why these files matter

| File or directory | Purpose |
| --- | --- |
| `WORKFLOW.md` | Runtime config and prompt entrypoint |
| `docs/symphony-prompts/` | Worker prompts; dispatched agents read these |
| `skills/symphony-skill/` | Canonical operator router skill |
| `skills/symphony-skill/oneshot/`, `skills/symphony-skill/monorepo/` | Router branch subfolders for templates, scripts, and references |
| `.claude/skills/symphony-skill` | Claude Code discovery symlink to the router |
| `AGENTS.md` | Codex entrypoint pointing to repo skills |
| `GEMINI.md` | Gemini entrypoint pointing to repo skills |
| `tui-open.sh`, `tui-open.bat` | One-shot board launchers |
| `scripts/symphony-setup-worktree.sh` | Worktree-setup body invoked by the default `after_create` hook in both WORKFLOW examples. Without it, every fresh ticket dispatch fails at the hook stage with `No such file or directory`. |

`skills/symphony-skill/SKILL.md` is the only operator activation route. Edit
only the canonical files under `skills/`; platform entrypoints should point at
them.

## Preserve the default pipeline

Both WORKFLOW examples ship with the supported production flow:

```text
Todo -> In Progress -> Verify -> Document -> Done
```

Do not trim it to a smaller lane set unless the user explicitly asks. The base
prompt names these stages, Verify is the compulsory review/QA/merge gate, and
Document writes back to `docs/llm-wiki/` for future tickets. `Human Review` is an
intervention-only terminal state for explicit operator review or critical
manual decisions; agents should not use it as the normal completion path.

If the target project truly needs a different workflow, edit these together:

- `tracker.active_states`
- `tracker.terminal_states`
- `prompts.stages`
- the matching stage files under `docs/symphony-prompts/<flavor>/stages/`

Use `reference/customization.md` for lane and prompt changes.

## Pick the prompt flavor

- `tracker.kind: file` uses `docs/symphony-prompts/file/...`; the agent writes
  stage notes into the ticket file body. Bootstrap from
  `WORKFLOW.file.example.md`.
- `tracker.kind: linear` uses `docs/symphony-prompts/linear/...`; the agent
  writes stage notes as Linear comments. Bootstrap from `WORKFLOW.example.md`.

Copy only the flavor you need if you want a smaller target repo. Copying both
is fine when simplicity matters more than disk hygiene.

## First launch

Foreground board view:

```bash
./tui-open.sh
./tui-open.sh path/to/WORKFLOW.md
tui-open.bat
```

For managed headless operation and the admin web app, use
`reference/operations.md`.
