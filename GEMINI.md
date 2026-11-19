# GEMINI.md: Gemini CLI entry point

This repository is a **Symphony-managed project**. Symphony
(`oh-my-symphony`) is a separate control-plane checkout that dispatches coding
agents (Codex / Claude Code / Gemini / AGY / Kiro / OpenCode / Pi / Prime
Agent) at the Kanban board in this repository. This file is the discovery
point Gemini CLI reads on startup.

## What Symphony added here

- `WORKFLOW.md`: board states, agent backend, hooks, and prompt routing.
- `kanban/`: one Markdown file per ticket; the `state:` frontmatter is the
  board column.
- `docs/symphony-prompts/`: stage prompts rendered into each worker turn.
- `scripts/symphony-setup-worktree.sh`: provisions the per-ticket
  `symphony/<ID>` worktree.
- `skills/symphony-skill/`: the operator skill (routing, troubleshooting,
  customization). `.claude/skills/` is a thin symlink layer for Claude Code.
  Edit the canonical files under `skills/`.

Everything else in this repository is the product. Treat it as the user's
code, not as Symphony's.

## Skill activation

Gemini activates Symphony through one operator skill: read the
`description` in `skills/symphony-skill/SKILL.md` (via `read_file`), then
follow its route table when the user asks to add, list, or move tickets,
launch the TUI or web board, inspect orchestrator state, customize lanes or
per-state prompts, delegate sub-tasks, or diagnose dispatch failures.

## Worker-side guidance

Dispatched Gemini workers (running inside a per-ticket worktree) do **not**
consume the operator skill. Worker behavior comes from `WORKFLOW.md`'s
`prompts.base` + `prompts.stages` map, rendered from
`docs/symphony-prompts/<flavor>/`.

## Tool mapping

The skill files use Claude Code tool names. The Gemini equivalents:

| Claude Code  | Gemini CLI              |
|--------------|-------------------------|
| `Read`       | `read_file`             |
| `Bash`       | `run_shell_command`     |
| `Edit`       | `edit` / `replace_file_content` |
| `Glob`       | `glob`                  |
| `Grep`       | `search_file_content`   |
| `Skill`      | `activate_skill`        |

## Conventions

- Read `WORKFLOW.md` and a couple of `kanban/*.md` files before any
  recommendation. Settings vary per project.
- Run `symphony doctor ./WORKFLOW.md` before launching anything.
- Never hard-reset a worker worktree between turns; turns are committed in
  place and a reset discards in-progress work.
