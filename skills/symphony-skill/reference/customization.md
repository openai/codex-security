# Customizing the workflow — multi-stage lanes + per-state prompts

Symphony does **not** hardcode the canonical "Todo / In Progress / Done"
workflow. The orchestrator treats state strings opaquely; what columns
exist and what the agent should do in each is entirely up to the operator.

Before hand-editing lanes, consider the shipped **lane presets**: the
succinct 4-lane default (`Todo → In Progress → Verify → Document`) and the
8-lane deep pipeline (`Intake → Research → Plan → Review → Build → QA →
Verify → Document`). Apply one from the admin UI settings page or
`POST /api/v1/workflow/presets/apply`; the switch round-trips through the
same comment-preserving machinery as the edits below, and everything here
still works afterwards.

## Add or rename lanes

Edit `tracker.active_states` and `tracker.terminal_states`. The TUI builds
columns from `active_states + terminal_states` in declared order
(`tui.py:212`). For a deploy pipeline:

```yaml
tracker:
  kind: file
  board_root: ./kanban
  active_states:
    - Reproduce
    - Todo
    - "In Progress"
    - Verify
    - "Deploy Ready"
    - Deployed
    - Verified
  terminal_states:
    - Done
    - Cancelled
    - Blocked

agent:
  kind: claude
  max_concurrent_agents: 1
  max_concurrent_agents_by_state:
    "Deploy Ready": 1     # never deploy two things at once
    Verified: 1
```

`symphony board mv TASK-1 "Deploy Ready"` quotes are required for
multi-word state names. The agent transitions states from inside its
prompt by rewriting the ticket file's frontmatter `state:` field.

## Per-state default system prompt (lane-specific behavior)

Prefer external prompt files in `WORKFLOW.md`:

```yaml
prompts:
  base: ./docs/symphony-prompts/file/base.md
  stages:
    Reproduce: ./docs/symphony-prompts/file/stages/reproduce.md
    Todo: ./docs/symphony-prompts/file/stages/todo.md
    Verify: ./docs/symphony-prompts/file/stages/verify.md
    "Deploy Ready": ./docs/symphony-prompts/file/stages/deploy-ready.md
    Deployed: ./docs/symphony-prompts/file/stages/deployed.md
```

At runtime Symphony assembles `base` plus only the current state's stage
file. A ticket entering `Verify` automatically receives `verify.md` on the
next fresh first-turn prompt; unrelated lane rules are not sent.

Stage prompt files are still strict Liquid templates, so they can use the
same variables as the legacy body:

```liquid
## Stage: Verify

You are reviewing {{ issue.identifier }}: {{ issue.title }}.

- Read the diff against `main`. Check tests, security, style, and merge proof.
- Append `## Review` with findings.
- If green, set `state` to `Deploy Ready`. Otherwise set `state` to `In Progress`.
```

### Legacy inline branching

The inline body below the YAML frontmatter still works as a fallback. Use
it when you need a single-file bootstrap template or a tiny demo. It
re-renders on every turn, and `issue.state` is exposed to the template, so
branching by current lane can still give each lane its own instructions:

```liquid
You are picking up ticket {{ issue.identifier }}: {{ issue.title }}.
Current state: {{ issue.state }}.

{% if issue.state == "Reproduce" %}
## Stage: Reproduce
- Your only goal is to write a failing test that reproduces the bug.
- Do NOT fix anything. Stop after the test fails reliably.
- When done, set the ticket `state` to `Todo`.

{% elsif issue.state == "Verify" %}
## Stage: Verify
- Read the diff against `main`. Check tests, security, style, and merge proof.
- Append `## Review` with findings.
- If green, set `state` to `Deploy Ready`. Otherwise `state` to `In Progress`.

{% elsif issue.state == "Deploy Ready" %}
## Stage: Deploy
- Run `make deploy-staging`. Capture the build URL.
- Append `## Deploy` with the URL. Set `state` to `Deployed`.

{% elsif issue.state == "Deployed" %}
## Stage: Verify
- Run smoke tests against the URL in `## Deploy`.
- If green, set `state` to `Verified`. Otherwise `state` to `Blocked`.

{% else %}
## Default
{{ issue.description }}
When done, set `state` to `Done` and append `## Resolution`.
{% endif %}
```

The fallback is backward-compatible, but avoid growing it into a giant
all-stage prompt. Split substantial lane behavior into `prompts.stages`
files so each turn stays focused and smaller.

## What customization does *not* (yet) support

| Want                                                | Status | Notes                                                                       |
|-----------------------------------------------------|--------|-----------------------------------------------------------------------------|
| Per-state agent kind (e.g. gemini for Todo, claude for In Progress) | yes | `agent.stage_kinds` maps states to kinds; ticket `agent_kind` pin still wins. See `reference/workflow-config.md`. |
| Per-state turn limits / timeouts                    | no | Globals (`agent.max_turns`, `<kind>.turn_timeout_ms`). PR territory to add. |
| Auto-progression without an agent edit              | partial | Only operator controls such as Skip Document do this. Other lanes require the agent to rewrite `kanban/<ID>.md` `state:`. |
| Hard ordering between tickets                       | yes | `blocked_by` in ticket frontmatter gates dispatch until every blocker resolves; `symphony board new --blocked-by` validates edges and keeps the DAG acyclic. |

## Available template variables

The renderer exposes these to the body (see `prompt.py` + `issue.py`):

| Variable                  | Type    | Notes                                                |
|---------------------------|---------|------------------------------------------------------|
| `{{ issue.identifier }}`  | string  | e.g. `TASK-1`                                        |
| `{{ issue.title }}`       | string  |                                                      |
| `{{ issue.description }}` | string  | full ticket body minus frontmatter                   |
| `{{ issue.state }}`       | string  | current lane                                         |
| `{{ issue.priority }}`    | int     | nullable                                             |
| `{{ issue.labels }}`      | list    | use `{{ labels \| join: ", " }}`                     |
| `{{ issue.blocked_by }}`  | list    | each item has `.id`, `.identifier`, `.state`         |
| `{{ issue.agent_kind }}`  | string  | per-ticket backend override, or empty when global    |
| `{{ attempt }}`           | int     | retry attempt; null on first try                     |

Unknown variables / filters intentionally raise `TemplateRenderError` —
typos surface immediately rather than silently emitting empty strings.
