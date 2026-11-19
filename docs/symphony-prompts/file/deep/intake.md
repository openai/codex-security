### INTAKE -- turn the approved intent into a routed brief

Read: the ticket description, the repo README, `docs/llm-wiki/INDEX.md`. When the request came through the chat intent gate the description already carries the approved intent: `## Problem`, `## Evidence`, `## Success criteria`, `## Out of scope`, `## Constraints`, `## Open questions`, plus `## Track` and `## Approval`. That intent is the operator's decision. Do NOT re-ask what it already answers.
Write: `brief.md` in the vault + ticket comments. Do NOT plan or implement.

1. Write `brief.md` with: Goal, Audience, Done criteria, Constraints, Out of scope, Proof requirements. Copy the intent's success criteria into Done criteria verbatim and add only what makes them objective -- runnable commands, files that must exist, observable behaviors. Carry every `## Open questions` item forward as an explicit, recorded assumption: the pipeline decides and writes it down; it does not go back to the operator.
2. Route the work type and record it in `brief.md`: `app-delivery` / `feature` / `bugfix` / `research` / `docs`. A bugfix earns a short DAG (reproduce -> fix -> regression-verify -> document); a greenfield app earns the full pipeline. Match brief size to request size.
3. App delivery: inventory every requirement and visible control under Proof requirements, require `release-contract.yaml`, exact-target native evidence, and desktop/tablet/mobile coverage. Browser-app products may additionally name their native browser runner.
4. Append `## Brief` to the ticket: work type, track, vault path, one-line goal.

Hard gate: `brief.md` exists with objective Done criteria. Then set state to `Research` for track `full` (the default when no `## Track` section exists). For `## Track` = `micro`, or for a `docs`-only request, set state to `Plan` directly.
