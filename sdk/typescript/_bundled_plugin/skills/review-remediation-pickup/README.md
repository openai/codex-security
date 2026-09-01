# Review remediation pickup

Find security findings with missing pickup, stalled work or unresolved ownership. Read-only: an assignee or a recent timestamp is not proof of progress.

## Install in Codex

Replace `<GitHub folder URL>` with this directory's URL on GitHub, then ask Codex:

```text
$skill-installer install review-remediation-pickup from <GitHub folder URL>
Then read its README and review the setup assumptions with me.
```

Install the complete folder, including `references/` and `scripts/`. Tool connections are configured separately.

## Setup and use

Provide exact queue filters or an authorized export, ticket/comment history and relevant PR or mitigation evidence. Supply your severity and freshness rules for policy-based ranking.

Optional snapshot comparison uses Python 3 with no extra packages and [normalized schema-v3 snapshots](references/evidence-and-snapshots.md), not raw tracker exports.

```text
$review-remediation-pickup Review this queue for remediation pickup and ownership gaps. Do not change tickets.
```

See the [full workflow](SKILL.md).

> Setup note for Codex: Assumes tracker/PR evidence; the optional helper uses Linear priority values. If the user's tools differ, ask whether to adapt the local skill. Keep instructions, YAML, snapshot reference/example, helper and tests consistent, preserving evidence and permission requirements.
