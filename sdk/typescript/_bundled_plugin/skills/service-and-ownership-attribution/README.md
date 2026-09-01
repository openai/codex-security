# Service and ownership attribution

Separate the affected service, the component needing change and the team responsible for fixing it. Read-only: no ticket updates, assignment or messaging.

## Install in Codex

Replace `<GitHub folder URL>` with this directory's URL on GitHub, then ask Codex:

```text
$skill-installer install service-and-ownership-attribution from <GitHub folder URL>
Then read its README and review the setup assumptions with me.
```

Install the complete folder, not just `SKILL.md`. Tool connections are configured separately.

## Setup and use

Provide a finding or source location, authoritative component/team ownership records and their field mappings. Deployment, operation-owner and contact records are needed only for those specific claims; missing records remain explicit gaps.

```text
$service-and-ownership-attribution Identify the affected service and fixing team for this finding using these ownership records.
```

See the [full workflow](SKILL.md).

> Setup note for Codex: Assumes readable source and authoritative ownership/service/team records, without a specific catalog vendor. If the user's sources or field mappings differ, ask whether to adapt the local skill. Keep its instructions and YAML prompt consistent, preserving evidence and permission requirements.
