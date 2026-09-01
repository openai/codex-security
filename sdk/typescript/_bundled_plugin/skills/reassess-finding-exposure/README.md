# Reassess finding exposure

Reassess an existing finding against a code revision, separating exposure, impact and escalation. Static review by default: no new scan, patch or automatic notification.

## Install in Codex

Replace `<GitHub folder URL>` with this directory's URL on GitHub, then ask Codex:

```text
$skill-installer install reassess-finding-exposure from <GitHub folder URL>
Then read its README and review the setup assumptions with me.
```

Install the complete folder, not just `SKILL.md`. Tool connections are configured separately.

## Setup and use

Provide the finding, a local Git repository and your security/severity and escalation policy. The default revision is committed `HEAD`; deployment claims need separate evidence. Missing policy leaves severity and escalation unassessed.

```text
$reassess-finding-exposure Reassess this finding in this repository using the attached policy.
```

See the [full workflow](SKILL.md).

> Setup note for Codex: Assumes local Git/source access and supplied severity/escalation rules. If the user's setup differs, explain the mismatch and ask whether to adapt the local skill. Keep its instructions and YAML prompt consistent, preserving evidence and permission requirements.
