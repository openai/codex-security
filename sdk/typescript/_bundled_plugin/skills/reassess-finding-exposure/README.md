# Reassess finding exposure

Reassess an existing finding against a code revision, separating exposure, impact and escalation. Static review by default: no new scan, patch or automatic notification.

## Install in Codex

Copy this prompt into Codex:

```text
$skill-installer install reassess-finding-exposure from https://github.com/openai/codex-security/tree/defense-factory/reference-skills/sdk/typescript/_bundled_plugin/skills/reassess-finding-exposure
Use --repo openai/codex-security --ref defense-factory/reference-skills --path sdk/typescript/_bundled_plugin/skills/reassess-finding-exposure
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
