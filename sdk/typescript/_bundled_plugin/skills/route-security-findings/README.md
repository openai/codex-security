# Route security findings

Route existing Linear findings to the team that can fix them. Can update labels, assign people and post explanatory comments; start with a dry run.

## Install in Codex

Copy this prompt into Codex:

```text
$skill-installer install route-security-findings from https://github.com/openai/codex-security/tree/defense-factory/reference-skills/sdk/typescript/_bundled_plugin/skills/route-security-findings
Use --repo openai/codex-security --ref defense-factory/reference-skills --path sdk/typescript/_bundled_plugin/skills/route-security-findings
Then read its README and review the setup assumptions with me.
```

Install the complete folder, including `references/`. The ownership procedure is bundled; no separate skill install is needed. Tool connections are configured separately.

## Setup and use

- Connect Linear with issue/history reads and permission for the specific writes you request.
- Supply issue IDs or queue filters, authoritative ownership/team records and a confirmed team-to-DRI mapping with its field and confirmation rules.
- For label changes, confirm the `owner:`, `area:` and `service:` conventions fit your team. Assignment-only and labels-only modes are supported.

```text
$route-security-findings Dry-run these issues using this owner mapping. Do not change labels, assignees or comments.
```

See the [full workflow](SKILL.md).

> Setup note for Codex: Assumes Linear, a confirmed owner-to-DRI mapping and the label conventions above. For another tracker or schema, explain the mismatch and ask whether to adapt the local skill. Keep instructions, YAML and bundled references consistent, preserving evidence and permission requirements.
