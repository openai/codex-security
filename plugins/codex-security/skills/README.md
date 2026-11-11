# Codex Security skills

With the plugin enabled, tell Codex what you want to check and point it to the code, report, or finding. To pick a skill directly, use its name in your request, for example, `$security-diff-scan Review my uncommitted changes for vulnerabilities.`

## Choose a scan

- [security-scan](security-scan/SKILL.md) — Check a repository or folder for vulnerabilities in one pass. “Scan the authentication code.”
- [security-diff-scan](security-diff-scan/SKILL.md) — Look for vulnerabilities in a change. Give it a PR, commit, branch diff, or local edits.
- [deep-security-scan](deep-security-scan/SKILL.md) — Run several passes over a repository or folder for a more thorough audit. “Deep scan the payments directory.”

## Understand the system or investigate a finding

A scan uses several of these skills along the way. You can also ask for an individual step.

- [define-security-policy](define-security-policy/SKILL.md) — Write or update `SECURITY.md` to tell reviewers what to cover and what the code must protect.
- [threat-model](threat-model/SKILL.md) — Map what needs protecting, who can reach it, and where an attack could start. “Create a threat model for the upload service.”
- [threat-model-visualize](threat-model-visualize/SKILL.md) — Explore an existing threat model as an interactive diagram. Point it to the model or ask to see one from the last scan.
- [finding-discovery](finding-discovery/SKILL.md) — Identify possible vulnerabilities for further investigation. Point it to the code or change you want examined.
- [triage-finding](triage-finding/SKILL.md) — Compare a reported issue with the code and security policy to see whether it applies. Supply the alert, report, or ticket.
- [validation](validation/SKILL.md) — Check whether a suspected vulnerability holds up. “Can you verify the access-control issue described in this finding?”
- [attack-path-analysis](attack-path-analysis/SKILL.md) — Trace how an attacker could reach the vulnerable code and what they could do there. Give it a finding to assess for impact and severity.

## Review a change, dependency, or skill

- [assess-patch-risk](assess-patch-risk/SKILL.md) — Ask what a patch could break and whether it qualifies for automatic merging. Supply a patch, PR diff, or commit range.
- [resolve-dependency-alert](resolve-dependency-alert/SKILL.md) — Give it a dependency alert or advisory to find what pulls in the vulnerable package and whether an upgrade is possible.
- [check-skills](check-skills/SKILL.md) — Review a skill file or bundle before installing it. Ask it to check the instructions, scripts, permissions, and dependencies for risks.

## Fix, share, or follow up on findings

- [fix-finding](fix-finding/SKILL.md) — Give it a vulnerability and ask it to fix the code and verify the repair.
- [verify-fix](verify-fix/SKILL.md) — Supply the original finding and an existing fix to check whether the fix closes the vulnerability.
- [propose-security-hardening](propose-security-hardening/SKILL.md) — Ask for design changes that could prevent a class of issues. Point it to related findings or the affected code.
- [vulnerability-writeup](vulnerability-writeup/SKILL.md) — Turn notes, a proof of concept, or a finding into a report that explains the vulnerability and the evidence.
- [publish-findings](publish-findings/SKILL.md) — Preview findings from another scanner and import them into the local workbench or Codex Security Cloud. Supply the findings and name the destination.
- [cloud-findings](cloud-findings/SKILL.md) — Look up existing findings, reports, or scan status in your connected Cloud account. “Who is assigned to this finding?”
- [track-findings](track-findings/SKILL.md) — Give it validated findings and a destination to track follow-up work in Linear, Jira, GitHub issues, or draft GitHub security advisories.
