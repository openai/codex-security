# Codex Security skills

Describe the job in Codex, or name a skill directly. For example, `$security-diff-scan Check my uncommitted changes for vulnerabilities.`

## Scan code

- [security-scan](security-scan/SKILL.md) checks a repository or folder for vulnerabilities in one pass.
- [security-diff-scan](security-diff-scan/SKILL.md) reviews the changes in a PR, commit, branch, or working tree.
- [deep-security-scan](deep-security-scan/SKILL.md) makes repeated passes over a repository or folder when you want a more thorough audit.

## Set the scope

- [define-security-policy](define-security-policy/SKILL.md) writes or updates `SECURITY.md` so reviewers know what to check and what's out of scope.
- [threat-model](threat-model/SKILL.md) maps what the system protects, who can access it, and where an attacker might get in.
- [threat-model-visualize](threat-model-visualize/SKILL.md) turns an existing threat model into an interactive diagram you can use to follow an attack path.

## Investigate a finding

- [finding-discovery](finding-discovery/SKILL.md) looks for potential vulnerabilities in the code you specify.
- [triage-finding](triage-finding/SKILL.md) checks whether a scanner alert or reported issue applies to your code under the repository's security policy.
- [validation](validation/SKILL.md) checks the evidence for a suspected vulnerability and tries to reproduce it when practical.
- [attack-path-analysis](attack-path-analysis/SKILL.md) traces how an attacker could reach the vulnerable code and what they could do once there.

## Review a patch, package, or skill

- [assess-patch-risk](assess-patch-risk/SKILL.md) identifies what a patch could break and assesses whether it's safe to merge automatically.
- [resolve-dependency-alert](resolve-dependency-alert/SKILL.md) traces which dependency brought in a flagged package and checks whether you can upgrade it.
- [check-skills](check-skills/SKILL.md) inspects a skill's instructions, scripts, permissions, and dependencies before you install it.

## Fix and prevent vulnerabilities

- [fix-finding](fix-finding/SKILL.md) patches a reported vulnerability and checks that the fix works.
- [verify-fix](verify-fix/SKILL.md) checks an existing patch against the original finding to see whether the attack still works.
- [propose-security-hardening](propose-security-hardening/SKILL.md) suggests design changes that could prevent the same kind of vulnerability elsewhere.

## Report and track findings

- [vulnerability-writeup](vulnerability-writeup/SKILL.md) turns notes or a proof of concept into a report explaining the bug, its impact, and the evidence.
- [publish-findings](publish-findings/SKILL.md) previews findings from another scanner and imports them into the local workbench or Codex Security Cloud.
- [cloud-findings](cloud-findings/SKILL.md) looks up findings, reports, and scan status in your connected Cloud account.
- [track-findings](track-findings/SKILL.md) records validated findings in Linear, Jira, GitHub issues, or draft GitHub security advisories.
