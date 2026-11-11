# Codex Security skills

With the plugin enabled, describe the job in Codex or name a skill directly. For example, `Use $security-diff-scan to check my uncommitted changes for vulnerabilities.` See the [setup instructions and CLI examples](../../../docs/agent-workflows.md).

## Scan or review code

| What you want to do                                                                                                                                                       | Skill                                             |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Scan a repository or folder for vulnerabilities in one pass. Start here for a general audit.                                                                              | [security-scan](security-scan/SKILL.md)           |
| Check a PR, commit, branch diff, or local edits for vulnerabilities introduced or exposed by the change.                                                                  | [security-diff-scan](security-diff-scan/SKILL.md) |
| Run several audits of the same repository or folder and get one report combining their findings.                                                                          | [deep-security-scan](deep-security-scan/SKILL.md) |
| Get a merge recommendation for a saved patch, PR diff, or commit range based on what could break and whether tests would catch it.                                        | [assess-patch-risk](assess-patch-risk/SKILL.md)   |
| Check a downloaded skill before installing it. From a separate trusted workspace, point Codex to the folder to inspect its instructions and scripts without running them. | [check-skills](check-skills/SKILL.md)             |

## Set review scope and model threats

| What you want to do                                                                                             | Skill                                                     |
| --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| Write or review `SECURITY.md` to define what a scan should cover and which security rules the code must uphold. | [define-security-policy](define-security-policy/SKILL.md) |
| Map what a service protects, where it accepts input, and how an attacker could cross a trust boundary.          | [threat-model](threat-model/SKILL.md)                     |
| Explore an existing threat model as an interactive diagram. You can use the model from the last scan.           | [threat-model-visualize](threat-model-visualize/SKILL.md) |

## Investigate alerts and suspected vulnerabilities

| What you want to do                                                                                                     | Skill                                                         |
| ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Check a reported issue against the source and security policy. Start with a scanner alert, advisory, report, or ticket. | [triage-finding](triage-finding/SKILL.md)                     |
| Find out why a flagged package is in your checkout or image and which dependency, if any, needs an upgrade.             | [resolve-dependency-alert](resolve-dependency-alert/SKILL.md) |
| Look for possible vulnerabilities in a path or diff and identify what still needs proof.                                | [finding-discovery](finding-discovery/SKILL.md)               |
| Check whether a suspected vulnerability is real by tracing the code or trying to reproduce the bug.                     | [validation](validation/SKILL.md)                             |
| Trace a finding from attacker input to its impact and explain how severe it is.                                         | [attack-path-analysis](attack-path-analysis/SKILL.md)         |

## Fix a vulnerability or prevent similar bugs

| What you want to do                                                                                                             | Skill                                                             |
| ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| Patch a reported vulnerability and check that the fix blocks the attack while preserving legitimate use.                        | [fix-finding](fix-finding/SKILL.md)                               |
| Check the original finding against the current checkout after a fix. Get a verdict of fixed, still vulnerable, or inconclusive. | [verify-fix](verify-fix/SKILL.md)                                 |
| Compare the costs and benefits of design changes that could prevent similar bugs.                                               | [propose-security-hardening](propose-security-hardening/SKILL.md) |

## Import, read, or share findings

| What you want to do                                                                                                                                                                          | Skill                                                   |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Preview a supported scanner report and import its alerts into the local workbench or, for supported inputs, Codex Security Cloud.                                                            | [publish-findings](publish-findings/SKILL.md)           |
| Open a finding link, read its report, or check the status of a scan in your connected Cloud account.                                                                                         | [cloud-findings](cloud-findings/SKILL.md)               |
| Turn notes, a proof of concept, or scan findings into a vulnerability report that explains the impact and shows the evidence.                                                                | [vulnerability-writeup](vulnerability-writeup/SKILL.md) |
| File validated findings in Linear, Jira, GitHub issues, or a draft GitHub security advisory. Supply the completed scan directory and review the proposed tickets or advisory before posting. | [track-findings](track-findings/SKILL.md)               |
