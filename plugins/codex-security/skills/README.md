# Codex Security skills

With the plugin enabled, you can ask Codex to "check my uncommitted changes for security bugs." To pick the skill yourself, include its name in the request, as in `$security-diff-scan`. [Setup and CLI examples](../../../docs/agent-workflows.md)

## Choosing a scan

- [security-scan](security-scan/SKILL.md) audits a repo or folder in one pass. Start here for a general review.
- [security-diff-scan](security-diff-scan/SKILL.md) looks for vulnerabilities introduced or exposed by a PR, commit, branch diff, or local edits.
- [deep-security-scan](deep-security-scan/SKILL.md) makes several passes over the same code and combines the findings in one report.

## Before you merge or install something

- [assess-patch-risk](assess-patch-risk/SKILL.md) takes a patch file, PR diff, or commit range. It explains what could break, whether the tests would catch it, and whether the patch is ready to merge.
- [check-skills](check-skills/SKILL.md) reviews a downloaded agent skill before you install it. Open Codex in a separate, trusted workspace and point it to the skill folder. It reads the instructions and scripts without running them.

## Security policy and threat models

- [define-security-policy](define-security-policy/SKILL.md) helps you spell out in `SECURITY.md` what reviewers should check and what's out of scope.
- [threat-model](threat-model/SKILL.md) maps what the system protects and where an attacker could get in.
- [threat-model-visualize](threat-model-visualize/SKILL.md) turns an existing model into a diagram you can explore.

## Investigating a finding

- [triage-finding](triage-finding/SKILL.md) checks a reported bug against your code and security policy. Give it the alert or ticket.
- [resolve-dependency-alert](resolve-dependency-alert/SKILL.md) traces what pulled a flagged package into your checkout or image and checks your upgrade options.
- [finding-discovery](finding-discovery/SKILL.md) looks for possible vulnerabilities in a path or diff and flags what still needs proof.
- [validation](validation/SKILL.md) checks whether a suspected bug is real by tracing the code or trying to reproduce it.
- [attack-path-analysis](attack-path-analysis/SKILL.md) traces how an attacker could trigger the bug and what they'd gain.

## Fixing a bug

- [fix-finding](fix-finding/SKILL.md) patches a vulnerability and checks that the fix stops the attack and preserves normal use.
- [verify-fix](verify-fix/SKILL.md) checks an existing fix. Give it the original finding and the current checkout to see whether the fix worked or what evidence is missing.
- [propose-security-hardening](propose-security-hardening/SKILL.md) compares design changes that could keep the same kind of bug from turning up again.

## Reports and tickets

- [vulnerability-writeup](vulnerability-writeup/SKILL.md) turns notes or a proof of concept into a report explaining the bug, its impact, and the evidence.
- [publish-findings](publish-findings/SKILL.md) previews alerts from another scanner and imports them into the local workbench. Some formats also support import into Codex Security Cloud.
- [cloud-findings](cloud-findings/SKILL.md) looks up a finding, report, or scan status in your connected Cloud account. You can paste a finding link.
- [track-findings](track-findings/SKILL.md) takes validated findings from a completed scan directory and checks for existing tickets. You review any new Linear, Jira, or GitHub issues before it files them. It can also draft a GitHub security advisory.
