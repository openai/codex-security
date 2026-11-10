# Severity and Policy Guidance

Apply this policy after establishing the attack path, scope, and counterevidence. Start from the candidate's severity hypothesis and adjust it using repository-supported impact, likelihood, prerequisites, and mitigations. Do not reopen discovery during calibration.

Grade reportable findings with the scan's rubric or, when none is supplied, the [default severity rubric](../../../references/default-severity-rubric.md).

For SSRF, a documented outbound-request feature or optional operator filter does not defeat a demonstrated destination-control bypass. For CSRF, evaluate browser credential attachment, cookie policy, preflight, request parsing, and effective controls; method or JSON content type alone is not a categorical defense. For XSS, distinguish self-only effects from victim impact; an `alert` reproduction proves script execution but does not alone establish the severity.

## Reportability

- Set `ignore` for a disproved finding or a bug without a meaningful security impact.
- Do not discard a real, reportable finding solely because its impact or likelihood is low; use the corresponding lower severity.
- Apply hard suppression to self-only impact or unachievable/highly unrealistic prerequisites.
- Privileged-only, operator-only, developer-only, physical-access-only, or protected-write-path prerequisites imply `ignore` unless a privilege-escalation delta is the issue.
- If repository evidence does not establish a realistic lower-privileged in-scope attacker path, set `ignore`.

Private or internal exposure alone does not suppress a supported authorization, identity, trust-boundary, or security-control failure in a real product or production workflow. Missing deployment or ingress evidence can lower confidence or leave facts unknown without defeating an otherwise supported finding.

Weight likelihood using the established attacker position and exposure:

- `remote` usually supports high likelihood when the attacker position is realistic and in scope;
- `local_network` usually supports medium likelihood unless the evidence supports a different level;
- `localhost` usually supports low likelihood unless a lower-privileged attacker can realistically reach the listener;
- `none` does not increase likelihood based on exposure.

## Priority

Map the final reportable severity to a priority.

- `critical` -> `P0`
- `high` -> `P1`
- `medium` -> `P2`
- `low` -> `P3`

An ignored finding receives an `ignore` decision and severity, with no priority.
