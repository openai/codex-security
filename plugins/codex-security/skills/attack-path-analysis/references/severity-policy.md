# Severity and Policy Guidance

Apply this policy after establishing the attack path, scope, and counterevidence. Start from the candidate's severity hypothesis and adjust it using repository-supported impact, likelihood, prerequisites, and mitigations. Do not reopen discovery during calibration.

## Severity criteria

Reserve `critical` for a realistic in-scope path to severe compromise that requires immediate attention. Use `high` for a realistic attacker path with major security impact. A bug class, dangerous sink, unusual configuration, or scanner label alone does not establish either level.

Evidence that can support `critical` includes:

- arbitrary code execution or readily exploitable memory corruption;
- account takeover, strong authentication bypass, or XSS that enables account compromise or privileged actions;
- broad authorization or tenant-boundary failure;
- access to highly sensitive data, signing keys, private keys, credential stores, or similarly valuable secrets;
- query injection that exposes sensitive data or creates dangerous records;
- sandbox, container, VM, browser, or interpreter escape;
- server-side template execution that enables code execution or secret access;
- arbitrary file writes with a realistic path to persistence or execution;
- irreversible or broad integrity compromise, such as cross-tenant deletion or unauthorized changes to security-critical configuration.

These examples require evidence of attacker control, an in-scope reachable path, and the claimed impact. Unauthenticated reachability, low-friction exploitation, cross-tenant effects, identity or signing compromise, persistence, and mass exploitation can support raising an otherwise plausible `high` to `critical`.

Evidence that can support `high` includes:

- SSRF with attacker-controlled destinations and meaningful internal, metadata, file-backed, or side-effecting access;
- exploitable memory corruption with major impact;
- unauthorized reads of meaningful user data or source code, with highly sensitive secret exposure considered for `critical`;
- file writes with a realistic execution or persistence path;
- CSRF that enables sensitive state changes with realistic victim interaction;
- valid, reachable hardcoded or default credentials granting meaningful access;
- practical cryptographic failures enabling forgery, secure-channel bypass, or sensitive-data decryption;
- update or supply-chain compromise delivering malicious code or trusted artifacts;
- authorization or privilege failures with meaningful but narrower object or same-tenant impact;
- exploitable XXE;
- uploads enabling stored active content, trusted-origin script execution, or consequential content-type confusion;
- reachable deserialization, template, plugin, macro, or interpreter primitives with demonstrated impact but without the proof needed for `critical`.

For SSRF, a documented outbound-request feature or optional operator filter does not defeat a demonstrated destination-control bypass. For CSRF, evaluate browser credential attachment, cookie policy, preflight, request parsing, and effective controls; method or JSON content type alone is not a categorical defense. For XSS, distinguish self-only effects from victim impact; an `alert` reproduction proves script execution but does not alone establish the severity.

Constrained, same-tenant, internal, localhost, self-only, or already-privileged paths generally reduce severity unless the threat model or privilege gained supports greater impact. Ordinary correctness bugs, low-impact information leaks, speculative injection or memory-corruption claims, security-header or crypto-hygiene observations, and transient or self-targeting denial of service do not warrant `high` or `critical` without a demonstrated severe consequence. Evaluate the actual privilege delta and boundary crossing.

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

## Calibration matrix

Severity calibration and final policy-adjustment matrix:

- `impact=high`:
  - `likelihood=high` -> `critical` only when the critical criteria above are satisfied; otherwise `high`
  - `likelihood=medium` -> `medium`
  - `likelihood=low` -> `low`
  - `likelihood=ignore` -> `ignore`
  - `likelihood=unknown` -> `medium`
- `impact=medium`:
  - `likelihood=high` -> `medium`
  - `likelihood=medium` -> `low`
  - `likelihood=low` -> `low`
  - `likelihood=ignore` -> `ignore`
  - `likelihood=unknown` -> `low`
- `impact=low`:
  - `likelihood=high` -> `low`
  - `likelihood=medium` -> `low`
  - `likelihood=low` -> `low`
  - `likelihood=ignore` -> `ignore`
  - `likelihood=unknown` -> `low`
- `impact=ignore`:
  - all likelihoods -> `ignore`
- `impact=unknown`:
  - `likelihood=high` -> `medium`
  - `likelihood=medium` -> `low`
  - `likelihood=low` -> `low`
  - `likelihood=ignore` -> `ignore`
  - `likelihood=unknown` -> `low`

Priority mapping after final severity:

- `critical` -> `P0`
- `high` -> `P1`
- `medium` -> `P2`
- `low` -> `P3`

Use this mapping after the final policy-adjustment pass determines the final reportable severity. Do not assign a priority to findings whose final policy decision is `ignore`.

Once the facts are set, use the severity calibration and final policy-adjustment matrix mechanically. Do not re-argue severity from scratch afterward.
