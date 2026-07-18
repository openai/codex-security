# Severity and Policy Guidance

Use this guidance after attack-path facts, reachability, and counterevidence are established.

-- Considerations for severity / criticality re-rating --
- For `high` and above, the impact must be materially security-relevant (for example: account takeover, auth bypass, meaningful privilege escalation, significant sensitive data exposure/exfiltration, credible RCE, or similarly severe compromise), not simply a bug or strange behavior
- For a finding to remain `high` or `critical`, the exploitation path and impact should be clear enough that a professional security reviewer would not need a long speculative argument to justify it.
- Do **not** treat ordinary code bugs as high/critical security issues just because they are bugs or because the scanner labeled them that way.
- Do **not** keep `critical` based on contrived, highly speculative, or edge-case-only exploit stories unless the threat model explicitly supports those conditions. Critical DEMANDS attention implying an immediate likely threat.
- Do **not** keep `high`/`critical` for strange configurations or odd codebase behaviors unless there is clear evidence that an in-scope attacker can realistically exploit them for major impact.
- Do **not** rely on unusual operator mistakes, internal-only access, or non-attacker-reachable code paths to justify severe external impact unless the repository threat model says those actors/paths are in scope.
- If the issue is a real bug but not actually a security vulnerability, classify it as `ignore` (or, if you have to, `low`) for criticality purposes.
- If it is actually provable that there is no bug at all (the description is entirely wrong or made up and you actually got that real proof that it is so), then label it as `ignore` for criticality to mark a false-positive.

Non-exhaustive examples of vulnerabilities that often support `critical` when evidenced in code and context:
- Credible RCE or arbitrary code execution (command injection, LFI exec, trivial memory corruption exploits, etc.). Requires actual proof that attacker input causes this from an in-scope attack surface.
- Real XSS with meaningful proven impact (for example session/token theft, account compromise, privileged action execution, etc)
- Account takeover or strong authentication bypass, especially if it is 0-click
- Missing authorization checks / authorization bypass / tenant-boundary break (trivial IDOR, easy to swap out org or use ids with no authz, etc)
- Severe sensitive data leak (LFI, path traversal, bad scoping of file downloads, access to data without authorization, trivial side-channels) with realistic attacker access (proof the attacker can read secrets, PII, signing keys, credential stores, private keys, classified or highly confidential information (model weights etc))
- Trivial memory corruption exploits with known exploit patterns which require little effort to exploit
- SQL or other Database or query injection with clear proof of path from attacker input from in-scope attack surface and impact of the injection (leaks sensitive data, inserts dangerous records)
- Sandbox, container, VM, browser, or interpreter escape that breaks an intended isolation boundary
- Server-side template injection when it leads to RCE or leaking of secrets, with actual proof that the templating library can be exploited to do this (RCE escape or secrets/credentials in scope) and that this can be reached from an in-scope attack surface
- Arbitrary file write in executable, startup, config, or firmware paths with a realistic path to persistence or code execution. Requires proof that an attacker can actually trigger this from in-scope attack surface.
- Logic flaws that allow irreversible or broad compromise of integrity at scale, such as unauthenticated deletion of other users' data, cross-tenant tampering with sensitive records, or unauthorized modification of security-critical configuration, when the impact is clearly demonstrated and severe enough to be compromise-equivalent; when there is actual proof that this logic can be exercised from in-scope attack-surface.
- etc, other bugs not listed which follow this level of critical severity and impact; with actual proof that these bugs are reachable from in-scope attack-surface.

Non-exhaustive examples of vulnerabilities that often support `high` when evidenced in code and context:
- Server Side Request Forgery where there is actual proof that (1) an attacker can control the url being requested (bypassing protections around that) from in-scope attack-surface and (2) there are likely other local/lan/cloud services which can be reached to show actual impact. Be careful with reporting webhooks unless there is clear proof that it is dangerous, but do not treat a product-intended webhook/download/callback feature or optional operator allow/deny list as suppression evidence when attacker-controlled destinations can still reach internal, metadata, file-backed, redirect, or side-effecting targets.
- Exploitable memory corruption with clear, major impact or ease of exploitation
- Arbitrary file read that exposes less-sensitive user data or source code (if you have actual proof it reveals env secrets, then it is critical)
- Arbitrary file write in executable, startup, config, or firmware paths with a realistic path to persistence or code execution
- CSRF when it enables important state-changing actions such as credential changes, permission changes, payment / billing changes, security-setting changes, or other materially harmful actions, and the victim interaction required is realistic, and is not mitigated by any of these : `same-site strict cookies, auth headers, csrf tokens, PUT/PATCH/DELETE, enforced json request body content type`.
- Hardcoded or default credentials that are valid and reachable and give meaningful access, but not sufficiently broad or privileged to justify high.
- Cryptographic failures that allow signature forgery, token forgery, trusted artifact forgery, secure-channel bypass, or decryption of highly sensitive data in a way that directly enables compromise, with actual proof that these attacks are practical and can be carried out from an in-scope attack surface.
- Supply-chain or update-channel compromise that allows malicious code or malicious trusted artifacts to be delivered to users, servers, agents, or endpoints, including signing bypass or package source substitution with real impact. This should focus on actual supply-chain risk and risk around CI actions, not just "does npm report outdated packages"
- Authorization bypass, IDOR, or privilege escalation that exposes or modifies meaningful sensitive data or privileged functionality, but is narrower in scope, limited to a smaller set of objects, limited to same-tenant boundaries, or otherwise less catastrophic than the critical cases above.
- XXE with clear proof that an attacker can control the XML document through in-scope attack-surface and that the XML engine is vulnerable to XXE
- etc, other bugs not listed which follow this level of high severity and impact; with actual proof that these bugs are reachable from in-scope attack-surface.
- Dangerous upload / file handling issues that enable stored active content, trusted-origin script execution, or meaningful content-type confusion with real security impact; with actual proof that both the upload and access are reachable through in-scope attack-surface.
- Deserialization, SSTI, plugin abuse, macro / template abuse, or interpreter abuse where dangerous primitives are clearly reachable and impactful, but code execution or compromise is not fully proven to the standard needed for critical.

Strong factors that often push a plausible `high` up to `critical`:
- Unauthenticated or near-unauthenticated reachability from the internet or other broad in-scope surfaces.
- 0-click or extremely low-friction exploitation.
- Cross-tenant / cross-boundary impact rather than same-user or same-tenant impact.
- Direct compromise of signing, identity, control-plane, or cloud credentials.
- Realistic persistence, mass exploitation, wormability, or compromise of many victims at once.
- Clear proof of code execution, full account takeover, or crown-jewel secret access rather than only a plausible path.

Examples that usually should not remain `high`/`critical` without very strong proof of it leading to the class of vulnerabilities above:
- Generic correctness/reliability bugs
- Strange edge cases with unclear attacker value
- Low-impact information leaks
- Internal-only defects without realistic attacker reachability
- The report shows a bug class in isolation, but not a realistic exploit path.
- The issue requires the attacker to already have privileged, admin, root, console, shell, or code-execution access.
- "Could maybe matter if chained with many assumptions" arguments
- Self-XSS, reflected XSS with only an alert-box proof, or XSS without demonstrated access to sensitive data, session material, privileged actions, or comparable real impact.
- SQLi or other injection claims with no demonstrated attacker control, no shown sink reachability, or only speculative impact.
- CSRF on low-impact actions, cosmetic actions, logout, preferences, or actions requiring unrealistic victim behavior.
- Open redirect, clickjacking, user enumeration, rate-limit weakness, banner leakage, version disclosure, directory listing, stack traces, internal hostnames, or basic error-message leakage, unless they are shown as part of a serious exploit chain.
- Memory corruption that is theoretical, non-triggerable from in-scope input, or not plausibly exploitable in the target environment.
- Missing headers, cookie flags, CSP weaknesses, TLS observations, or crypto hygiene issues without a concrete exploit path and meaningful demonstrated impact.
- Reports that effectively say "this could be dangerous if combined with something else" but do not show the something else.
- Denial of service that is transient, single-user, self-targeting, easy to mitigate, requires disproportionate attacker resources, or does not create severe and realistic business / safety impact.
- Authz findings that require already having the same privilege as the victim, or only expose trivial metadata.
- Bugs that already require admin/root/shell access unless the privilege-escalation delta itself is the issue being reported.
- Arbitrary file read limited to public files, low-sensitivity files, or source fragments with no realistic security consequence.

High/Critical acceptance checklist (all should be true, unless the threat model strongly justifies an exception):
- In-scope component
- Realistic attacker
- Reasonable in-scope attack surface
- Credible exploitation path (not simply speculation)
- Major security impact
- Would likely be accepted as `high`/`critical` (not informational/low) in serious audit or bug bounty triage by a major auditing firm who puts their reputation on the line.

## Severity and Policy Checklist

Apply severity adjustment only after scope, reachability, and counterevidence are established. Do not reopen discovery here.

Start from the candidate's original severity hypothesis, then adjust it using the repository-evidenced facts from this phase.

Severity adjustment guidance:

- Keep `critical` only when the attack path, reachability, and impact are all clear enough that the finding would demand immediate attention.
- Keep `high` only when there is a realistic in-scope attacker path and major security impact without a long speculative chain.
- Downgrade when the path is real but constrained to narrower objects, same-tenant impact, internal-only surfaces, or other materially limiting conditions.
- Reduce severity when the path is localhost-only, self-only, highly constrained, dependent on unrealistic preconditions, or already requires privileged access unless the privilege-escalation delta is the issue.
- Dangerous sink, scary bug class, or sensitive code area alone is not enough to preserve high severity.
- If the issue is a real bug but not meaningfully reportable as a security problem in context, set the final policy decision to `ignore`.

Final policy-adjustment guidance:

- Apply hard suppression first:
  - self-only impact -> `ignore`
  - unachievable or highly unrealistic preconditions -> `ignore`
  - privileged-only, operator-only, developer-only, physical-access-only, or protected-write-path preconditions -> `ignore`, unless the privilege-escalation delta itself is the issue
- Then weight likelihood using the established network scope:
  - `remote` usually supports high likelihood when the attacker position is realistic and in scope
  - `local_network` usually supports medium likelihood unless the evidence is stronger or weaker
  - `localhost` usually supports low likelihood unless a lower-privileged attacker can realistically reach that listener
  - `none` does not increase likelihood based on exposure
- Then decide reportability using the existing facts:
  - if the component is not part of a real product surface or meaningful production workflow, set `ignore`
  - if repository evidence does not establish a realistic lower-privileged in-scope attacker path, set `ignore`
  - if the path is internal-only, developer-only, operator-only, localhost-only, privileged-local, or otherwise not meaningfully reportable in context, set `ignore`

Do not suppress solely because the surface is private or internal when repository evidence still shows a meaningful authorization, trust-boundary, identity, or security-control regression in a real product or production-service workflow. In those cases, internal exposure should usually reduce likelihood or confidence rather than force `ignore`.

Use missing deployment or ingress evidence to lower confidence or keep fields unknown when appropriate; do not automatically defeat an otherwise well-evidenced finding on that basis alone.

Severity calibration and final policy-adjustment matrix:

- `impact=high`:
  - `likelihood=high` -> `critical` only when the critical criteria above are satisfied; otherwise `high`
  - `likelihood=medium` -> `medium`
  - `likelihood=low` -> `ignore`
  - `likelihood=ignore` -> `ignore`
  - `likelihood=unknown` -> `medium`
- `impact=medium`:
  - `likelihood=high` -> `medium`
  - `likelihood=medium` -> `low`
  - `likelihood=low` -> `ignore`
  - `likelihood=ignore` -> `ignore`
  - `likelihood=unknown` -> `low`
- `impact=low`:
  - `likelihood=high` -> `ignore`
  - `likelihood=medium` -> `ignore`
  - `likelihood=low` -> `ignore`
  - `likelihood=ignore` -> `ignore`
  - `likelihood=unknown` -> `ignore`
- `impact=ignore`:
  - all likelihoods -> `ignore`
- `impact=unknown`:
  - `likelihood=high` -> `medium`
  - `likelihood=medium` -> `low`
  - `likelihood=low` -> `ignore`
  - `likelihood=ignore` -> `ignore`
  - `likelihood=unknown` -> `low`

Priority mapping after final severity:

- `critical` -> `P0`
- `high` -> `P1`
- `medium` -> `P2`
- `low` -> `P3`

Use this mapping after the final policy-adjustment pass determines the final reportable severity. Do not assign a priority to findings whose final policy decision is `ignore`.

Once the facts are set, use the severity calibration and final policy-adjustment matrix mechanically. Do not re-argue severity from scratch afterward.
