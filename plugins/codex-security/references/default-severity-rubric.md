# Severity guidance

Judge the attacker's actual starting access, the security boundary crossed, and
the additional unauthorized harm. Keep confidence separate from severity and
identify the missing fact that could change the assessment. Missing proof alone
does not establish that a broader attack is impossible; do not invent an attack
path or downgrade merely because exploitation was not demonstrated.

## Critical

Reserve Critical for consequential, strongly supported compromise meeting all
three conditions:
- Access: an unauthenticated internet attacker, ordinary external user, or
  publicly admitted untrusted workload can exploit the interface without
  employee-only access, an invitation, an approved business relationship, or
  compromise of a trusted supplier.
- Impact: crossing an important security boundary enables consequential access
  to protected data, privileged actions, meaningful code execution, workload
  escape, or comparable compromise of the affected system.
- Evidence: demonstrated exploitation or strong source-backed validation
  establishes the complete attack path.

Second-order attacks can qualify: an external attacker plants data that a trusted
user or system later processes, causing consequential unauthorized access or
privileged actions.

## High

Assign High when a realistic, evidenced path gives a lower-trust attacker a
substantial unauthorized capability they did not already possess. Internal
users, partners, invited collaborators, and admitted untrusted workloads can
qualify; unauthenticated internet access is not required. Consequences include
sensitive customer or business data or reusable credentials, account takeover,
meaningful cross-tenant access or actions as another user, control of production
workloads or deployments, privileged identities, encryption keys or important
isolation boundaries, or significant repeatable disruption of a critical or
shared service. A dangerous function, production label, internal access, or the
existence of a privileged credential alone is insufficient: identify the
lower-trust actor, boundary crossing, and consequential new capability.

## Medium

Assign Medium to a credible vulnerability with concretely bounded impact, such
as nonsecret operational information, narrow unauthorized changes, contained
disruption of a noncritical service, or isolated development or staging systems
without a consequential pivot. A fully demonstrated vulnerability can still be
Medium. Base a downgrade on verified constraints, not on an assumption that
missing evidence rules out broader harm.

## Low

Assign Low to a supported security weakness with minor additional unauthorized
harm and verified limits on its scope, sensitivity, or duration, such as a small
information exposure with little security value or a narrowly contained nuisance.
Do not use Low as a substitute for uncertainty about a potentially serious path.

## Informational

Assign Informational to a hardening opportunity or observation for which the
supplied evidence establishes no additional unauthorized capability or security
impact. Explain why it is informational rather than treating missing proof of
exploitation as proof of safety. Administrative records that do not describe a
security finding may be excluded; exclusion is distinct from severity.
