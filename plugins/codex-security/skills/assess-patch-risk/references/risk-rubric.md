# Patch risk rubric

Rate each dimension from evidence, not from diff size or test count.

## Impact if wrong

- `low`: local behavior with no material contract, state, privilege, availability, deployment, or shared-runtime effect.
- `moderate`: bounded component or consumer impact with a clear containment boundary.
- `high`: shared runtime, public contract, persistent state, privileged boundary, broad deployment, or difficult operational recovery.
- `critical`: plausible cross-tenant, major security, irreversible state, fleet-wide, or catastrophic availability impact.

## Regression likelihood

- `low`: narrow semantics, supported controls preserved, material counterexamples rejected, and directly relevant protection passes.
- `moderate`: some coupling, partial protection, or bounded uncertainty remains but no source-visible defect is established.
- `high`: complex or weakly protected behavior, important untested paths, contract ambiguity, or substantial unresolved coupling.
- `critical`: evidence already demonstrates a serious regression, bypass, unsupported control break, or failed required safety property.

## Regression protection

- `strong`: assertions observe the changed property through affected callers or integration boundaries, relevant checks ran at the assessed head, and required platform or rollout validation is present.
- `partial`: useful tests exist but miss an affected caller, failure mode, platform, deployment, or integration boundary.
- `none`: no relevant executable protection was found or the available checks did not run.
- `unknown`: test identity, execution, or relevance cannot be established.

## Recoverability

- `easy`: isolated revert or disable path with no migration, persisted incompatible state, or coordinated rollout.
- `managed`: recovery is understood but needs coordination, replay, cleanup, or operational action.
- `hard`: rollback is unsafe, irreversible, stateful, cross-version, or operationally uncertain.

## Confidence

- `high`: exact patch identity, affected roots and callers, material boundaries, controls, counterexamples, and relevant validation are all evidenced.
- `moderate`: the main path is traced but a bounded non-decision-critical gap remains.
- `low`: patch identity, applicability, runtime reachability, contract, or a decision-critical behavior remains uncertain.

## Boundary challenge

For each material changed boundary, record:

- the invariant that must hold;
- the affected runtime root or supported consumer;
- the strongest concrete counterexample;
- a legitimate control from base source, callers, or an authoritative contract;
- the patched source path for both cases; and
- whether the result is supported, contradicted, or unresolved.

When a decision depends on a complete enum, allowlist, routing table, protocol matrix, identity class, state transition, or similar bounded domain, derive the partitions from an independent contract or an exhaustive self-contained new contract. Representative tests are not proof of completeness.

When behavior derives a new target or reuses saved authority, independently classify the derived URL, callback, nested resource, cached principal, historical object, retry, replay, or re-execution at the consuming policy decision. Inherited trust is not evidence of safety.

Apply these challenges when the patch contains the corresponding structure:

- for aggregated policy inputs, verify that the property and resulting decision bind to the same individual subject;
- after validation, trace mutation, interpretation, callbacks, retries, lazy initialization, and re-resolution to the first sensitive sink; and
- for UI, discovery, prompt, instruction, or visibility changes, require capability removal or independent downstream enforcement before assigning authorization or isolation impact.

A trigger alone is not a defect. Mark the boundary contradicted only when source or an authoritative contract establishes a concrete cross-subject decision, post-validation bypass, or capability-preserving enforcement gap.

## Strict auto-merge gate

Use `auto_merge_candidate` only when all of the following are true:

- impact and likelihood are `low`;
- regression protection is `strong` and relevant exact-head checks pass;
- recovery is `easy` and confidence is `high`;
- runtime reachability and ownership are established;
- no privileged boundary, migration, persistent-state change, public contract change, architecture-specific rollout, or broad shared default is materially affected;
- every material boundary challenge is supported;
- no unknown, skipped required check, failed relevant check, or merge condition remains; and
- status-quo risk is known.

Otherwise use `human_review_required` for a supported `merge`. Strong tests can lower likelihood and raise confidence, but never lower impact.

The validator enforces this gate and the recommendation-to-label mapping. A validation failure means the evidence packet is internally inconsistent; it is not permission to weaken a rating or omit evidence.
