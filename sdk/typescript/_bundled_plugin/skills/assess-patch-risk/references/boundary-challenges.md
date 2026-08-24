# Boundary Challenge Catalog v1

Use this catalog to build `boundaryChallenges` before selecting a recommendation. It defines minimum source questions, not an exhaustive bug taxonomy. Record only dimensions relevant to the changed behavior, except where the schema requires dimensions for a boundary kind.

## Shared Challenge

For every material changed boundary:

1. state the safety or compatibility invariant;
2. identify the strongest plausible counterexample from the exact patch and source;
3. trace that counterexample through the changed code and affected callers;
4. trace at least one supported legitimate control through the same path; and
5. classify the counterexample as `handled`, `fails`, or `unresolved` and the control as `preserved`, `broken`, or `unresolved`.

Do not select only cases already represented by tests. Tests are inputs to the challenge, not the case inventory.

Compare every concrete counterexample at the exact base and head. Require revision when the patch introduces or enables the failure, breaks a supported existing invariant, or leaves its specifically claimed remediation bypassable. An unchanged, explicitly acknowledged residual risk outside a bounded partial-remediation claim is status-quo evidence, not itself a patch defect.

## Classification Completeness

Use an applicable `domainCoverage` only when the patch's correctness depends on complete coverage of a bounded or externally defined domain. Typical forms are allowlists and denylists, enum-to-behavior mappings, routing or dispatch tables, protocol or version matrices, identity or fallback classes, and state-transition tables. Do not enable it merely because open-ended inputs can be described with categories; those remain ordinary counterexample challenges.

Before naming the complete domain, classify whether the patch creates a genuinely new contract, preserves the existing supported surface, narrows it, or leaves that relationship unknown. Compare the exact base and head and search beyond changed files for pre-existing callers, runtime behavior, public documentation, compatibility tests, schemas or enums, generated contracts, and available external provider specifications. Record these as `contractProvenance` sources and distinguish `pre_existing_repository`, `external_authority`, and `patch_authored` origins.

A description, allowlist, enum, implementation, or test introduced or modified by the patch can describe the proposed behavior but cannot alone prove completeness for a preserved or narrowed contract. Patch-only provenance may support `self_contained_new_contract` only when the behavior is genuinely new, finite, self-contained, and exhaustively enumerated. Otherwise complete coverage requires at least one pre-existing repository or external authoritative source with no contradiction or unresolved remainder.

Name the completeness claim and derive material partitions from the independently grounded contract or exhaustive new state model before relying on the implementation or its tests. Record every materially distinct partition inspected and any unclassified remainder. `complete` requires `bounded` or `exhaustive` coverage, acceptable contract provenance, no unclassified partition, and source evidence that every recorded partition is handled. Use `gap_found` when a repository or authoritative source contradicts the patch inventory or source shows a relevant omission. Use `unresolved` only when provenance or a material partition cannot be established after the bounded search. A representative sample is evidence about examples, not evidence of completeness.

The fresh falsifier must challenge both false applicability decisions and false completeness claims. When coverage applies, independently derive at least one material partition from provenance that does not originate solely in the patch, except for an exhaustive self-contained new contract. Do not replay only the examples, descriptions, enums, or tests emphasized by the patch. A source-visible gap requires `revise` when source or tests must change; an externally unavailable basis may support `needs_validation` only when it is the decision pivot and the bounded resolution branches are recorded.

## Claims And Oracles

Use an applicable `claimOracleCoverage` when a material boundary changes documentation or tests, or when the merge decision relies materially on their claims. The bounded subjects are the material normative claims, test assertions, and platform assumptions in the exact changed or relied-upon artifacts. Do not enable it for incidental prose or tests that provide no material merge evidence.

For every subject, record what the artifact claims, the property that must actually hold, and a concrete falsifier. A falsifier asks whether the prose or assertion could still appear satisfied while the required property is false. Examples of generic falsifier dimensions include omitted modes or exceptions, alternate routes, wrong-field assertions, normalization and case differences, negative and legitimate controls, unrealistic fixtures, mocks that remove the boundary, skip or expected-failure logic, and platform, architecture, or executor branches.

Every `test_assertion` subject also requires `oracleSensitivity`. Split a compound assertion claim into the material properties or representations it claims to distinguish. For each one, isolate a mutation that breaks only that property, record the behavior held constant, identify the exact assertion or output field that observes it, and name the failure signal expected from that mutation. Use `detected` only when execution or an exact source trace establishes that the signal must change. Use `not_detected` when the assertion still passes, and `unresolved` when sensitivity cannot be established. `complete` requires every material property to be detected and no unobserved remainder.

The actual assertion determines the claimed semantic property and permitted equivalence; the test name and setup identify every deliberately configured representation of that property. A configured representation remains asserted even when the assertion fails to observe or distinguish it. Do not strengthen equivalent behavior or values into object identity or implementation coupling unless an independently grounded contract expressly requires it. An unclaimed adjacent case is a coverage limitation, not itself a contradicted claim. Separately challenge that case against source and supported contracts: an actual defect still requires `revise` even when the changed test never claimed to cover it.

`complete` requires bounded or exhaustive review of every material subject, source-backed `supported` results, and no unreviewed remainder. Use `gap_found` when a claim or assertion is source-visibly contradicted. Use `unresolved` when a material subject, platform assumption, or required behavior cannot be established. A contradicted claim or oracle requires `revise` when documentation, source, or tests must change; externally unavailable behavior may support `needs_validation` only when it is the decision pivot and bounded terminal branches are recorded.

## Network And Derived Targets

Required dimensions: `policy_mode`, `initial_trust_class`, and `derived_target_transition`.

Cross product the relevant policy and feature-gate modes with initial and derived target classes. Include redirects, DNS answers, multi-answer and rebinding behavior, response-advertised or embedded URLs, callbacks, imports, nested resources, proxies, custom transports, Unix sockets, and protocol changes when reachable. Cover IPv4, IPv6, mapped addresses, NAT64, and applicable IANA special-purpose ranges rather than checking only loopback, link-local, and RFC1918 space. Reclassify and enforce every derived target independently; a trusted initial origin must not transfer its exemption, credentials, proxy bypass, or direct transport to attacker-controlled targets. Record `trustTransitionCoverage` for every material transition. `complete` requires no unreviewed transition and a `reclassified` or source-proven `proven_equivalent` decision for each target; `inherited` is `gap_found`, while an unknown target or decision is `unresolved`.

## Authentication And Authorization

Required dimensions: `identity_source` and `fallback_route`.

Trace the authenticated principal from its trusted source to each decision. Challenge request-carried identity, derived identity, service identity, missing identity, legacy unowned records, and every fallback. Inventory fail-open, shadow, discovery, internal, administrative, compatibility, and error routes that can bypass or materially change enforcement. Verify both a denied adversarial case and an allowed legitimate control for each materially different route class.

Derive supported legitimate controls from exact-base source or callers, including trusted producers and supported persisted or historical object versions. Vary authenticated principal provenance and object version together when relevant. A changed test alone cannot prove prior support. A newly rejected independently evidenced control requires `revise`, even when a changed test expects that rejection.

When a decision consumes saved, cached, historical, or versioned authority, add `authority_lifecycle` and trace every applicable creation, update, refresh, replay, retry, and re-execution event. Record those events on the corresponding `trustTransitionCoverage` transition. The consuming decision must reclassify the current principal and policy or prove from source that the authority cannot change across those events. An inherited or stale decision is `gap_found`; an unreviewed event is `unresolved`.

## Documentation And Public Claims

Required dimension: `documentation_claim`.

Bound every material changed or relied-upon enforcement, compatibility, rollout, and failure-mode claim before reviewing implementation details. Split compound claims when their scopes or exceptions differ. Map each subject to exact source behavior and callers, including disabled gates, shadow or fail-open modes, discovery routes, unsupported transports, legacy data, and error paths. Try at least one path where the documented headline remains plausible but an omitted mode or exception defeats it. A claim that is broader than source behavior is a broken contract even when the implementation is otherwise safe.

## Tests And Oracles

Required dimension: `test_oracle`.

Inspect the assertion and fixture, not only the test name or presence. Translate each material assertion into the exact property it proves, then construct a false-positive input or mutation that violates the intended property while attempting to keep the assertion satisfied. Check wrong fields or representations, normalization and case handling, negative and legitimate controls, mocks that remove the boundary, and whether skips, expected failures, feature conditions, platforms, architectures, or executors omit a supported path. When several aliases, case forms, encodings, protocol versions, identity classes, or state variants are configured, mutate and observe each independently; one observed form or an indistinguishable aggregate does not prove all configured forms. Record material environment assumptions as `platform_assumption` subjects. When a test or relied-upon claim excludes recovery through another route, backend, credential, or service identity, add `fallback_route` and require distinct oracle-sensitivity properties whose `observationTarget` values cover the intended `real_sink` and every material `prohibited_alternate_sink`. A mocked wrapper, propagated exception, or return value is only `assertion_output`; it cannot substitute for either sink observation. Confirm that the test reaches the real changed boundary, fails on the exact base and passes with the patch when feasible, and preserves a legitimate control. Treat a relevant exact-head failure as unresolved until logs or reproduction explain it. A passing test with the wrong expected behavior is not protection.

## Contracts, State, And Deployment

Use `persisted_or_mixed_state` when behavior depends on previous deployments, stale resources, serialized data, caches, migrations, or version skew. Exercise old-to-new and new-to-old interactions, retry and partial-failure paths, cleanup ordering, rollback, and convergence after externally changed state. A desired-state omission is not proof that existing state is removed.

## Parser, Filesystem, And Sandbox Boundaries

Use `protocol_or_object_shape` for alternate encodings, nested objects, aliases, symlinks, hard links, path normalization, archive members, generated inputs, and platform-specific forms. Trace validation and use at the same identity and time boundary; preserve at least one valid supported shape.

## Separate Source Falsifier

Before any `auto_merge_candidate`, and before a merge-family recommendation for a high or critical boundary, perform a fresh source-only falsifier pass. Prefer an independent evaluator when available. Otherwise start a separate pass that receives the immutable patch, exact source, invariants, and required catalog dimensions, but not the draft recommendation, risk ratings, terminal outcome, post-cutoff comments, or desired conclusion.

The falsifier tries to produce one concrete source trace that defeats an invariant or legitimate control. It independently challenges applicable domain completeness and claim-oracle coverage rather than replaying only examples selected by the patch. Merge-family output requires every challenge to be handled or preserved, every applicable domain and claim-oracle result to be `complete`, and the falsifier status to be `passed`. A confirmed source failure requires `revise`; a genuinely external unresolved pivot may require `needs_validation`; lack of a falsifier pass requires human review and cannot produce `auto_merge_candidate`.
