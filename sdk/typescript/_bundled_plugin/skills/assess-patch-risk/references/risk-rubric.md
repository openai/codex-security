# Patch Risk Rubric

Use this rubric to turn repository evidence into consistent categorical ratings. Rate the evidence that exists; do not fill gaps with optimistic assumptions.

## Core Ratings

Rate `impactIfWrong` by the worst credible regression supported by the affected production paths:

- `low`: local behavior with no meaningful external, persistent, privileged, or shared-path effect;
- `moderate`: one bounded component, workflow, or consumer can malfunction without crossing a critical boundary or causing difficult recovery;
- `high`: a shared production path, public contract, important availability path, security boundary, or persistent state can be materially affected; or
- `critical`: the patch can plausibly cause widespread outage, irreversible or cross-tenant data damage, systemic authorization failure, unsafe update or deployment behavior, or an equivalently severe consequence.

Rate `regressionLikelihood` from semantic complexity, coupling, behavioral novelty, regression protection, and unresolved assumptions:

- `low`: behavior is narrowly changed, important paths are understood, regression protection is strong, and no material assumption is unresolved;
- `moderate`: the change is understandable but has partial protection, multiple paths, or bounded uncertainty;
- `high`: the patch changes complex or weakly understood behavior, lacks direct regression protection, crosses several components, or relies on material unverified assumptions; or
- `critical`: available evidence already demonstrates a serious regression or a required safety property fails.

Rate `confidence` independently:

- `high`: the exact patch and base were verified, relevant production roots and contracts were traced, and the important checks ran successfully;
- `moderate`: the main paths are supported but one bounded consumer, environment, or validation gap remains; or
- `low`: material reachability, external consumers, dynamic registration, deployment behavior, or validation results remain unknown.

## Overall Risk Matrix

Start with this matrix, then apply the escalation rules below.

| Impact if wrong | Low likelihood | Moderate likelihood | High likelihood | Critical likelihood |
| --- | --- | --- | --- | --- |
| Low | low | low | moderate | high |
| Moderate | low | moderate | high | critical |
| High | moderate | high | critical | critical |
| Critical | high | critical | critical | critical |

Escalate the result by one band when recovery is `hard` and the failure can persist after rollback. Do not report `low` overall risk with `low` confidence. Never lower risk by averaging dimensions, and never lower a known `critical` likelihood.

## Dimension Guidance

### Change Scope

Consider production files and symbols separately from tests, generated output, docs, and mechanical changes. Inspect control-flow branches, side effects, defaults, dependencies, configuration, build metadata, and migrations. A one-line privileged-boundary or default change can be high risk; a large test-only change can be low risk.

### Blast Radius

Map changed symbols to direct callers, transitive production roots, affected callees, package or build dependents, runtime frequency, and external consumers. Weight runtime role more than raw caller count. When a sparse checkout omits an apparent caller, inspect the exact revision's Git objects and resolve the actual import before inferring absence or substituting a same-named symbol. Rate blast radius `unknown` when dynamic dispatch, reflection, framework registration, generated bindings, configuration, or unavailable downstream repositories prevent a supported conclusion.

Treat code as dead only when evidence excludes production roots, exports, registration, packaging, deployment, and supported external consumers. No text-search result alone is insufficient.

### Boundary Criticality

Raise risk for authentication, authorization, tenant isolation, cryptography, sandboxing, parsing and deserialization, filesystem and network access, secrets, payments, deployment, update channels, or similarly privileged behavior. Tests can reduce likelihood but do not reduce the consequence of failure at these boundaries.

### Contract And State

Inspect public APIs, CLI semantics, schemas, wire and serialized formats, configuration defaults, persisted data, migrations, cache keys, error behavior, compatibility windows, and version skew. Include both producers and consumers. Irreversible migrations or writes make recovery harder even when the code diff is small.

### Runtime Behavior

Inspect concurrency, ordering, retries, idempotency, resource bounds, performance, availability, fallback behavior, error propagation, and cleanup. Prefer evidence from the realistic runtime boundary over helper-only reasoning.

### Source Sufficiency Challenge

Before treating the current source and tests as sufficient, try to disprove that conclusion using [boundary-challenges.md](boundary-challenges.md). Derive the intended safety and compatibility invariants, then record and trace the strongest plausible counterexample and at least one legitimate control through every material changed boundary and affected caller. Compare each counterexample at the exact base and head: require revision when the patch introduces or enables a failure, breaks a supported existing invariant, or leaves its specifically claimed remediation bypassable. An unchanged, explicitly acknowledged residual risk outside a bounded partial-remediation claim is status-quo evidence. Derive legitimate controls from exact-base source or callers, including trusted producers and supported persisted or historical object versions; a changed test alone cannot establish prior support. Relevant counterexamples include alternate URL, protocol, object, identity, or persisted-state shapes; fallback and error routes; mixed-version behavior; parallel entrypoints; and documented exceptions.

For policy-enforcing network, authorization, sandbox, proxy, or validation changes, enumerate policy and feature-gate modes together with multi-step target transitions. A trusted initial request does not make redirects, embedded or advertised URLs, callbacks, imports, or nested resources trusted. Record each transition in `trustTransitionCoverage`, including whether trust can change and whether policy is independently reclassified, independently proven equivalent, inherited, or unresolved. Inherited policy is a source gap; unresolved or unreviewed transitions cannot support merge-family output. Test combinations of initial and derived trust classes; checking each setting or request hop in isolation is insufficient.

Tests are evidence about the cases and assertions they contain, not proof that the case inventory or asserted contract is correct. A patch can pass focused tests while leaving a parallel trust-boundary route open, rejecting a supported control, or making documentation claims that the code does not enforce. Those source-visible failures require `revise` even when more validation could measure prevalence or reproduce them dynamically.

When correctness depends on a bounded inventory, mapping, or transition model, apply the catalog's classification-completeness challenge. First compare base and head to classify whether the patch creates a new contract, preserves the existing supported surface, or narrows it. Derive partitions from an authoritative specification, pre-existing repository contract or behavior, compatibility evidence, or bounded state model rather than from the implementation or tests alone. A patch-authored description, allowlist, enum, implementation, or test cannot be the only completeness authority for an existing or narrowed contract. Patch-only provenance is sufficient only for a genuinely new, finite, self-contained contract that is exhaustively enumerated. Representative examples cannot establish completeness. Merge-family output requires acceptable contract provenance, bounded or exhaustive coverage, no contradiction or unclassified material partition, and source-backed handled results for every recorded partition.

When changed documentation, tests, or platform assumptions materially support the merge decision, apply the catalog's claim-and-oracle challenge. Bound the material claims from the exact artifacts, state the property each actually needs to prove, and try a false-positive counterexample that leaves the property broken while the prose or assertion still appears satisfied. The assertion defines its semantic property and permitted equivalence; the test name and setup identify every configured representation that must be independently observed. Do not strengthen equivalent behavior or values into object identity or implementation coupling unless an independently grounded contract expressly requires it. For each claimed property or representation, preserve the other behavior and map an isolated mutation to the exact assertion or output that must change. An unclaimed neighboring case may lower coverage or confidence but does not itself contradict the test; require revision when an asserted property fails or independent source or contract evidence establishes a real defect. Merge-family output requires bounded or exhaustive review, no unreviewed material subject, source-backed support for every claim, assertion, and platform assumption, and complete oracle sensitivity for every supported test assertion.

`merge` and `merge_with_conditions` require affirmative source evidence that the strongest attempted counterexamples are handled and legitimate controls remain supported. Do not use `merge_with_conditions` when an unresolved compatibility, consumer-contract, parallel-route, or documentation concern could require changing source or tests.

For high or critical boundaries, a merge-family recommendation also requires a fresh source-only falsifier pass that does not receive the draft recommendation or desired conclusion. Every `auto_merge_candidate` requires that separate pass regardless of boundary rating. Prefer an independent evaluator when available; otherwise use a clearly separated second pass and record that method honestly.

### Regression Protection

Rate regression protection separately from impact:

- `strong`: existing or new tests directly exercise the changed behavior and important production callers or contracts; meaningful failure and legitimate-control paths are covered; the focused test fails on the base when feasible; and relevant focused and owning-component checks are proven to have run and passed without pertinent skips or flakes;
- `partial`: some changed behavior is directly tested, but an important caller, contract, error path, environment, architecture, deployment observation, or owning suite remains uncovered, unexecuted, blocked, or unavailable;
- `weak`: tests are absent, mock away the relevant boundary, assert only implementation details, exist but were not run in the relevant validation path, or do not cover the semantic change; or
- `unknown`: the test inventory or execution result cannot be established.

Record validation evidence as structured facts rather than collapsing it into a green-check summary:

Inspect exact-head CI that already exists at the decision cutoff. A directly relevant or unattributed failure prohibits unconditional `merge`; explain an unrelated failure with evidence, use `revise` for a patch defect, or retain a decision-critical validation condition when the bounded evidence cannot resolve attribution. Proactively run a focused local check only when it is discoverable, reasonably fast, deterministic, requires no deployment or unavailable credentials, and leaves the patch unchanged.

- `kind`: whether the evidence is a test, static analysis, build, CI result, manual QA, deployment, or runtime observation;
- `executionStatus`: whether it passed, failed, was blocked, was not run, or remains unknown;
- `relevance`: `direct` only when it exercises the changed behavior or affected contract, otherwise `indirect` or `unknown`; and
- `scope`: distinguish changed-behavior, affected-component, broad-system, deployment, architecture-specific, and runtime-observation evidence.

The presence of a test file proves only that a test exists. A passing test proves only the proposition its fixtures and assertions can distinguish; inspect whether wrong fields, alternate representations, normalization, skips, or platform branches can produce a false positive. Configuring multiple inputs does not establish that each is observed: require an isolated mutation and an exact failure signal for every claimed property or representation. A broad green CI check is indirect unless its configuration or logs establish that the relevant test ran. Manual QA, deployment evidence, and runtime observations can be direct when they exercise the real changed boundary, but record them as their actual kind rather than relabeling them as tests.

When correctness depends on apply order, deployed policy, generated artifacts, platform behavior, or architecture-specific inputs, require evidence from those relevant scopes. Source validation and broad CI alone cannot make protection `strong`; absent required post-apply, runtime, or architecture evidence keeps it `partial`. Classify the gap as decision-critical when it can change whether the current patch is safe, and otherwise as a bounded rollout, post-apply, or operational merge condition.

Strong regression protection is evidence for lower regression likelihood and higher analysis confidence. It is not evidence that the impact of a possible failure is smaller.

### Recoverability

Rate recovery `easy` when a code-only revert or proven feature disable restores behavior without compatibility or data repair. Rate it `moderate` when coordinated rollback, cache invalidation, redeploy, or bounded repair is required. Rate it `hard` for irreversible data changes, incompatible contracts, long-lived mixed versions, unsafe rollback, or damage that survives reverting the code.

### Analysis Uncertainty

Record missing evidence explicitly. Common sources include dynamic dispatch, reflection, dependency injection, framework or plugin registries, generated code, external consumers, deployment-only configuration, unavailable integration environments, flaky tests, an unverified patch base or digest, a commit-series artifact whose final file set was not reconciled, and an unresolved sibling patch that may duplicate, depend on, supersede, complement, or conflict with the assessed patch. Unknown means unknown, not low risk.

### Patch Disposition

Classify whether this patch is an applicable merge candidate before recommending what to do with it:

- `active`: repository ownership and a relevant runtime, packaging, deployment, or supported-consumer path are evidenced;
- `inactive`: evidence excludes production roots, exports, registration, packaging, deployment, and supported external consumers;
- `no_affected_instances`: the changed path is live, but prevalence evidence shows that no deployed or supported instance has the condition this remediation targets, and no separate hardening requirement justifies the patch;
- `wrong_repository`: the behavior is live, but this repository does not own the effective implementation or generated source of truth;
- `upstream_owned`: the required change belongs in an upstream dependency or source and a local patch would modify only a derived or ineffective copy;
- `duplicate`: patch-set evidence shows another patch implements the same required behavior without a reason to merge both;
- `superseded`: patch-set evidence shows another patch or patch set replaces this implementation; or
- `uncertain`: applicability or ownership cannot be established from available evidence.

Caller search alone cannot establish `inactive`. Shared issue metadata or file overlap alone cannot establish `duplicate` or `superseded`.

Prevalence evidence can establish `no_affected_instances` even when the changed code is reachable. Keep that distinct from `inactive`. Use it only when the proposed patch is justified as remediation for the absent condition; if the patch has an independently supported defense-in-depth requirement, assess that requirement instead of discarding it silently.

### Decision-Critical Resolution

Attempt every authorized, currently available read-only check before choosing `needs_validation`. This includes repository ownership and reachability analysis, existing provider and CI evidence, linked patch-set context, and feasible focused tests. Future CI, owner action, deployment, telemetry, or production inventory need not be awaited.

If evidence remains externally unavailable, identify the exact decision pivot and explain why resolving it would settle the strongest remaining risk driver. Record a bounded resolution plan containing the exact evidence required, whether collection was attempted but unavailable, is already pending externally, or is blocked externally, what was attempted, one executable evidence action, and at least two evidence-outcome branches covering the plausible results of that pivot. Every branch must end in `merge`, `merge_with_conditions`, `revise`, `no_op`, or `block`; include `no_op` when ownership, prevalence, or patch-set evidence can establish non-applicability. Reassess against the same immutable patch when that evidence is supplied; a changed patch requires a new assessment.

Do not select a convenient proxy such as generic CI, test execution, or owner confirmation when it would leave the strongest source-level concern unresolved. A syntactically bounded decision packet is still insufficient if its evidence axis is unrelated to the decision or its branches omit a plausible terminal outcome.

Do not use validation uncertainty to hide a known source defect. When source or test evidence already shows a trust-boundary, contract, or safety failure and the patch must change, use `revise`. Validation may still measure prevalence or confirm the corrected revision, but it does not make the current defect merely unknown.

### Status-Quo Risk

Rate the risk of leaving current behavior unchanged separately from merge risk. Use repository, issue, incident, telemetry, or operational evidence for the motivating defect and affected paths. If that context is unavailable, use `unknown` and state what is missing. Do not infer status-quo severity from the patch's size, sophistication, or security-oriented wording.

## Recommendation

Choose the recommendation after classifying patch disposition:

- `merge`: the disposition is `active`, the current source and tests are sufficient, decision-critical evidence is present, and no condition beyond ordinary review remains;
- `merge_with_conditions`: the disposition is `active`, adversarial source tracing supports that the current source and tests are sufficient, and only bounded non-code owner review, validation, dependency, rollout, post-apply, or operational conditions remain;
- `revise`: a source-code or test change is required to establish the intended behavior or its safety;
- `needs_validation`: applicability or another decision-critical fact remains externally unavailable after bounded collection, including an unclassified known sibling relationship; the condition records terminal resolution branches;
- `no_op`: the disposition is `inactive`, `no_affected_instances`, `wrong_repository`, `upstream_owned`, `duplicate`, or `superseded`; or
- `block`: a material safety property is known to fail, not merely unverified.

Record each condition with a `kind`, `summary`, and `decisionCritical` flag. Code changes, test changes, and unresolved patch-set analysis are decision-critical. Never hide them under `merge_with_conditions`. When a deterministic changed-subject inventory is supplied, identify every decision-critical condition with reconciliation metadata. `changed_subjects_only` means all evidence needed to settle the condition is represented by its subject IDs and direct controls; any dependency on unchanged source, callers, alternate routes, sinks, persisted state, or configuration is `broader_source`, while deployment, CI, ownership, or other unavailable facts are `external_evidence`. Missing or broader linkage cannot justify automatic de-escalation. Missing validation is a bounded merge condition only when its outcome cannot reasonably overturn the current patch's applicability or basic safety; otherwise use `needs_validation` with the required evidence, attempted collection, collection status, executable action, and terminal outcome branches.

## Automation Eligibility

Recommendation and automation eligibility answer different questions. `merge` means the current patch is merge-ready. `auto_merge_candidate` means it is also inside a deliberately narrow subset that an already-authorized repository workflow may consider for automatic merge.

Emit `auto_merge_candidate` only when all of the following are true:

- recommendation is `merge`, disposition is `active`, and there are no merge conditions or unknowns;
- overall risk, impact if wrong, regression likelihood, blast radius, boundary criticality, contract/state effect, and runtime effect are all `low`;
- confidence is `high`, regression protection is `strong`, recoverability is `easy`, and analysis uncertainty is `low`;
- direct validation of the changed behavior passed, as required by strong protection;
- every structured counterexample is `handled` and every legitimate control is `preserved`; and
- a separate or independent source-only falsifier pass completed with `passed` status.

Change scope may be `low` or `moderate`; size alone must not disqualify a mechanically larger patch when the evidenced program impact remains low. Conversely, a tiny patch cannot qualify by size alone.

Use `human_review_required` for all other `merge` and `merge_with_conditions` results. Preserve `revise`, `needs_validation`, `no_op`, or `block` as the workflow label for the corresponding terminal recommendation. These labels classify evidence and route the next action without collapsing distinct outcomes; they do not bypass repository policy, required checks, codeowners, or user authorization, and they do not perform a merge.
