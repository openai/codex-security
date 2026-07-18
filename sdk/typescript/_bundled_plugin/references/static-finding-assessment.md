# Static Finding Assessment

Use this reference when a Codex Security workflow needs static repository evidence to support or defeat a supplied security claim.

This is not a top-level workflow. It does not define input normalization,
user-facing verdicts, scan ledgers, dynamic validation, or fix behavior. The calling skill owns those contracts.

## Assessment Tuple

For each claim, identify the smallest useful tuple:

- source: the attacker-controlled input, external trigger, or trusted operator input named by the claim
- control: the relevant guard, validator, sanitizer, authorization check,
  configuration gate, feature flag, or missing security control
- sink: the dangerous operation, vulnerable dependency, broken control, or impact point
- reachable path: the code/config path that connects source, control, and sink under stated preconditions
- boundary: the product surface and trust boundary that make the path security relevant
- counterevidence: static facts that weaken, defeat, or scope the claim
- proof gaps: missing facts that prevent a stronger conclusion

Do not treat dependency presence, string matches, or a partial call chain as a complete assessment. A useful static assessment explains both what was found and what remains unproven.

## Evidence Search Order

Inspect the smallest relevant evidence set before broadening:

1. User-provided locations, scanner locations, advisory references, or SARIF result locations.
2. Dependency manifests, lockfiles, package exports, binary entrypoints, build metadata, deploy configs, and generated-artifact boundaries.
3. Affected functions, call sites, routes, RPC handlers, parser entrypoints,
   CLI commands, plugin hooks, message consumers, and package APIs.
4. Nearby guards, validators, sanitizers, authorization checks, feature flags,
   configuration checks, and compensating controls.
5. Product-surface evidence such as `SECURITY.md`, supported-version docs,
   disclosure policy, threat models, product docs, deploy files, comments, and tests that clarify intended behavior.

Prefer precise repository references over broad claims. If evidence is absent,
record the absence as a proof gap unless the absence itself defeats the claim.

## Boundary And Surface Checks

Before treating a static path as security-relevant, classify:

- product surface: hosted service, library API, CLI, local developer UI,
  MCP/tooling surface, plugin hook, example/demo, test/fixture, docs, generated code, vendored code, or unknown
- source trust: untrusted user input, tenant/user-controlled data, remote attacker input, trusted operator input, trusted developer configuration,
  local-only input, intentionally code-executing extension point, or unknown
- policy basis: repository policy, product docs, deploy/config evidence,
  package metadata, code comments, threat model, or unknown

A reachable dataflow is not enough on its own. Static evidence is strongest when the vulnerable condition is reachable and the source crosses a product security boundary the project appears to support.

If a path is only example-only, fixture-only, docs-only, generated-only,
vendored-only, local-only, trusted configuration, or intentionally code-executing extension behavior, record that as counterevidence unless other repository evidence shows the surface is shipped, deployed, documented for untrusted users, or bypasses a supported hardening/auth boundary.

## Static Confidence

Calibrate confidence from evidence quality:

- high: exact source/control/sink path, stated preconditions, relevant boundary evidence, and no material unresolved counterevidence
- medium: plausible path with some direct evidence, but incomplete call-chain,
  config, version, deployment, or boundary evidence
- low: weak or indirect static support, significant ambiguity, or missing repository context

Use proof gaps instead of filling in missing runtime, environment, policy, or deployment facts.

## Output Ingredients

The calling skill decides the final schema and labels. The static assessment should provide enough ingredients for that output:

- concise rationale
- source, control, sink, and reachable path when established
- affected locations with exact repository paths and line references when available
- boundary assessment and policy basis
- supporting evidence
- counterevidence
- proof gaps
- confidence based on static evidence quality
- minimal next step when static evidence cannot settle the claim
