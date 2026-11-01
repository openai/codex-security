# Validation Guidance

## Evidence and scope

Validate the supplied claim and candidate set. A standalone request for one finding does not authorize a repository-wide search. In a repository-wide scan, discovery's coverage ledger and advisory-seeded rows remain in scope even when they are not yet polished findings.

For each candidate, establish the attacker-controlled source, closest relevant control, sensitive sink, reachable path, trust boundary, and concrete impact. Use `../../../references/static-finding-assessment.md` for static evidence and proof gaps. A matching advisory, dangerous API, helper name, or missing guard is a lead; it is not a finding without a supported security impact.

Choose evidence that tests the claimed boundary. A focused unit test, realistic interface reproduction, sanitizer, debugger trace, or static analysis can each be appropriate. Use runtime validation when it would resolve a material uncertainty and setup is proportionate. Do not rank methods by language or tool name, and do not require a build or live deployment when source evidence settles the claim.

When setup fails, determine whether a targeted harness, existing test, or disposable build copy can exercise the original code. Record missing services, dependencies, or configuration as proof gaps, not evidence of safety. Do not replace the target with a reimplementation and claim it proves the original behavior. Check logs or process status before stopping a command that may still be making progress.

## Preserve independently vulnerable instances

- Give every supplied candidate a disposition: `reportable`, `suppressed`, `not_applicable`, or `deferred`. Preserve its identifiers, source reference, and affected locations, including the root control and any distinct seed anchor.
- One representative reproduction can support related instances, but check each instance's source, control, sink, and impact. A safe sibling or stronger neighboring finding does not decide another row.
- Keep independently triggerable operations and broken controls separately addressable. A wrapper proves reachability; preserve the concrete implementation or shared control that causes the vulnerability. If a family candidate contains several such instances, record their individual dispositions.
- Suppress with evidence that defeats the exact claim. Missing caller, deployment, or provenance evidence may justify focused follow-up or `deferred`; absence alone does not establish safety.
- Prioritize by supported impact, reachability, and unresolved uncertainty. Once further work on one instance would not change its disposition or severity, continue the remaining candidate set.

Check controls at their point of use. Trace alternate representations, branch-specific transforms, redirects, state changes, or object selection when they could change what was validated. A control must cover the object or value the sensitive operation actually consumes. Documented dangerous behavior, optional restrictions, and deprecation establish context; assess whether the claimed attacker crosses an intended boundary.

## Runtime evidence

Use short, non-interactive commands scoped to the claim. When useful, run gdb with `-q -batch -ex run -ex bt -ex quit` or lldb with `-b -o run -o bt -o quit`. Exercise the actual library or application and use a legitimate input as a control when it helps distinguish the vulnerability from ordinary failure.

Follow `../../../references/artifact-storage.md` for disposable execution and retained evidence. Retain only useful PoCs, inputs, and logs; include enough commands and prerequisites to reproduce the result. Do not claim execution that did not occur.

## Confidence

Assess confidence in the complete finding, including reachability, the violated boundary, impact, and counterevidence:

- `high`: the relevant path and security impact are established, with no material unresolved counterevidence;
- `medium`: direct evidence supports the claim, but a material precondition or part of the path remains uncertain;
- `low`: support is indirect or significant context is missing.

A crashing PoC establishes the observed crash; it does not by itself prove every claimed consequence. Static evidence can support high confidence when it establishes the complete claim. Explain what each observation proves and what remains unknown, using the calling workflow's result schema.
