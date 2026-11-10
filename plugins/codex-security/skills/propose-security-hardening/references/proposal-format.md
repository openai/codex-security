# Detailed Security Hardening Proposals

Use this reference when the requested decision benefits from a detailed proposal or portfolio. Adapt the structure to the work; these are optional formats, not a required artifact suite.

## A focused proposal

Explain the problem, the evidence for its structural cause, the meaningful alternatives, and the recommendation. A useful outline is:

```markdown
# Security Hardening Proposal: <title>

## Recommendation

## Evidence and Current Design

## Desired Invariants and Constraints

## Options and Tradeoffs

## Migration and Validation

## Open Decisions
```

Keep the recommendation understandable without reading the original finding. Define evidence identifiers with a short title and explain what each cited item establishes. Cite source locations and revisions when known. Separate supplied claims, inspected evidence, inference, and design expectations.

For each serious option, describe how it works, why its changed boundary improves security, what risk remains, and the costs that matter. Give alternatives a fair comparison. When local fixes are sufficient, explain that conclusion without inventing larger designs.

Discuss performance or resource effects through their mechanisms, such as added copies, process boundaries, retained state, or synchronization. Separate measured results from estimates. Where uncertainty could change the choice, identify a useful workload, metric, baseline, and decision criterion rather than manufacturing a score.

## Diagrams and tables

Use a diagram when it explains control ownership, authority flow, isolation, or state transitions more clearly than prose. Keep before-and-after views at the same abstraction level, reuse component names, and show only supported current structure. Mermaid flowcharts can be embedded in the proposal; separate `.mmd` files are useful when requested for reuse.

A comparison table can summarize material differences. An evidence-coverage table can help when several findings contribute; identify what an option addresses, mitigates, leaves unaffected, or cannot yet resolve. Neither table is required for a simple decision.

## Multiple opportunities

For a large analysis, use a short portfolio that links to individual proposals and explains their relationship and relative priority. Suggested relative paths are:

```text
hardening/hardening.md
hardening/proposals/<opportunity-id>.md
hardening/diagrams/<opportunity-id>-<view>.mmd
```

Resolve physical directories through `../../../references/artifact-storage.md`. Only `hardening/hardening.md` is required when attaching the analysis to a scan. If no structural change is warranted, that file can explain why local remediation is preferable; no proposal or diagram files are needed.

Keep distributable source citations repository-relative and links relative to the analysis. Do not include author-machine paths or internal drafting notes. Preserve original evidence separately from the derived design.

## Structured output

Generate structured output when requested or when an identified consumer needs it. Use that consumer's schema. The scan attachment consumes `scan.hardening.portfolioPath`, not a separate `hardening.json` document.

For a standalone structured analysis without an existing schema, useful fields include source identity, constraints, opportunities, evidence references, options, material tradeoffs, residual risks, and recommendations. Use stable semantic IDs for cross-references. Record immutable revisions or verified digests when available; do not fabricate missing identities or require a collection digest merely to analyze supplied documents. Validate generated JSON and its references before delivery.

## Implementation planning

When requested, turn the selected design into work packages with affected components, compatibility constraints, tactical protections, meaningful tests, rollout or rollback needs, and acceptance criteria. Include benchmarks only where resource or performance uncertainty matters. Check the source revision before implementation and revisit the design if relevant drift changes its assumptions.
