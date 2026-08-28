# Security Hardening Proposal Format

Use this format for a derived hardening analysis based on vulnerability disclosures, supplied findings, incident or assessment documents, source evidence, a completed Codex Security scan, or a mixture of these. The analysis is a design product, not part of its source evidence and not proof that any finding has been remediated.

## Contents

1. [Artifact Set](#artifact-set)
2. [Writing Voice And Narrative](#writing-voice-and-narrative)
3. [Structured Analysis](#structured-analysis)
4. [Portfolio Format](#portfolio-format)
5. [Proposal Format](#proposal-format)
6. [Diagram Rules](#diagram-rules)
7. [Tradeoff Rules](#tradeoff-rules)
8. [Implementation Handoff](#implementation-handoff)

## Artifact Set

Write the following under one analysis directory:

```text
<analysis_dir>/
├── context.md
├── hardening.json
├── hardening.md
├── proposals/
│   └── <opportunity-id>.md
├── diagrams/
│   ├── <opportunity-id>-before.mmd
│   └── <opportunity-id>-<option-id>-after.mmd
└── implementation/
    └── <option-id>.md
```

`context.md` is local working context and may contain a local source-root path.
The other artifacts must be distributable and use only repository-relative source paths and analysis-relative artifact links.

Create `implementation/` only after the user selects an option or explicitly asks for implementation planning.

## Writing Voice And Narrative

Write for security engineers and software engineers who are technically strong but may not know this subsystem or the original scan. The documents should feel like a principal security engineer calmly walking peers through a design question: professionally warm, precise, candid about uncertainty, and open to input. Do not sound robotic, alarmist, bureaucratic, or overly familiar.

Use first person as an integral part of the design-review voice:

- use first-person plural throughout the substantive walkthrough to guide shared reasoning: "we can see why the current ownership boundary drifts",
  "if we keep the fast path", or "we would pay this memory cost only while old generations drain";
- use first-person singular truthfully and sparingly to establish work the author actually performed and the recommendation being offered: "I inspected these callers", "I measured", "I could not validate the device exposure",
  or "I recommend Option 2 under the current constraints";
- never imply that code was run, performance was measured, or behavior was observed when the basis is source review, supplied evidence, analogy, or a hypothesis. Say which basis applies in plain language.

This is not a pronoun quota. Do not decorate mechanical prose with isolated
"we" or "I" statements. First person should expose the reasoning, invite the reader into the design choice, and make the author's evidentiary basis clear.
A proposal with only a token opening and closing in first person still fails this standard.

Let professional judgment show through. Explain what is attractive about an option, what gives the author pause, which tradeoff seems proportionate, and which uncertainty prevents a firmer conclusion. Phrases such as "what gives me pause is...", "the attractive part of this option is...", "we should be honest about...", or "I would be comfortable with this if..." illustrate the tone,
but are not a script. Use the language that fits the actual design and avoid repeating stock sentences across the portfolio.

Build a coherent technical argument rather than filling a template. Patiently connect the relevant actor and boundary, the observed failure, the structural condition that allowed it, the desired invariants, and the available design choices. Preserve the required tables and use them generously where exact deltas, coverage mappings, or cross-option comparisons benefit from a compact view. Treat them as a second layer for scanning and reference, not a replacement for the prose that teaches the reader why the comparison matters. Introduce diagrams and source references, then explain the important edges in words.

Discuss options clearly and calmly. Give each serious alternative its strongest reasonable case, its costs, its residual risks, and the conditions under which it should win. Make a recommendation without salesmanship or option theatre.
Prefer language such as "I recommend Option 1 under the current constraints"
and "Option 2 becomes preferable if..." over absolute declarations. When a local fix is proportionate, say so without manufacturing an architectural project.

The portfolio should be concise, but the proposals should not read like terse triage notes or stitched-together bullets. Give the portfolio enough prose to explain why these opportunities form a coherent decision set. Give each proposal the fuller discussion needed to let an engineer challenge the diagnosis, compare the options, and begin implementation without reconstructing the argument. Use paragraphs for reasoning and lists for genuinely list-shaped material. Preserve the natural rhythm of the prose; terminal-friendly wrapping is welcome when it does not damage clarity, links, tables, code references, or technical language.

Before accepting a proposal, make sure the narrative itself, without relying on tables, does all of the following:

- connects observed evidence to the inferred structural condition and explains why that inference is reasonable;
- gives every serious option its strongest case, including what it preserves,
  what changes, how the control works, and where risk remains;
- explains the mechanism behind material security, performance, memory,
  reliability, operational, and migration effects;
- makes the author's considered view visible, including the appealing part of each option, the principal concern, and what evidence would resolve it;
- introduces each diagram and table, then explains the decision-relevant edges or comparisons that the reader should take from it;
- offers a conditional recommendation and names the facts, constraints, or priorities that would make another option preferable.

Reject and rewrite prose that is impersonal, mechanically mirrors the heading structure, or compresses an option into a diagram, delta table, and one short paragraph. Depth should follow the decision's complexity; do not pad a simple point to meet an artificial length target.

For a complex architectural alternative, one introductory paragraph and one closing paragraph around a diagram and table will rarely be enough. Develop the option in connected prose that can stand on its own: first make its strongest case and explain the mechanics; then reason through security and residual risk; then spend real attention on the resource, reliability, and migration effects that could change the decision. Explain a credible introduction and rollback posture for that option, not only for the final recommendation. Compress genuinely neutral or simple points rather than manufacturing equal-length sections.

## Structured Analysis

Write `hardening.json` as UTF-8 JSON with this shape. Additional fields are allowed when they carry meaningful semantics, but do not use `extensions` as a dumping ground for prose that belongs in the proposal.

The first example is scan-backed. For ordinary documents, use the `sourceEvidence` alternative described immediately afterward.

```json
{
  "documentType": "codex-security.hardening-analysis",
  "schemaVersion": "1.0",
  "analysisId": "hardening_20260619_example",
  "sourceScan": {
    "scanId": "scan_example_001",
    "manifestSha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "targetRevision": "deadbeef",
    "snapshotDigest": "codex-security-snapshot/v1:sha256:...",
    "sourceDrift": "none"
  },
  "assessment": {
    "outcome": "opportunities_identified",
    "summary": "The scan supports one cross-cutting containment opportunity."
  },
  "constraints": {
    "profile": "balanced",
    "changeHorizons": ["incremental", "medium_term", "foundational"],
    "nonNegotiables": [],
    "assumptions": [
      "No measured latency or memory budget was supplied."
    ]
  },
  "opportunities": [
    {
      "opportunityId": "centralize-archive-containment",
      "title": "Centralize archive destination containment",
      "summary": "Move destination derivation and containment behind one owned extraction boundary.",
      "diagnosis": "Several extraction paths can independently construct filesystem destinations.",
      "evidence": [
        {
          "claimType": "observed",
          "sourceKind": "finding",
          "findingId": "csf_852f90d6e1177502ff113d4a",
          "path": "src/extract.py",
          "claim": "An archive entry path reaches a filesystem write without containment validation."
        },
        {
          "claimType": "inferred",
          "sourceKind": "source",
          "path": "src/extract.py",
          "claim": "Destination policy is owned by callers rather than by the write boundary."
        }
      ],
      "desiredInvariants": [
        "Every extraction write uses a destination proven to remain under the caller's output root."
      ],
      "proposalPath": "proposals/centralize-archive-containment.md",
      "options": [
        {
          "optionId": "local-guards",
          "title": "Strengthen local guards",
          "kind": "baseline",
          "summary": "Patch each existing extraction path and add shared regression cases.",
          "diagramPaths": {
            "before": "diagrams/centralize-archive-containment-before.mmd",
            "after": "diagrams/centralize-archive-containment-local-guards-after.mmd"
          },
          "findingCoverage": [
            {
              "findingId": "csf_852f90d6e1177502ff113d4a",
              "effect": "addresses",
              "tacticalFixRequired": true,
              "rationale": "The local containment check is itself the tactical fix."
            }
          ],
          "tradeoffs": [
            {
              "dimension": "security",
              "direction": "improves",
              "confidence": "high",
              "basis": "source-derived",
              "assessment": "The observed write path rejects escaping entries, but future callers can still omit the guard.",
              "validationPlan": "Run the original traversal PoC and search every extraction write path."
            },
            {
              "dimension": "performance",
              "direction": "neutral",
              "confidence": "medium",
              "basis": "source-derived",
              "assessment": "The local lexical containment check adds no I/O or process boundary.",
              "validationPlan": "Benchmark representative archive extraction before and after the guard."
            },
            {
              "dimension": "memory",
              "direction": "neutral",
              "confidence": "medium",
              "basis": "source-derived",
              "assessment": "The guard requires only bounded temporary path values.",
              "validationPlan": "Compare peak RSS while extracting archives with many entries."
            },
            {
              "dimension": "reliability",
              "direction": "improves",
              "confidence": "medium",
              "basis": "source-derived",
              "assessment": "Escaping entries fail before a filesystem side effect.",
              "validationPlan": "Exercise mixed valid and invalid entries and verify deterministic failure behavior."
            },
            {
              "dimension": "operability",
              "direction": "neutral",
              "confidence": "low",
              "basis": "hypothetical",
              "assessment": "No new service is introduced, but rejection telemetry may be useful.",
              "validationPlan": "Confirm whether existing extraction errors are observable in production."
            },
            {
              "dimension": "migration",
              "direction": "neutral",
              "confidence": "high",
              "basis": "source-derived",
              "assessment": "The change preserves the current extraction API.",
              "validationPlan": "Run compatibility coverage for valid relative archive entries."
            }
          ],
          "residualRisks": [
            "Containment policy can drift between call sites."
          ],
          "implementationReadiness": {
            "affectedComponents": ["src/extract.py"],
            "workPackages": ["Add containment enforcement and regression coverage."],
            "acceptanceCriteria": ["The original traversal PoC cannot write outside the output root."],
            "migrationNotes": [],
            "rollback": "Revert the focused guard and test change."
          }
        }
      ],
      "recommendedOptionId": "local-guards",
      "recommendation": "Use the baseline only when delivery time dominates recurrence risk."
    }
  ],
  "openQuestions": []
}
```

For disclosures, supplied findings, or another non-scan collection, replace `sourceScan` with an integrity-recorded evidence identity:

```json
{
  "sourceEvidence": {
    "kind": "document_collection",
    "label": "Kernel vulnerability disclosure documents",
    "collectionSha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "artifactCount": 12,
    "sourceDrift": "unknown"
  }
}
```

When an option maps to disclosure documents rather than canonical scan findings, use `evidenceCoverage` in place of `findingCoverage`:

```json
{
  "evidenceCoverage": [
    {
      "evidenceId": "evidence-001",
      "effect": "mitigates",
      "tacticalFixRequired": true,
      "rationale": "The structural boundary narrows recurrence risk, while the affected path still needs its direct lifetime fix."
    }
  ]
}
```

### Required Semantics

- Record at least one of `sourceScan` or `sourceEvidence`. Both may be present for a scan supplemented by external evidence.
- For analysis of an already completed scan, `sourceScan.manifestSha256` binds the analysis to the sealed input when that digest is available and verified.
  Do not require or invent it when hardening runs before normal scan completion. Record at least one immutable target identity, `targetRevision`
  or `snapshotDigest`, when the source scan provides one.
- For non-scan analysis, `sourceEvidence.collectionSha256` binds the analysis to the inventoried input collection. Record its `kind`, reader-facing `label`, and positive `artifactCount`. A target revision or snapshot digest is optional because ordinary disclosures may not identify one.
- `sourceDrift` is one of `none`, `present`, or `unknown`.
- `assessment.outcome` is `opportunities_identified` or `local_remediation_preferred`.
- `assessment.summary` is the concise reader-facing conclusion used by the scan report index. It must not claim that proposed work is implemented.
- `opportunities_identified` requires at least one complete opportunity.
  `local_remediation_preferred` requires an empty opportunity list and a portfolio that explains why tactical fixes are proportionate.
- `claimType` is `observed` or `inferred`. Proposed behavior belongs in option text, not in the evidence array.
- `sourceKind` is `finding`, `disclosure`, `document`, `source`, `coverage`,
  `threat_model`, `poc`, or `experiment`. Use `evidenceId` for disclosure,
  document, PoC, or experiment evidence and `findingId` for a canonical finding.
- `kind` is `baseline`, `incremental`, `structural`, `isolation`, or `foundational`.
- Each option must contain at least one `findingCoverage` or `evidenceCoverage` mapping. Their `effect` is `addresses`, `mitigates`,
  `unaffected`, or `unknown`.
- `direction` is `improves`, `regresses`, `neutral`, or `unknown`.
- `confidence` is `high`, `medium`, or `low`.
- `basis` is `measured`, `source-derived`, `analogous`, or `hypothetical`.
- `recommendedOptionId` may be `null` when constraints do not support a clear recommendation. Otherwise it must name an option in the same opportunity.
- Every opportunity and option ID must be unique within the analysis and use lowercase letters, digits, dots, underscores, or hyphens.
- Every option must assess `security`, `performance`, `memory`, `reliability`,
  `operability`, and `migration`. Use an honest `neutral` or `unknown` entry rather than omitting an inconvenient dimension.

## Portfolio Format

Write `hardening.md` with these headings in order. Use `Evidence Basis` for an ordinary or mixed collection; `Source Scan` remains acceptable for analysis derived solely from a Codex Security scan.

```markdown
# Security Hardening Review: <target>

## Evidence Basis
## Constraints
## Opportunity Portfolio
## Recommendation Summary
## Next Decisions
```

Under `Opportunity Portfolio`, use a compact table:

| Opportunity | Evidence | Options | Recommendation | Proposal |
| --- | --- | --- | --- | --- |

Link every proposal using its exact `proposalPath`. Make the recommendation conditional on the recorded constraints. Keep this document easy to skim; put the complete technical argument in the proposal file. Open with enough prose to orient a reader who did not participate in the scan, and use the recommendation summary to explain the reasoning in a warm design-review voice rather than merely repeating the table.

The `Evidence` cell must be meaningful without opening `context.md`. Use short finding or document titles, optionally followed by their IDs, or a clear reader-facing group label linked to the proposal. Do not write a bare list such as `E021, E022, E031` or opaque canonical finding hashes. For example, prefer `Netlink length and scratch failures (E021, E031)` or link a compact label such as `6 decode-boundary findings` to the proposal that defines all six.

For a `local_remediation_preferred` assessment, retain all required portfolio headings. Under `Opportunity Portfolio`, state that no structural opportunity qualified; under `Recommendation Summary`, explain the local remediation conclusion. Do not create proposal or diagram files for fictional options.

## Proposal Format

Name each proposal `proposals/<opportunity-id>.md` and use these headings in order:

```markdown
# Security Hardening Proposal: <title>

## Decision
## Executive Recommendation
## Evidence
## Current Design And Failure Mode
## Desired Invariants
## Constraints And Non-Goals
## Before Architecture
## Options
### Option 1: <baseline, when useful>
### Option 2: <first alternative>
## Comparison
## Recommendation
## Evidence Coverage And Residual Risk
## Migration And Rollout
## Validation Plan
## Implementation Work Packages
## Open Questions
```

Requirements:

- start reader-facing option numbering at 1, including when Option 1 is the baseline; never expose a zero-based implementation index as "Option 0";
- keep structured `optionId` values semantic and independent of display order so options can be reordered without renaming machine-facing identities;
- introduce every option in `Executive Recommendation` using its number and a short descriptive title before referring to the option by number alone;
- make the complete option set visible before recommending a subset, and avoid numbered step lists that could be mistaken for the numbered options;
- identify observed and inferred claims explicitly in `Evidence`;
- define every opaque finding or evidence ID in the proposal where it is used;
  pair it with a concise title and a one-line statement of what it establishes,
  using a compact evidence map when several items contribute;
- when source or artifacts were actually inspected, state that basis truthfully in first-person and explain which evidence most influenced the structural diagnosis;
- cite finding IDs or evidence IDs and repository-relative source locations when source is available;
- explain the structural condition, not merely the vulnerable line;
- state desired invariants before proposing components;
- include the before diagram and one after diagram for every option;
- follow each diagram pair with a delta table using `Change`, `Before`,
  `After`, `Security consequence`, and `Cost`;
- include a tradeoff comparison table without a fabricated composite score;
- explain every option in connected prose before relying on its diagram or delta table, including the control mechanism, strongest case, material costs, residual risk, rollout, and rollback;
- explain the recommendation under current assumptions, state it in first-person when a recommendation is supported, and say when another option should win;
- preserve tactical fixes needed during migration;
- list concrete validation, benchmark, rollout, rollback, and acceptance work.

Use this shape under `Evidence` when several findings or documents contribute:

| Evidence | Finding or document | What it establishes |
| --- | --- | --- |
| `E021` | Netlink multipath scratch exhaustion | Attacker-controlled nesting can exhaust unchecked parser scratch space. |

Link the finding or document title to its writeup when a distributable relative path is available. The title may be shortened for readability, but it must be specific enough that a new reader understands the reference. After defining an ID once in the proposal, later prose may use the ID alone where repetition would be awkward. In `Evidence Coverage And Residual Risk`, label every row with both the ID and short title, for example `E021 — Netlink scratch exhaustion`. Apply the same rule to canonical scan finding IDs. A complete registry in `context.md` supports auditability but does not make a bare ID self-explanatory in another document.

The proposal should read as one connected discussion. In particular:

- establish the component, relevant actor, trust or lifetime boundary, and evidence basis before asking the reader to choose an option;
- keep evidence references locally understandable; do not make the reader shuttle to `context.md` to decode an identifier;
- move naturally from observed facts to the inferred structural condition,
  making the change in epistemic status explicit without reducing the section to labels;
- introduce each option in prose, explain what it preserves and what it asks the project to change, how the changed boundary creates the security effect,
  and then use diagrams or tables to sharpen the point;
- return to prose after each diagram and comparison table to interpret the important edges, cost mechanisms, and remaining uncertainty;
- avoid repeating the same opening, transition, and verdict formula for every option or proposal; let the actual engineering concern shape the discussion;
- compare alternatives fairly, including useful rejected or deferred designs when they teach an important constraint;
- state the recommendation in first-person when it is supported, explain why it fits the current constraints, and name the evidence or priority that would change the recommendation;
- avoid generic endings. Leave reviewers with concrete decisions, open questions, and a comfortable path to refine or implement the design.

## Diagram Rules

Use Mermaid `flowchart` source in `.mmd` files. Keep diagrams compact and security-relevant:

- reuse component names and abstraction level across before and after views;
- show trust boundaries, attacker-controlled entry points, control ownership,
  dangerous capabilities or sinks, and failure containment;
- label changed control or authority edges clearly;
- avoid code-level call graphs unless the proposed change is itself a call boundary;
- do not imply that a process, service, queue, or sandbox exists unless source or deployment evidence supports the before view;
- keep supporting detail in prose rather than filling nodes with paragraphs.

## Tradeoff Rules

Assess these dimensions for every option:

| Dimension | Questions |
| --- | --- |
| Security | Which attack paths disappear, narrow, or remain? What new trusted component appears? |
| Performance | Does the critical path gain hops, copies, serialization, locks, or cache misses? |
| Memory | Are there new processes, buffers, indexes, queues, caches, or retained objects? |
| Reliability | How do failure isolation, retries, backpressure, recovery, and availability change? |
| Operability | What new deployment, observability, alerting, or incident response burden appears? |
| Migration | What compatibility, data, protocol, rollout, and rollback work is required? |

For unmeasured effects, name the likely mechanism and a measurement plan. A useful plan identifies the workload, metric, baseline, candidate design, and decision threshold. Do not present analogy or intuition as benchmark data.

## Implementation Handoff

After selection, write `implementation/<option-id>.md` with:

```markdown
# Implementation Plan: <option title>

## Selected Design And Constraints
## Source Revision And Drift Check
## Affected Components
## Ordered Work Packages
## Compatibility And Migration
## Tactical Protections During Migration
## Tests And Security Validation
## Performance And Resource Benchmarks
## Rollout And Rollback
## Acceptance Criteria
## Open Decisions
```

Anchor the plan to the scan manifest digest or evidence collection digest and,
when available, the refreshed implementation revision. If source drift changes a relevant boundary, return to design review instead of quietly adapting the proposal while coding.
