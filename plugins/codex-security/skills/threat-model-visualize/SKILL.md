---
name: threat-model-visualize
description: Turn an existing threat model into an interactive architecture and threat-path explorer. Resolve simple requests for a target's last scan; do not perform a new assessment.
---

# Threat Model Visualize

Create a standalone explorer that shows application teams and leadership what can go wrong, how it could happen, why it matters, and where controls would stop or limit it. Use the shared workbench and role palette; do not use Mermaid or run a new scan.

A request such as “Visualize the threat model generated in the last scan of X” is sufficient. Resolve the target, latest assessment and snapshot. If the latest artifact is missing, disclose that before using an older fallback. The default input is the existing threat-model artifact, not an automatic import of a complete scan. Keep inputs immutable and do not silently combine snapshots. Do not inspect application code or invent topology, authority, controls, reachability or validation.

Capture source-supported deployment context: exposure, trust, tenant and process boundaries, identities, and conditional deployment assumptions. Do not treat repository defaults as proof of deployed configuration. Preserve uncertainty and the distinction between hypotheses, findings, declared controls and observed enforcement. For several explicitly supplied artifacts, pass one derived document to `--assessment`. Label verbatim excerpts with each source’s identity, snapshot and original finding status. Distinguish findings from hypotheses, identify local IDs, and preserve conflicting accounts and the original artifacts.

For a **fresh candidate or regeneration**, author a new view model; do not patch or copy a previous candidate model or HTML. Ordinary edits may reuse the existing model. Renderer-only polishing is a display update, not fresh generation.

## 1. Enumerate and validate the source

Complete this phase before planning any visualization, choosing display groupings or routes, assigning geometry, or authoring the explorer JSON. Save `source-inventory.md` in the workspace. Validate fidelity to the supplied assessment, not the application implementation; do not run a new assessment to fill gaps.

Record the assessment identity, exact file hash and scope. Give inventory rows semantic IDs and supporting source spans or exact quotations, without assigning visual node or edge IDs. Enumerate:

- **Components and roles:** actors, inputs, application components, stores, external dependencies, trust boundaries, platform-specific instances and administrative contexts. Distinguish trusted operators, assumed compromise, controlled input, owned assets and enforcing components.
- **Relationships and capabilities:** each supported caller → operation → receiver relationship, meaningful return, independently sufficient authority or entry condition, prerequisites and platform/deployment conditions. Enumerate alternatives per operation: an account session and an issued capability may each authorize the same operation. Preserve known logical capabilities when transport or order is unknown; do not import a prerequisite from another entry point.
- **Controls and qualifications:** each protective mechanism → enforcing owner → constrained component → protected operation, with conditions and evidence. Record an unmapped enforcer explicitly; configuring or being subject to a restriction does not establish enforcement ownership. Classify existing mechanisms, proposals, security objectives, configuration behavior and caveats separately. Ownership, expanded permissions, disabled protection or documentation advice alone is not an existing safeguard.
- **Threat-model coverage:** substantive threats, supplied findings, hypotheses and consequential configurations, linked to the relevant components, relationships and controls. Retain source confidence, potential impact and unresolved questions.

Review the inventory against the complete assessment before proceeding. Check that evidence supports the same object, caller, operation and owner; distinguish configuration delivery from protected operations and assets from their managers. Do not transfer a validation rule between different inputs or infer platform endpoints from a group label. Account for every substantive source concern; reconcile aliases and record contradictions without inventing a resolution. Correct unsupported assertions, misclassified controls and unexplained omissions now.

Finish the inventory with source-reconciliation corrections and unresolved source gaps. Keep later model-repair notes and review verdicts in `correctness-review.md`, not this source inventory. It is ready for composition when its claims are supported or explicitly unknown and coverage has been reconciled. Source uncertainty may remain; it must not silently become a visual relationship or safeguard. Do not plan the visualization while performing this review.

## 2. Compose from the validated inventory

Read the [view-model contract](references/view-model.md) and [presentation guidance](references/context-explorer.md), then build a source-backed JSON model and geometry. The shell supplies interaction, colors and exports.

Default to **standard**: compose a readable architecture overview before adding threats. Show the actors and entry points, trust boundaries, application or library components, identity and authorization, stores, and external dependencies needed to explain the assessment. Include administrative, automation and build contexts when relevant. Connect them with meaningful request, data and authority relationships. Match platform relationships to the service endpoints named by the source; do not infer group membership or a UI handoff. Use grouping, clear boundaries, aligned flows and short labels while preserving distinctions that change a threat or control. Do not collapse the whole system into one threat's pipeline or move substantive sources and control owners off-map merely for sparsity.

Keep the primary architecture visible in muted colors when a threat is selected. Emphasize its complete source-supported route, including proxies, other transit components, handoffs and meaningful returns. Highlight active transit with fill while retaining its neutral outline; transit alone is not a weakness. Distinguish conditional transitions from ordinary flows. A partial or unmapped view needs an evidence-based scope explanation. Secondary connections may appear under **More connections**, but the basic architecture must stand on its own.

Use the validated inventory as the coverage ledger. Map each substantive operation and its supported authority alternatives to selectable relationships and controls, or an explicit source-supported scope exclusion. Showing an actor in another threat does not cover its access to this operation. Shared nodes and edges must be valid for every alternative that uses them; an unordered union may retain alternative-specific relationships when their membership is explicit. Prose such as “otherwise authorized” cannot broaden an account-only path. An embedded quotation is not selectable coverage. Label a user-requested subset incomplete. Optional authoring fidelity is `simple` for a more grouped summary, `standard` by default, or `detailed` for useful secondary connections and facets; it does not change claims or require a UI selector.

Bind each case's mechanism, priority, prerequisites, impact and evidence to its own substantive source section. Verify that each quotation matches and supports the same object, operation and enforcing owner as the claim. Do not turn ambiguous source language into a more specific existing safeguard. Do not invent a sequence, authority gain or successful transition. Where order is unsupported, show related components with an explicit scope note. Model the actual starting actor or input and least required authority. Trusted operator or administrator activity remains authorized context, even when it changes configuration or consumes resources; make it a threat source only when the assessment explicitly models its abuse or compromise. An added assumption of malicious intent is not source evidence. Classify a caller-controlled value as untrusted input only when the source supports that trust boundary. Keep alternative footholds distinct and scope each selection to its relevant relationships and controls, with other architecture muted.

Expose consequential supplied controls and proposals at their actual operations and enforcing owners. Split controls with different owners, operations or effects, including deployment reachability and protocol authentication. If an enforcing owner is unmapped, disclose the gap rather than assigning the control to its recipient. Label proposals **Proposed control** and their effects conditionally as “Would block” or “Would limit.” Show where and why a control acts, its conditions and residual effect; mark the effect unknown when it is not established. Preserve arrival at the decision owner where required; blocking a sensitive result does not necessarily stop ordinary traffic. Do not present a proposal as deployed or validated.

## 3. Review the model and inspect the explorer

Save a candidate JSON and keep it unchanged while it is being checked. Give a fresh-context reviewer the assessment, view-model contract, inventory and candidate paths. Use `fork_turns: "none"` when spawning the reviewer and withhold the author's rationale and screenshots. While the reviewer works, build that same candidate and run the browser checks below. If delegation is unavailable, do a separate source-first self-review and record that limitation.

The reviewer reads the complete assessment and contract first and derives the obligations from the source. Then compare them with the inventory and the effective selections in the saved JSON:

- Cover each substantive concern, independently sufficient starting authority, operation and consequence. Check trusted roles, deployment conditions, scope exclusions and any unsupported order or prerequisite.
- Resolve the actual highlighted nodes and edges for each distinct selection, including defaults, overrides and branches. Distinguish highlighted failure sites from ordinary transit. Check node and edge captions against the source, including who receives data, where it is stored, and whether grouping changes a trust boundary. Equivalent selections can share a check.
- For each control, match its owner markers, protected operation, classification, conditions and residual effect to the cited passage. Trace stops and arrivals through the effective route. Preserve proposals, uncertainty and unmapped owners as such.

In `correctness-review.md`, record the assessment and candidate hashes, review method, selections checked and remaining gaps. For a required correction, identify the JSON location, source span and mismatch. The reviewer records `PASS` or `REVISION REQUIRED` for the candidate.

Collect semantic and browser findings before editing the candidate. After a JSON change, rebuild the HTML, update the inventory for new claims, and have the reviewer verify affected selections and anything sharing their defaults against the new hash. Recheck the affected rendered states and exports. A display-only change needs the relevant browser checks. Deliver the HTML built from the reviewed JSON. Report the semantic verdict and browser results separately, and label a delivery with outstanding required corrections or checks as a draft.

### Build and browser checks

```sh
python3.12 <skill-directory>/scripts/build_explorer.py <model.json> --assessment <threat-model.md> --output <explorer.html>
```

Choose browser tooling available and permitted in the current environment before starting a preview server. In standalone CLI/CI, check known runtime or dependency locations for an installed headless browser (such as Playwright with Chromium); do not assume a desktop browser host exists. Use that browser for interaction checks, screenshot inspection, offline loading and export verification when policy permits. A missing desktop host does not establish that every browser is unavailable; a policy denial does not authorize a workaround. If no permitted browser is available, deliver the local files and mark browser QA incomplete.

Codex’s in-app browser automation does not support `file:` URLs. For browser QA there, use a local HTTP preview; do not try a file URL first. Other browsers may open the standalone HTML directly from disk. When HTTP is needed, bind your own server to `127.0.0.1` on an unused or OS-assigned port, serve only the output directory, and stop it after QA; do not assume another process on a familiar port serves these files.

Review the builder’s connector warnings. After moving or resizing a node, align adjacent bends with its ports and check that each connector approaches the node from outside. Rebuild after correcting the authored points.

Open the HTML in a browser and inspect the overview, selected scenarios and representative controls at desktop sizes. Check that the architecture, source, route, impact and control remain understandable in context. Inspect representative source and route alternatives and blocked and restored states where mapped. Check readable default-fit text, simple connector routing, text/component collisions, control markers, evidence, navigation, scope and residuals; repack rather than relying on zoom. Prefer minor connector crossings to convoluted detours. Verify offline loading and SVG export. The builder checks structure and exact quotations, not claim truth or visual clarity.

Deliver standalone HTML locally by default. Create, update or publish a site only when the user explicitly requests site hosting or publication; a visualization or preview request alone is insufficient. Do not create a site for local or inline previews. For requested hosting, use the Sites workflow and preserve the requested audience. Use visualize integration for an inline preview. Static requests use an SVG or PNG of the same selected state.
