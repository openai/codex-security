# Final Report and Codex Review Directives

Use this guidance when authoring canonical report semantics and returning the generated Codex Security report and review directives.

## Final Outputs

The final readable output is a deterministic projection of `scan-manifest.json`, `findings.json`, and `coverage.json`:

- primary readable markdown report at the final scan report path from `scan-artifacts.md`
- optional detailed vulnerability write-ups under `findings/<slug>/`, linked from the primary report through `finding.writeup.reportPath`
- optional structural hardening guidance under `hardening/`, linked from the primary report through `scan.hardening.portfolioPath`

When writing `findings.json` alongside this readable output, populate the optional structured details in `finding-detail-fields.md` from the same validated evidence. Do not parse the rendered report back into finding data.

Use `report.md` as the primary readable entry point. Explain report-relevant artifact paths in the report itself, especially in `Scope`, `Reviewed Surfaces`, and `Open Questions And Follow Up`.

In the final response, link the generated markdown report path as the primary readable artifact.

Every scan mode uses the same final report pipeline. Workbench-owned Standard and workbench-backed diff scans submit canonical semantics with `record_codex_security_scan_draft({ scanId, handoffClaimToken?, scope?, threatModel?, findings, coverage })`; the workbench supplies authoritative metadata and writes the unsealed canonical draft. Deep Standard scan workers submit complete semantic results through their bound draft tool, and the coordinator aggregates them and writes the parent scan's unsealed canonical draft. SDK-owned Standard scans instead write unsealed canonical files with the exact SDK-provided metadata and leave finalization to the SDK. Terminal scans without a `scanId` retain their existing canonical JSON workflow. No mode authors, repairs, or treats an existing `report.md` as input. Finalization validates and enriches the canonical JSON, seals the canonical JSON and evidence artifacts, then deterministically generates `report.md`. Supply report prose through structured canonical semantics rather than a separately authored report.

For each finding, supply an evidence-supported lowercase vulnerability-family `ruleId`; `taxonomy: { category, cwe }` using its exact known CWEs; verified locations; and `provenance.source`, using `"local_plugin"` only when this plugin actually discovered the finding. Preserve genuine worker or source provenance and any existing canonical candidate identity in the finding extensions. A finding with no known CWE retains `cwe: []`; never invent a classification. Include optional `codeEvidence` only when its actual code is nonempty and every referenced evidence ID is present.

Supply semantic coverage as `{ completeness, surfaces, explicitExclusions, deferred }`, with each surface using the actual `label` and one existing `disposition`. Mark coverage `partial` when a deferred item or `needs_follow_up` surface remains; preserve its real reason and supporting context. Each deferred item needs a meaningful reason; preserve any existing `id` or `candidateId`. The workbench derives a missing ID from its candidate identity or stable deferred-work details. Open questions may be nonempty strings or `{ question, followUpPrompt? }` objects. The workbench derives target and scope metadata, scope include and exclude paths, coverage mode and inventory strategy, finding identities and fingerprints, and surface IDs. Do not put those workbench-owned values or top-level coverage receipt references into the semantic draft.

During a host-backed scan, checkpoint saved findings and pending candidates with `complete: false`; a checkpoint is not a completed audit. After a final workbench-owned Standard or workbench-backed diff draft is accepted with `complete: true` (or the backwards-compatible omitted flag), or the Deep coordinator returns its parent scan's canonical manifest, call `complete_codex_security_scan({ scanId, handoffClaimToken? })` and use its returned completion metadata. An SDK-owned scan returns its unsealed canonical files without calling a completion tool or finalizer; the SDK owns completion and report generation. Read full canonical results only when explicitly requested. For a terminal/chat workflow without a `scanId` or completion tool, retain `python <plugin_dir>/scripts/finalize_scan_contract.py --scan-dir <scan_dir> --source-root <repo_root>` after writing the canonical JSON. Outside the SDK path, do not mark the scan goal complete until finalization succeeds and the generated report exists.

On a confirmed failure or explicit cancellation, the workbench preserves saved results without marking the scan successful. Report validated findings separately from pending candidates and explain the incomplete coverage. Use the retained report and exports; do not start additional model work after cancellation or replace saved results with a no-findings response.

After `complete_codex_security_scan` succeeds, include its returned `usage.totalTokens`, `usage.inputTokens`, and `usage.cachedInputTokens` in the final response when `usage.coverage` is `complete` or `partial`; explicitly label a partial measurement. If coverage is `unavailable`, say that token usage could not be measured instead of reporting zero or estimating a cost. Report only measured completion metadata in a terminal/chat host. Token usage is workbench metadata, not a reason to modify sealed scan artifacts or the deterministic report.

Before workbench-owned Standard or workbench-backed diff completion, require `record_codex_security_scan_draft` to succeed. Before Deep completion, require the coordinator to return the parent scan's already-authored canonical manifest; do not submit another draft or rerun worker phases. SDK-owned Standard and terminal diff workflows instead verify their canonical JSON before the appropriate owner finalizes it. Completion validates and seals existing canonical artifacts and generates `report.md`; it does not create missing artifacts or run skipped scan phases.

An MCP `-32602` input rejection, an `isError: true` result reporting `Input validation error`, or an explicit pre-write rejection of complete coverage containing deferred work or a follow-up surface makes no draft write. Correct only the named paths in the same draft, preserving all valid findings, fields, evidence, and deferred work; retry the same scan at most twice. Stop final submission after the first accepted complete draft; an accepted complete:false checkpoint does not end the audit. Do not blindly retry an ambiguous transport or write failure.

For any other required scan phase, canonical-artifact write, or on-disk existence check that fails before completion, stop the current response and surface the exact workflow blocker. Do not call completion with missing artifacts, return a final report or no-findings result, or satisfy a structured output schema. Leave the durable scan available for a later continuation instead of canceling or failing it solely because canonical assembly is blocked.

If `complete_codex_security_scan` or the terminal/chat finalizer fails, stop the current response and surface the exact MCP or finalizer error. Do not retry completion in the same response, return a final report or no-findings result, or satisfy a structured output schema. Leave the durable scan available for a later continuation instead of canceling or failing it solely because completion failed.

Canonical report semantics live in these fields:

- `scan-manifest.json`: `scan.scope` and `scan.threatModel`
- `findings.json`: each finding's `summary`, `codeEvidence`, `rootCause`, `validation`, `attackPath.dataflow`, `attackPath.reachability`, `severity.rationale`, `severity.changeConditions`, `remediation`, `remediationTests`, and `preventiveControls`
- `findings.json`: optional `writeup.reportPath` for a derived, unsealed detailed vulnerability report written under `findings/<slug>/<slug>.md`
- `scan-manifest.json`: optional `scan.hardening.portfolioPath` for the derived, unsealed design portfolio at `hardening/hardening.md`
- `coverage.json`: `surfaces` including `riskArea` and `notes`, plus `openQuestions`

For a whole-repository Deep scan, the workbench derives `coverage.inventoryStrategy: "repository"` in the stored coverage document; repeated discovery is workflow metadata, not a different inventory strategy. Do not include `inventoryStrategy` in `record_codex_security_scan_draft`.

Older v1 producers may omit the new optional fields. Finalization uses explicit JSON-derived fallback text in that case; it never reads a pre-existing report to fill gaps.

When `scan.hardening.portfolioPath` is present, include a short `## Structural Hardening` section linking the portfolio. Keep individual proposal links and the full option analysis in `hardening/hardening.md` rather than copying them into the primary scan report. The portfolio is design guidance, not evidence that any finding has been remediated.

When there are no reportable findings, include a short `No findings` section that explains why nothing survived discovery or the later reportability gates. For repository-wide and scoped-path scans with a coverage ledger, still include `Reviewed Surfaces` so checked, rejected, not-applicable, and follow-up-needed surfaces remain auditable.

When there are reportable findings, render them as readable markdown findings rather than raw JSON or a dumped schema object.
Order findings from highest severity to lowest severity: `critical`, then `high`, then `medium`, then `low`.

Group observations only when they share the same broken security control and effective remediation. Preserve every affected route, operation, sink, and supporting source location; keep distinct security failures separate even when they share a CWE.

Set the finding category and CWE from the primary broken control. Do not add secondary support-impact CWEs, such as data exposure or missing authentication, to an injection/RCE/path/file/parser finding merely because they make exploitation worse; mention those impacts in prose or emit a separate finding if that secondary control is independently vulnerable.

Workbench-owned Standard scans submit their source-backed final findings and coverage directly through `record_codex_security_scan_draft`; SDK-owned Standard scans write the same semantics into unsealed canonical files. Deep scans semantically aggregate complete Standard worker results, preserving validated findings, attack-path analysis, affected locations, threat-model context, and honest coverage. The coordinator writes the parent scan's canonical draft; the parent does not read candidate ledgers, run separate validation or attack-path phases, or submit another draft. Canonical `severity.changeConditions` must be one non-empty string; when `attack_path.change_conditions` contains multiple strings, join them into one prose string before writing `findings.json`.

For workbench-backed diff candidates, apply row outcomes in this order: validation disposition `reportable` plus attack-path decision `reportable` becomes a finding with its distinct instance and all relevant entrypoint, root-control, sink, and supporting locations; otherwise, a `deferred` result from either phase becomes `needs_follow_up` coverage and a `coverage.deferred` entry using the recorded uncertainty or proof gap; otherwise, validation disposition `not_applicable` becomes `not_applicable` coverage; otherwise, validation disposition `suppressed` or attack-path decision `ignore` becomes `rejected` coverage. A missing required phase record leaves the candidate unresolved and prevents complete coverage. Do not require phase receipts, per-candidate narratives, or another reconciliation pass.

Terminal diff scans without a `scanId` may provide per-candidate ledgers, validation closure tables, and repository coverage ledgers. When those artifacts exist, retain their traceability: start from reportable/surviving rows, preserve exact affected locations, and map suppressed, not-applicable, or deferred rows to public-facing coverage outcomes. Do not silently drop a seeded row because a same-family neighbor survived.

## Report Structure

Use this report structure:

`# Security Review: <repo_or_target_name>`

`## Scope`

Populate `scan.scope` with in-scope context, artifacts reviewed, runtime or test status, validation mode, and explicit limitations. Include/exclude paths and coverage fields supply the remaining projected scope content. If the threat model was generated during Phase 1 rather than provided by the user, say that in canonical scope context. Do not call generated threat-model material an external input.

After the scope bullets, include a compact `### Scan Summary` table when the scan has findings or repository-wide coverage. Use columns `Field` and `Value`. Include the count of reportable findings, severity mix, confidence mix, coverage, and validation mode when those values are known. Keep artifact paths below this table.

`## Threat Model`

Use the completed canonical `threatModel` when one exists. In any workflow that produced only `<context_dir>/threat_model.md`, including Workbench-backed diff scans, preserve that text exactly as `{ "summary": "<completed model text>" }` and include it in the canonical draft. Use the field mapping and scenario reconciliation in `threat-model.md` when building a generated canonical model; do not regenerate it from the final finding list. Preserve source citations, capability boundaries, deployment assumptions, and material unknowns. Finalization reads only the canonical threat-model object when projecting this section.

`## Findings`

Start this section with the findings summary table.

For Deep Security Scan outputs, group the summary table by `extensions.candidateId` and use columns `Findings`, `Reports`, `Severity`, `Confidence`, and `Detailed write-up`. `deep_repository` scans always use this presentation. Scoped-path deep outputs use it when the reportable child findings carry the deep-scan identifiers described below; ordinary scoped standard scans keep the standard table. Emit one table row per reportable canonical DSS finding. `Findings` contains the vulnerability title without duplicated trailing report or provenance annotations. `Reports` lists every child finding's unique `extensions.reportId`, with each id linking to that child's detailed summary section. For compatibility with older deep-scan artifacts, fall back to `extensions.ledgerRowId`; when a ledger row produced multiple reports, use each child's unique trailing title annotation or instance identity rather than displaying duplicate labels. `Detailed write-up` lists the corresponding `writeup.reportPath` link for every child report. Preserve every child report as its own detailed section below the grouped table. When child reports have different severity or confidence levels, list every distinct level in the grouped row. In the scan summary, distinguish the number of reportable DSS findings from the number of child report instances. For every other scan mode, preserve the standard columns `Finding`, `Severity`, `Confidence`, and `Detailed write-up`, with the finding title linking to the detailed summary section.

After the summary table, include a compact `### Confidence Scale` table with columns `Label` and `Meaning`:

- `high`: direct source, configuration, or runtime evidence supports the finding, with no material unresolved reachability or exploitability blocker.
- `medium`: source evidence supports a plausible issue, but runtime behavior, deployment configuration, role reachability, type constraints, or exploit reliability still need proof.
- `low`: weak or incomplete evidence; include only when the user explicitly wants follow-up candidates in the final report.

When a finding records `writeup.reportPath`, link the detailed report from the findings summary and do not duplicate the complete finding inline. The linked write-up is a derived, unsealed readable output; the canonical finding remains the source of truth for adapters and regeneration. Findings without a write-up continue to use the inline format below for compatibility.

Render each inline finding as:

`### [<number>] <title>`

For each finding include a compact two-column metadata table immediately below the heading. Use columns `Field` and `Value`. Include these rows:

- `Severity`: `critical|high|medium|low`
- `Confidence`: `high|medium|low` or a short calibrated confidence label
- `Confidence rationale`: one sentence explaining why the confidence label is calibrated that way, grounded in the validation method, direct evidence, and missing proof if any
- `Category`: concrete vulnerability class
- `CWE`: id and name list, or `none`
- `Affected lines`: path:line-range list

Use a concrete category such as `Authorization bypass / IDOR`, `Path traversal`, `SQL injection`, `XXE`, `Open redirect`, or `Hardcoded credentials`. Do not use generic placeholders such as `security scan finding`.

For standard scan modes, the summary table should link each finding title to its detailed finding section with an intra-document markdown anchor. For the Deep Security Scan grouped presentation, the report id in the `Reports` column owns that link instead. Keep the displayed vulnerability title and report id aligned with the corresponding detailed heading. Use the explicit finding anchor emitted by the deterministic projection.
The summary table and the detailed finding sections must use the same descending severity order: all `critical` findings first, then `high`, then `medium`, then `low`. Renumber findings after sorting so the table order, detailed headings, and anchors match.

Affected lines must include the root broken control or dangerous sink line when that line is identifiable, not only the public wrapper, route, or caller that makes it reachable. For wrapper-to-shared-helper findings, list both the reachable wrapper/entrypoint and the underlying parser, deserializer, path/archive helper, expression evaluator, or auth/authz control line. If a seeded file, class, package, or hunk shares the surviving proof tuple, keep that seed anchor in affected lines instead of replacing it with a broader sibling-only location. If the bug is caused by unsafe transformation or selection before the sink, include the split, parse, canonicalization, normalization, comparison, regex, object-selection, or object-binding line where the control fails. For parser, XML, deserialization, and object-construction findings, include the concrete codec, converter, deserializer, parser feature setup, resolver, class filter, or container handler line when that line performs recursive parsing, type resolution, object conversion, class filtering, or fail-open hardening. For central file-format object models, include low-level helper lines such as `to*Array`, `toList`, `getObject`, numeric conversion, iterator, size-based allocation, unchecked cast, or collection-to-array loops when those helpers are the broken malformed-input control. For recursive placeholder/template findings, include the helper/parser setup line that enables recursive expansion or expression evaluation, not only the later resolver or render call. For resource-serving findings, include the allowlist, path-matcher, URL decoding, canonicalization, or resource-selection line that decides whether the attacker-selected resource is allowed. For stateful authentication protocol findings, include the principal/credential/token/issuer installation, rebind/reauthentication, or validated-vs-consumed object-selection line that creates the auth bypass. For SSO/SAML/federation findings, include the response/assertion selection, signed-object lookup, cloned/returned assertion, subject, audience, recipient, destination, ACS URL, or issuer-binding line that determines which identity object is trusted. For polymorphic or request-selected handler, operation, converter, filter, validator, or strategy families, include the concrete subclass/implementation line that transforms, validates, canonicalizes, selects, or reinterprets attacker input before a shared sink/control, including specialized helper methods and branch predicates inside the concrete class when they perform or enable the unsafe transform. If a special-case branch such as append, wildcard, fallback, copy/move `from`, default-value, or type-resolution handling bypasses or narrows validation, include that branch-local root-control line even when a shared helper is also affected. If the finding text says a shared flaw affects "all", "every", or "any" concrete operation, codec, converter, handler, validator, filter, or resolver, the affected lines must include the concrete implementations identified during discovery or validation; do not rely on "and related classes" prose for independently reachable root-control lines. If equivalent resolver/filter controls are duplicated across core, server, client, remoting, plugin, or import packages, include the runtime/exported implementation that enforces the broken control. For repeated vulnerable templates, routes, query builders, parser operations, or auth/object-access endpoints, keep each independently vulnerable file and line as its own affected instance; do not hide sibling instances as extra context on one representative finding when they can be attacked independently. The Codex review directive should point at the tightest root-cause line unless the wrapper or concrete implementation line is the actual broken control.

Then render these subsections under each finding:

- `#### Summary`
  - Explain why the issue matters, what the vulnerable path is, and why the current controls are insufficient.
  - Wrap code identifiers, RPC names, functions, types, fields, parameters, configuration keys, and literal values in single backticks.
- `#### Root Cause`
  - State the violated security invariant and explain exactly how the implementation breaks it.
  - Walk the vulnerable call stack from the code that accepts or decodes user-controlled input through each meaningful call or transformation to the missing control, dangerous operation, and security-relevant consumer. Do not begin at the sink when an earlier input boundary is known.
  - Give every displayed `codeEvidence` item a role and an explanation that names the carried value and the next callee or state transition. Order `rootCause.evidenceRefs` from input to outcome, with any `expected_control` comparison after the vulnerable stack.
  - Show the smallest complete snippets needed for that walkthrough. Omit incidental helpers, but do not skip a call boundary whose behavior is necessary to understand how attacker input reaches the broken invariant.
  - Do not emit generic prose that only repeats an affected `path:line` already present in the metadata table.
- `#### Validation`
  - Include method, checklist items, evidence, and remaining uncertainty.
  - Pair each important validation claim with actual source in `validation.evidenceRefs`; a list of file names and line numbers is not sufficient evidence for the readable finding.
- `#### Dataflow`
  - Show the technical source-to-sink path inside the code, such as request parameter -> controller -> service/helper -> dangerous sink -> response or side effect.
- `#### Reachability`
  - Explain who can realistically trigger the dataflow, from what boundary, under what preconditions, and what attacker outcome follows. Fold any attack-path facts into this prose or compact bullets instead of emitting a separate `Attack Path Facts` section.
  - Use `attackPath.evidenceRefs` for the few code transitions that establish attacker input, the missing control, and the resulting sink or state change. Keep this shorter than Validation.
- `#### Severity`
  - State the final severity and then explain the rationale.
  - Treat likelihood and impact as inputs to the final severity, not as separate report labels.
  - The rationale should fold in reachability: attacker role, exposed entry point, exploit steps, required feature flags/config, runtime/deployment assumptions, and any counterevidence or blockers.
  - The rationale should explain the concrete security consequence using repository evidence: data exposed, integrity boundary broken, credential/control-plane effect, code execution path, or why impact is narrower.
  - Include one concise sentence explaining what specific additional evidence would raise or lower the severity.
  - Avoid circular phrasing such as `this is high because it is high severity`, `maps to high`, or `high-severity issue`.
- `#### Remediation`
  - Give concrete minimal fixes, tests, and preventive controls.

For repository-wide and scoped-path scans with a coverage ledger, include a concise `## Reviewed Surfaces` section after the findings. This section summarizes what was inspected, what came out of each reviewed surface, and seeded/root-control rows that were suppressed, not applicable, or deferred so an auditor can see why they did not become findings. Use a table with `Surface`, `Risk Area`, `Outcome`, and `Notes`.

Recommended outcomes:

- `Reported`: became a final finding.
- `No issue found`: reviewed and no credible issue survived.
- `Rejected`: plausible-looking candidate was ruled out with specific counterevidence.
- `Not applicable`: the risk class does not apply to that surface.
- `Needs follow-up`: plausible but not fully closed because of a concrete blocker or proof gap.

Write the same content, or a slightly more detailed version, to `<coverage_dir>/reviewed_surfaces.md`.

For broad scans where the completed coverage is useful for triage but too large for high-precision review, include a concise `## Open Questions And Follow Up` section near the end of the report. Use concrete, copyable prompt ideas that narrow the next review to individual commits from the current scan. Do not include this section for precise scans where the requested scope was already sufficient.

Follow-up prompts should be tailored to the actual scan results:

- use exact commit SHAs, PR numbers, short titles, file paths, or component names from the report
- focus each prompt on the specific boundary that made the commit worth follow-up, such as auth, plugin/MCP exposure, artifact downloads, signed URLs, or gateway routing
- avoid generic placeholders

Each finding should make it easy for an application security engineer or software engineer to answer:

- what changed or what path is vulnerable
- what attacker-controlled input or trust boundary matters
- what direct evidence supports the claim
- what counterevidence or uncertainty remains
- why the severity landed where it did
- what the smallest safe fix is

Include the final markdown report path in the response so the user can find the readable report easily.

After a completed scan:

- If the scan found reportable issues, ask whether the user wants to export the findings as JSON, SARIF, or CSV, generate patches, or track selected findings. Name the highest-priority finding.
- Offer tracking only when `$track-findings` can use an available destination, such as Linear, Jira, or GitHub Issues. Name the destination in the question.
- If the report names a specific follow-up, ask whether the user wants to investigate it.
- If the scan found nothing and has no specific follow-up, do not add a generic question.
- Wait for the user's answer before exporting findings, generating patches, tracking findings, or starting another scan.

## Codex Review Directives

For Codex app rendering, emit one `::code-comment{...}` directive per surviving finding in the final response. The markdown report and review directives should agree on title, file, line range, and core explanation.

Map the final report severity to Codex directive priority only when emitting the directive:

- `critical` -> `P0`, `priority=0`
- `high` -> `P1`, `priority=1`
- `medium` -> `P2`, `priority=2`
- `low` -> `P3`, `priority=3`

For each reportable finding, emit a Codex review directive in this form:

`::code-comment{title="[P1] Example title" body="One-paragraph review explanation." file="/absolute/path/to/file" start=10 end=12 priority=1 confidence=0.55}`

Directive requirements:

- `title`, `body`, and `file` are required
- `title` should include the mapped Codex directive priority, formatted like `[P1] Example title`
- `file` should be an absolute path
- `start` and `end` should be tight 1-based line numbers
- `priority` should match the mapped Codex directive priority
- `confidence` should be numeric when available
- emit one directive per finding and none when there are no findings
- inline Markdown code spans are allowed and encouraged for short identifiers, flags, function names, and config keys, such as `git -c`, `--config`, and `diff.external`
- do not put double quote characters inside quoted attribute values, including escaped quotes like `\"`; rewrite quoted command examples without quotes or leave them only in the markdown report
