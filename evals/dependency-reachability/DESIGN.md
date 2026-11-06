# Dependency exploitability design

The command assesses a public dependency advisory against the current checkout:

```sh
codex-security exploitability check CVE-2023-4863 --json
```

It returns one assessment per distinct consumer or operation, with source
citations and explicit uncertainty. A package name or vulnerable version alone
does not establish an affected use. The investigation must connect the selected
dependency copy to the operation and prerequisites described by the advisory.

## Investigation and tracing

The CLI obtains public advisory metadata from OSV and starts the bundled
[dependency-exploitability skill](../../plugins/codex-security/skills/dependency-exploitability/SKILL.md)
in a read-only session. Inside Git, the investigation uses the enclosing worktree;
outside Git, it uses the current directory. It does not execute project code,
reproduce vulnerabilities, or probe deployed services.

`trace_codex_security_code` performs bounded local discovery with an explicit
time budget and hop limit. The CLI requires an executable `opengrep` on `PATH`
outside the scanned checkout. Ripgrep finds files to inspect. The provider
records explicit dependency declarations and uses OpenGrep to identify
candidate calls and same-file flows. An unresolved call carries the matched
name as `calleeText` on the call site. The investigator reads the imports and
build configuration to establish which dependency copy it calls. The trace
returns a bounded sample of matches in supported source and dependency
manifests separately. Automatic traces skip prose. Source scans and parsed
manifests have their own file budgets. Coverage reports truncated samples. The investigator follows up where a gap could affect
the assessment.

A check owns an in-memory evidence graph and a bounded cache of completed
lookups. Repeated traces can reuse unchanged inputs. Graph queries expose
observations, service-resolution state, and coverage limits. A new command
starts with fresh state; graph and cache limits remain explicit limitations.

## Optional service catalog

An explicitly selected project file can set
`exploitability.service_catalog_mcps` to names defined in `codex.mcp_servers`.
The same selected servers support service identity, running-revision, and
caller-access lookups. Configuration should select read-only tools and reference
credentials through environment variables.

`resolve_codex_security_services` sends related source paths and optional project
hints to a catalog helper. The helper retains one conversation across lookup
batches and can learn how source projects correspond to catalog records. It
owns the semantic mapping; paths need not match catalog names literally.
The host verifies that selected service identities and record selections came
from successful calls to the configured servers.

A scoped no-service conclusion requires an explanation and supporting lookups.
An empty exploratory query is insufficient. Unresolved mappings remain explicit;
new project hints or a requested retry can reopen them. Catalog identity and
desired configuration do not establish a running build or access to it.

## Candidate accounting and review

The host records checkout locations for structured dependency declarations,
candidate calls, and same-file flows. Literal graph searches and shell output
supply leads. The investigator can cite any verified source when assessing a
use. Candidate IDs connect the structured observations to their assessments.

The investigator queues items through
`queue_codex_security_dependency_assessments`. Each stable item ID represents
an assessed use, an evidence-backed dismissal, or an explicit unresolved gap.
Related candidate IDs are attached to that item. A previously queued use must
remain selected or be replaced by a reviewed disposition under the same ID.

Review runs in batches of up to 100 items, after one minute or when a batch fills,
with at most two batches in flight. Finalization flushes pending work immediately.
Each review packet includes the candidates, source excerpts, and inventory
receipts bound to its items. Receipt selections preserve the original response identity,
payload hash, and exact record path. Refreshed evidence can invalidate a binding;
unrelated lookups do not invalidate unchanged approvals.

The reviewer evaluates the advisory's prerequisites against each item's evidence
and reads its dependency version from those citations. The submitted version
field is omitted from the review packet. Decisions must identify evidence bound
to that item. Changed claims or evidence require review again. Oversized batches
can be split; failures remain visible rather than becoming approvals.

`get_codex_security_review_status` returns progress and actionable feedback.
Candidate pages and receipt metadata are requested explicitly. Candidate cursors
bind to a discovery generation and position in the complete registry, so assigning
a page does not skip the next page. New discovery requires a fresh cursor.

## Evidence and verdicts

Repository citations name a checkout-relative path and valid line range, with
labels identifying the facts they support. Inventory observations name the
selected server and specific returned record. Neutral observations can use an
empty `supports` list without asserting deployment or access.

- `exploitable`: evidence establishes the affected copy, applicable operation,
  running build, and access by the relevant caller.
- `potentially_exploitable`: the affected copy and operation are established,
  while running-build or caller-access evidence is missing.
- `unknown`: a deciding source fact, selected copy, or downstream operation
  remains unresolved.
- `ruled_out`: a verified fix, control, or other decisive exclusion applies
  to this use.

The host validates report structure, citation boundaries, receipt bindings,
required evidence labels, and candidate accounting. Semantic review checks what
those citations establish. Build configuration alone is not a running observation;
`deployment: "confirmed"` requires running evidence for every verdict.

Final submission through `produce_codex_security_exploit_report` selects the
current reviewed item IDs and candidate generation. The host checks that selected
uses match the report, awaits reviews, and rejects stale or incomplete accounting.
It derives the aggregate verdict from validated uses and actual unresolved gaps:
a positive aggregate requires a positive use, and an unresolved negative scope
cannot become a checkout-wide all-clear. Unresolved limitations preserve their
bound source paths and line ranges.

Final submission has a bounded retry count. Rejections identify the evidence or
accounting gap so the investigator can correct it. The public report contains
the CVE and advisory references, aggregate status, assessed uses, limitations,
and available token usage. Internal queue IDs and receipt selections are not
added to the public report schema. A completed assessment exits zero for every
verdict; automation should inspect the JSON `status`.

## Public evaluation contract

The checked-in [CLI evaluation](README.md) uses pinned public dependency sources
with synthetic application and deployment fixtures. Each command receives the
CVE; case descriptions and expected answers remain with the grader. Grading
checks the expected use's component, version, verdict, and deciding citations.
Verdict agreement and complete evidence coverage are separate requirements.

The [package-to-application evaluation](../package-application-mapping/README.md)
uses small synthetic checkouts and a synthetic read-only catalog to assess
mapping behavior. Model evaluations are opt-in and consume configured account
usage. These fixtures do not establish deployment facts about another environment
or certify exhaustive discovery in an arbitrary repository.
