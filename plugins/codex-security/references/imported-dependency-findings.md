# Imported dependency findings

Model-facing dependency MCP tools require the host's working directory and restrict report reads and assessment writes to that exact repository path. The app's global inventory, task history, and `_from_app` operations are app-only tools for local report management. Direct CLI/SDK callers retain cross-repository access; the workbench's ID-based get, start, and record commands accept `--target-path REPO` to check the stored report target before reading claims or changing assessments.

CLI/SDK assessment and fix sessions receive only their selected saved request in `dependency-request.json`. They work in a separate output directory, with the shared plugin state denied by the session's filesystem permissions. Assessments write the existing result array to `dependency-assessments.json`; the SDK reads it safely and records it using the original assessment ID and repository path. Fix sessions return a proposed patch. These model sessions do not receive a command for the shared workbench, and the SDK keeps responsibility for reading and updating saved records.

Import preserves the original scanner claim. A separate assessment records what Codex checked in the application, its conclusion, and the remaining unknowns. Nothing is submitted to a cloud dependency scan or changed in the vendor system.

## File formats

The adapters accept Snyk Open Source CLI JSON (one result or an array), Endor Labs Finding or ListFindingsResponse JSON or findings CSV exports, and Socket full-scan package artifacts (an array, `ok/data` response, or one package per NDJSON line). CSV is supported only for Endor. Socket package summaries and arbitrary SARIF are not supported by these adapters. Vulnerability and malicious-package alerts are included; license-only and unrelated policy alerts are excluded with a count in the import warnings.

Snyk `--group-issues` output preserves each dependency chain separately. A Snyk export containing failed-project error records is rejected rather than partially imported. Socket streams can contain a single package; an additional package or scores record is not required. Use Socket's `scan view` JSON export for package artifacts; `scan report` policy-summary JSON is a different, unsupported format.

Endor CSV requires the UUID, Title, Severity Level, and Finding Categories columns. When exporting, also select Dependency Name, Location, Remediation, Fix Version, Risk Details, Explanation, Aliases, and Commit SHA to retain the available package identity, evidence, and fix guidance. The default export can omit package identity and locations; these omissions remain input warnings.

For Endor CSV, the original record is the row's cell values. Missing source revisions, call paths, or repository locations are not reconstructed from the export's prose. Vendor locations are retained as supplied; an absolute vendor path is not silently converted into a local repository path. Comma-separated Location cells produce a warning and remain intact because the export does not distinguish path separators from commas in filenames.

Imports are limited to 8 MiB and 10,000 source records, including excluded alerts, with a 16 MiB limit on normalized data and bounded retained metadata. These limits bound normalization and storage work; assessment selections have a separate limit of 100 findings. The complete original file is stored locally. The adapter retains original severity, advisory identifiers, package identity, dependency paths, locations, fix hints, and supplied reachability evidence where available. Offsets in package artifacts are not treated as repository line numbers.

MCP clients can impose a separate response-size limit; the current MCP SDK defaults to 10 MiB. Responses carry the complete data once in `structuredContent`, but a large original record or collection of resolver transcripts can still exceed that transport limit. Use the direct SDK or workbench commands to read oversized saved results.

Parser fixtures and source URLs are in `tests/fixtures/dependency-imports`. The Snyk and Socket examples derive from vendor examples. Endor's adapters have also been checked against real individual Finding JSON exports, a locally assembled two-record JSON envelope, and a real findings CSV export, including a projection with only its default columns. This is deliberately narrower than support for every vendor report.

## Version and evidence checks

The import records the local Git revision and working-tree content. Endor's explicit source-code SHA is compared when supplied. Reports without an immutable repository revision receive a warning; it is not invented from a package release or branch name.

Import does not run a resolver. Assessment first checks advisory identity, affected versions, and the vulnerable operation, then gathers the evidence needed for the selected conclusion. Public advisory and exact public-package source lookups are permitted; repository content, paths, private package identities, and reports stay local. A source-identity or revision warning must be addressed in the assessment: use `unknowns` if it prevents the conclusion, or `limitations` if current evidence independently supports the stated scope. Do not alter the original scanner claim to resolve a discrepancy.

### Result contract

Record these fields for each selected finding:

| Field | Meaning |
| --- | --- |
| `findingId`, `verdict`, `basis` | Exact selected finding ID, outcome, and the evidence supporting it as defined below. |
| `summary`, `applicability` | Concise conclusion and its package, project, code-path, and configuration conditions. |
| `packageVersion`, `versionBasis` | Assessed version and whether it is `declared`, `resolved`, `artifact`, or unknown (`null`), following the version rules below. |
| `unknowns` | Material evidence gaps that could change the conclusion, each with a precise next action. Empty for a decisive verdict. |
| `limitations` | Nonblocking caveats that do not undermine the stated conclusion, including conditional declared-version scope or an independently irrelevant resolver failure. |
| `advisoryEvidence` | Public-source citations as `{url, explanation}`. Each HTTP(S) URL must support the identity, affected range, or operation claimed in its explanation. |
| `externalEvidence` | Inspected public dependency files as described below; use `[]` when none were inspected. |
| `investigation` | Actions actually taken and observed results as `{action, result}`. Include concrete commands, inspected sources, relevant findings, or access errors. Required and nonempty for `inconclusive`; planned work is not an attempted investigation. |
| `attackPath` | `{entryPoint, attackerControl, vulnerableOperation, prerequisites}`, each a nonempty evidence-backed explanation, or `null` when not established. Required for `affects_application`. |
| `codeEvidence` | Repository citations as `{path, startLine, endLine?, explanation}`. Paths are repository-relative and refer to tracked or non-ignored files; the recorder saves actual excerpts. |
| `resolution` | Native evidence as defined below, or `null` when none was gathered. Failed output may be retained without claiming a resolved version. |

Choose the narrowest supported basis:

| `basis` | `verdict` | Required evidence |
| --- | --- | --- |
| `advisory_mismatch` | `not_applicable` | Public advisory evidence establishes that the alert associates the advisory with the wrong package or ecosystem. Native resolution and code citations are not prerequisites. |
| `package_absent` | `not_applicable` | A complete native graph for the relevant project and dependency scope establishes absence: `selectedVersions: []`, `packageVersion: null`, `versionBasis: "resolved"`. An incomplete or failed graph does not establish absence. |
| `version_not_affected` | `not_applicable` | A complete native graph and public affected-range evidence rule out every relevant selected version. `versionBasis` is `resolved`, and `packageVersion` is included in `selectedVersions`; explain how the evidence covers the other versions too. |
| `code_path` | `affects_application` or `not_applicable` | Repository citations establish or rule out the vulnerable operation's required conditions within the stated scope. Include declared, resolved, or artifact version evidence. External source/bundle evidence must connect to that repository path; presence alone, a vendor reachability label, or an unsuccessful search is insufficient. |
| `execution_excluded` | `not_applicable` | Repository citations establish that the fully mapped finding path cannot execute under the checked repository identity/configuration. Explain coverage of alternative entry points. Nested package-version evidence is unnecessary when it cannot change that exclusion; use null version fields when unknown. |
| `unresolved` | `inconclusive` | A material gap prevents a stronger result. Record actual attempts in `investigation`, then state the gap and precise next action in `unknowns`. This is the only basis for `inconclusive` and cannot support another verdict. |

`affects_application` requires an evidenced attacker path, not merely a call to an affected API. Connect `attackPath` to the cited code: identify the entry point, what an attacker can influence, how it reaches the operation, and which required runtime/configuration conditions are established. A hardcoded demonstration input is not an attacker-controlled input; a required but unverified engine, callback, or feature remains an `unknown`. For malware, attacker control can be the malicious package itself executing during install/build. `not_applicable` defeats the selected claim within the documented scope; do not quietly narrow away relevant occurrences to obtain a negative verdict. Both decisive verdicts require empty `unknowns`; a limitation cannot hide evidence that could overturn the conclusion.

Version provenance applies to every verdict, including `inconclusive`:

- `declared` requires an exact manifest pin cited in `codeEvidence` and that exact `packageVersion`. A range is not an exact pin. State in `applicability` and `limitations` that the static result is conditional on that declaration; installed or deployed state remains unestablished. Never present the pin as the effective runtime version.
- `resolved` requires complete native evidence for the reported package in the relevant repository scope. `packageVersion` must appear in `selectedVersions`; it may be null only when that list is empty. Multiple selected versions are allowed. Explain which paths and versions a positive conclusion covers; a negative conclusion must account for every relevant version or establish why other versions are outside its scope.
- `artifact` requires at least one `externalEvidence` entry of kind `manifest` or `shipped_code` with the exact matching ecosystem, package name, and assessed version. Explain the connection from the repository reference to the inspected artifact and from its metadata to the analyzed code. A source-only citation is not version provenance. An inspected manifest does not by itself prove inclusion in a shipped bundle or installation. Scope any conclusion to the inspected artifact; do not claim a resolved local graph or historical deployment from this evidence.
- A null `versionBasis` requires a null `packageVersion`. When a resolver fails, retain its transcript if useful and use null provenance, or `declared` with an independently cited exact pin. Do not label failed or partial resolution as `resolved` even for an inconclusive result.

### External dependency and action evidence

Follow concrete vendor dependency clues or repository imports/action declarations. Inspect the exact public dependency release and relevant consumers instead of stopping at the first import. For CI actions, read the action entrypoint, workflow triggers and conditions, relevant nested actions, and the code actually shipped. Determine whether the affected library is used during action development, shipped for execution, or executed during a repository-controlled install/build. A `devDependency` label or absence of a package name in minified output is not enough to rule out execution.

Fetch public files read-only into temporary storage outside the target, without installing dependencies or running their code. Send only established public identifiers. Where available, resolve the public ref to an immutable commit and fetch files at that commit. Hash the complete fetched bytes with SHA-256 before selecting excerpts. Reuse the files for findings sharing an artifact and scope. Inspect enough of the entrypoint and affected caller to establish coverage; do not require an exhaustive unrelated dependency audit. If access or attribution fails, record what was attempted and the actual result rather than inventing source or leaving available work to the user.

Each `externalEvidence` entry contains:

- `url`: the public HTTP(S) source of the inspected file, preferably pinned to an immutable revision.
- `revision`: immutable source revision when established, otherwise `null`. Do not put a mutable branch or tag here.
- `sha256`: lowercase hexadecimal digest of the complete fetched file bytes, not the excerpt or a rendered web page.
- `kind`: `manifest` for package/version metadata, `source` for implementation source, or `shipped_code` for the executable file actually distributed.
- `package`: `{ecosystem, name, version}` when the file provides evidence of that exact package version, otherwise `null`.
- `excerpt`, `explanation`: relevant exact text and what it establishes, including its connection to the selected finding and repository path.

These are recorded observations. The recorder validates structure and package consistency; it does not fetch URLs, verify the claimed remote digest, or prove source-to-bundle equivalence. Do not claim that recording certifies provenance. A mutable tag resolved today establishes today's inspected artifact, not what the scanner or a past workflow run used. Keep a missing historical artifact as an `unknown` when it could change the requested conclusion, or a `limitation` when the conclusion explicitly covers current inspected code independently. Do not fabricate a digest when only a rendered page is available; retrieve the raw file or record that access gap.

### Native evidence

When effective versions or package presence are needed, use the shared `dependency-resolution` skill with the project's existing package manager or native resolver API offline and read-only. Reuse its graph for selected findings in the same project scope and snapshot. An unrelated global Python environment is not repository evidence. No installs, lifecycle scripts, target-file writes, or handwritten lockfile reconstruction are allowed. Missing tooling need not block a conclusion supported independently by advisory or static evidence.

Follow the skill's resolver startup checks before any native command or API import, including version probes. Repository-selected executables, pnpm hooks, Yarn plugins, preloads, and build scripts are untrusted code, not native evidence. When required startup code cannot be avoided while preserving the requested effective graph, or its behavior cannot be established safely, record the blocker in `investigation` and `unknowns` when material; continue independently supported advisory or static analysis without running it. Do not accept its output, or a graph obtained by silently disabling its configuration, as proof of a resolved graph.

The `resolution` object records `argv`, repository-relative `cwd`, `exitCode`, `stdout`, `stderr`, `package` (`ecosystem` and `name`), `selectedVersions`, `explanation`, `inputFiles` (`path` and lowercase `sha256`), and `issues`. Preserve actual output, all relevant selected versions and chains, and unresolved issues. Explain how the native output establishes the selected package in the relevant application scope. Complete evidence requires a successful command, usable output, matching package identity, no resolver issues, and at least one relevant input digest; a complete graph may establish that the package is absent.

Hash the actual manifests, lockfiles, or installed metadata that establish the native selection, including ignored metadata when the resolver reads the installed tree. Use repository-relative input paths. Check bytes before and after resolution when they may change; rerun if they do. Inputs outside the repository cannot be bound to this assessment. The recorder checks input bytes and the repository snapshot before and after accepting results. Structural and digest checks do not independently prove command execution, graph completeness, or the model's interpretation.

Select findings explicitly; a selection is limited to 100 and retries reuse an identical pending assessment. Results must contain exactly one result per selection. Assessment prose and generated source excerpts are limited to 64 KiB per finding; the native resolver transcript is retained separately from that prose budget. Code citations must refer to files covered by the Git snapshot. Changing the repository or recorded resolver inputs requires a new assessment; previous claims and completed assessment history remain available.

### Task launches

Clients that open assessment or fix tasks first call `claim_dependency_task_launch` with the account (nullable for API-key use), execution host, report, kind, and assessment ID. Fixes also require the finding ID and its latest saved assessment. The client creates the task only after a response with `claimed: true`. The workbench stores the claim atomically across connections and returns an `attemptId` for settlement.

Save the outcome with `settle_dependency_task_launch`: `settled` requires a known `threadId`, `failed` means task creation definitely failed, and `outcome_unknown` means creation may have succeeded. A known thread remains linked even when its first turn is uncertain; save that uncertainty in `error`. Settlement must use the captured attempt ID, so an old callback cannot overwrite a replacement attempt or replace a known task link.

Pending and unknown attempts never expire automatically. After checking existing tasks, the user may explicitly choose to retry; pass the saved `retryAttemptId` to compare and replace that attempt. This also recovers a pending claim left by a closed client. Confirmed failures may be claimed again normally. Both new and recovered launches recheck repository evidence. `get_dependency_task_launches` returns all saved assessment summaries for the report and task links for the requested account and host, without discarding older history.

## Fixes

Fixing requires an explicit user request and a current `affects_application` assessment. Fetch it with `requireCurrent: true`; the repository and any recorded resolver inputs must still match. Preserve its declared, resolved, or artifact scope and recheck the attacker path and prerequisites, including for older results without structured attack-path fields. Recheck native resolution when the fix relies on effective versions or package presence. For external artifacts, recheck the repository's current reference and inspected artifact identity; repository freshness alone does not detect a moved remote tag. Prepare a tested patch in an isolated worktree or temporary copy and record relevant tests and breaking upgrade behavior. Assessment alone does not authorize edits, and the Fix action does not automatically apply, commit, push, merge, or deploy a patch.
