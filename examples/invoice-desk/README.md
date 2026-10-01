# Invoice Desk security sample

This is a deliberately insecure, self-contained application for Codex Security
QA. All people, workspaces, invoices, and credentials are synthetic. Run it only
locally; do not deploy it or supply real data or credentials.

The application has **ten seeded finding scenarios**. It looks and behaves like
an ordinary invoice application, with no vulnerability labels, answer keys,
sample banners, or test-mode branches in its application code. This README and
the nested [QA guide](qa/README.md) explain the sample and its expected findings.
The [threat model](SECURITY.md) describes the app's assets, trust boundaries, and
intended security properties. It also stays outside the standalone scanner input.

## Start

From the repository root:

```bash
node examples/invoice-desk/app/server.mjs
```

Open `http://127.0.0.1:4310`. There is no install, build, Docker, database service,
external API, or model credential requirement. Node.js 22.13 or later is enough.
The app uses in-memory storage, binds to loopback, and makes no outbound network
requests. `PORT=4311` selects another local port. Stop and restart to reset it.

| Account                    | Password           | Workspace      | Role          |
| -------------------------- | ------------------ | -------------- | ------------- |
| `alex@north.example.test`  | `river-orchard-24` | North Studio   | Member        |
| `jules@north.example.test` | `meadow-paper-56`  | North Studio   | Administrator |
| `sam@cedar.example.test`   | `cedar-window-81`  | Cedar Workshop | Administrator |

These fixed login accounts are setup data. The connector secrets are generated
anew on each start, and are valid only for the same process's Ledger adapter.
They are never copied from environment variables, credentials, or the host.

## Verify

```bash
node --test examples/invoice-desk/qa/app.test.mjs
```

The tests start their own loopback servers on available ports and clean them up.
They exercise all ten seeded behaviors, ordinary application workflows, and
secure controls. **Passing scenario tests mean the intended weaknesses remain
present.** They do not mean the application is secure or that a scanner found
ten issues. The repository's Invoice Desk workflow runs this suite in CI without
installing dependencies.

## CI and OpenAI scans

The [Invoice Desk workflow](../../.github/workflows/invoice-desk.yml) runs behavior
tests on PRs targeting `main`, including drafts and forks, regardless of which
files changed. A separate [OpenAI scan workflow](../../.github/workflows/invoice-desk-scan.yml)
scans the entire application at the PR's exact head, subject to protected
environment approval. Failed behavior tests do not suppress a scan.

### Setup

Both workflows must be on `main` before automatic scans can run. Configure the
`invoice-desk-inference` environment with required reviewers and a deployment
branch rule allowing only protected `main`. Store a dedicated service-account
key in its `OPENAI_API_KEY` environment secret, with access to `gpt-5.6-sol` and
permission to use the API from the selected runner's network. Creating a service
account alone does not grant that network access. Do not use a repository or
organization Actions secret for this workflow. A missing key fails the scan
with a setup error.

Review the source commit before approving inference. Behavior tests receive no
inference credentials; GitHub may separately require approval to run them for a
first-time contributor.

For a manual baseline, select **Actions → Invoice Desk OpenAI scan → Run
workflow** on `main` and leave both inputs empty. To scan an open PR, provide its
number and exact current head SHA.

The scan adapts the existing [GitHub Actions example](../github-actions/README.md)
to OpenAI inference. It uses CLI 0.1.30, standard mode, high effort, Node.js 24,
and Python 3.12. Each run scans the full application so unchanged cases remain
in scope. Inference consumes API usage.

### Triggers and source selection

A [default-branch dispatcher](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request_target)
queues scans when a PR is opened, reopened, updated, or retargeted to `main`.
It handles only the PR number and head SHA, with no checkout or inference secret,
and starts the scan on protected `main`. PR edits cannot disable that dispatcher.
Title and description edits do not request another scan.

GitHub can suppress `pull_request_target` for PRs created using `GITHUB_TOKEN`
and for certain branch names. A `workflow_run` fallback handles completed
behavior workflows, including failed tests. It looks up the current PR and skips
PR/head pairs already dispatched from the same `main` workflow revision. It
queues eligible revisions through the same dispatch path, whose run title includes
the PR number and full source SHA. Later fallback events can find those runs and
avoid rescanning an unchanged revision.

If GitHub suppresses the target event and no behavior workflow completes,
automatic scanning cannot start. Use the manual PR dispatch above with the current
head SHA; the same protected workflow and approval checks apply.

The scan checks the PR's base and exact head through GitHub's API before queuing
and again after environment approval, immediately before inference. Closed,
retargeted, and superseded PR revisions are skipped. Repeated scans of the same PR
revision cancel older runs of that revision. A scan that has already started
inference may finish after the PR head changes; its reports identify the source SHA.

The workflow installs the CLI outside the checkout and copies committed `app/`
blobs into a fresh directory. Archive attributes cannot omit or substitute files;
unsafe paths, links, and submodules fail extraction. The inference job does not
install PR dependencies, run the application or its tests, or download artifacts
produced by the PR.

After rechecking eligibility, it removes both full checkouts so the scanner
cannot read their sample guide, threat model, tests, or answer key. Previous
reports are also outside the scan input. The API key is available only in the
scan step, and no GitHub token is passed to the scanner.

### Results

Results appear under **Actions → Invoice Desk OpenAI scan**. This separate
workflow does not create a PR status check or merge gate. Its summary identifies
the PR and source commit, completion, finding and severity counts, coverage,
elapsed time, and package-cache reuse. Passing behavior tests alone does not
mean a source scan completed.

Reports are retained for seven days. The artifact includes Markdown, findings
and coverage JSON, the scan manifest, CLI result JSON, SARIF, and
`invoice-desk-metrics.json`. Metrics record source and workflow revisions,
scanner settings, exit code, elapsed time, cache hits, and any token usage or
cost estimates reported by the CLI. Incomplete scans retain the measurements
that were emitted; missing measurements and recall remain unknown. Failed scans
do not count as zero findings. Authentication state and agent transcripts are
not uploaded. SARIF is downloadable; the workflow does not create Code Scanning
alerts or post PR comments.

Findings are report-only. Scan errors and incomplete scans fail the job, with
available reports retained. A successful job means the scan completed; it does
not establish that the application is secure or that all ten scenarios were
found. Compare distinct root causes with the QA manifest and review extra
findings and duplicates separately. There is no exact-count or recall gate yet.

### Cache persistence

The trusted preparation job restores and saves the npm content-addressed download
cache for the pinned CLI and its bundled runtime dependencies. Its key includes a
cache schema version, OS, architecture, Node major, and CLI version. The scan job
restores that same cache and installs with `--prefer-offline`; a cache miss still
allows a normal registry install. Cache population happens before PR source is
checked out or an inference credential is available. The scan job has read-only
cache access and never saves files produced during inference.

Only `invoice-desk-npm-cache/_cacache` is cached. The private
`CODEX_SECURITY_STATE_DIR`, `codex-home`, authentication files, session logs,
workbench database, threat models, and previous findings stay out of the cache.
Each scan starts with fresh analysis state so previous answers do not influence
fixture evaluation. API prompt-cache token usage is reported separately by the
CLI; saving the package cache does not preserve model responses. GitHub can
[evict caches](https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows),
so cache availability is a performance signal, not a pass/fail condition.

### Establishing the first baseline

After merging this setup, run a main baseline, approve the protected environment,
and inspect the completed reports. Run the same revision again to verify a cache
hit and compare elapsed time and token use. Then use an ordinary PR to verify the
automatic dispatcher and the reported source SHA.

Review actual findings against the ten root causes in the QA manifest. Record
matched cases, misses, uncertain cases, duplicates, and additional findings;
confirm secret exposure is matched by the crossed credential boundary. Start
with report-only recall and cost measurements. Consider a regression gate only
after repeated completed scans establish normal variation. The initial CI gate
is operational completion, not zero vulnerabilities or exactly ten reports.

## Scan without including the answer key

The standalone application is `app/`. The harness, scenario labels, and findings
manifest are siblings outside that directory:

```text
invoice-desk/
  README.md                   Sample instructions
  SECURITY.md                 Threat model and security assumptions
  app/                        Standalone scanner input
    README.md                 Ordinary product and runtime documentation
    server.mjs
    ...
  qa/
    README.md                 Scenario and scoring guide
    expected-findings.json    Expected root causes and source symbols
    app.test.mjs              Behavior checks and secure controls
```

For an independent discovery run, copy only `app/` into a fresh directory outside
this checkout and select that directory as the scan target. Keep this README,
SECURITY.md, the QA directory, and prior reports outside the scanner's input. This
also avoids inheriting the parent repository's instructions or exposing the answer
key by walking to a neighboring directory inside the checkout.

The app has no dependency on its surrounding example directory, and runs from
the copied directory. Its own README describes the product and intended roles,
without identifying the seeded defects. Source scanning does not require keeping
a separate server running; the HTTP suite independently verifies runtime behavior.

Review returned findings against the [manifest](qa/expected-findings.json).
Count distinct matched root causes, missed cases, unexpected findings, and
duplicates. Ten scenarios are a ground-truth design target, not a guaranteed raw
finding count from every model run. The fixed seed accounts, loopback HTTP, and
in-memory data are declared harness assumptions, not additional target findings.
