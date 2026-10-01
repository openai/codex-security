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
tests for pull requests targeting `main`, including drafts and forks, regardless
of which files changed. A separate job loaded from protected `main` dispatches
an [OpenAI source scan](../../.github/workflows/invoice-desk-scan.yml) when a PR is
opened, reopened, updated, or retargeted to `main`. That dispatcher handles only
the PR number and head SHA: it has no checkout, application commands, or inference
secret. PR changes cannot disable the dispatcher, and failed behavior tests do
not suppress scanning. Title and description edits do not request another scan.

Both workflows must reach `main` before automatic scanning is active. The
[dispatcher](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request_target)
loads trusted workflow code from the default branch and invokes the scan with
`workflow_dispatch` on protected `main`. The scan checks the PR's current base and
exact head through GitHub's API before queuing and again after environment
approval, immediately before inference. Closed PRs, PRs targeting other branches,
and superseded commits are skipped. New scans cancel older scans for the same PR.

The original PR test job receives no inference credentials. The scan waits for
approval of the `invoice-desk-inference` environment; automatic triggering does
not remove that requirement. GitHub may also require approval before running a
first-time contributor's behavior tests.

Configure that environment with required reviewers and a deployment branch rule
allowing only protected `main`. Store a dedicated service-account key as its
`OPENAI_API_KEY` environment secret, with access to `gpt-5.6-sol`. Do not use a
repository or organization Actions secret for this workflow. The credential must
also permit API access from the selected runner's network; creating a service
account does not establish that permission. Missing credentials fail the scan
job with a setup error. **Invoice Desk OpenAI scan → Run workflow** on `main`
remains available for a manual baseline scan with both inputs empty. To scan a
particular open PR manually, provide its number and exact current head SHA.

This adapts the existing [GitHub Actions example](../github-actions/README.md) to
OpenAI inference. It pins CLI 0.1.30 and uses standard mode with high effort on
Node.js 24 and Python 3.12. It scans the entire standalone application on each
run, not a PR diff, so unchanged seeded cases remain in scope. Inference consumes
API usage.

The workflow installs the CLI outside the checkout and copies only committed
`app/` blobs into a fresh directory. PR-controlled archive attributes cannot omit
or substitute files. Unsafe paths, links, and submodules fail extraction instead
of silently reducing coverage. It does not install dependencies from the PR, execute the
application or its tests in the inference job, or download PR-produced artifacts.
The sample documentation, threat model, tests, answer key, and previous reports
are not scan input. The API key is available only in the scan step; no GitHub
token is passed to the scanner. Review the source commit before approving an
inference run.

Results appear under **Actions → Invoice Desk OpenAI scan**. Because the scan
runs as a separate workflow on `main`, its result is not a PR status check or a
merge gate. The summary identifies the PR number and source commit so its
results can be matched to the PR revision. A passing behavior check alone does
not mean a source scan completed.

The Actions summary shows completion, total findings, severity counts, coverage,
scan elapsed time, and whether a package cache from an earlier run was restored.
A seven-day artifact contains the Markdown report, findings and coverage JSON,
scan manifest, CLI result JSON, an exported SARIF file, and
`invoice-desk-metrics.json`. Metrics record source and workflow revisions, CLI and
model settings, exit code, elapsed time, package cache hits, and token usage and
cost estimates when the CLI reports them. Missing usage or recall stays unknown;
failed scans do not count as zero findings. Authentication state and agent
transcripts are not uploaded. These reports describe only this
synthetic application. SARIF is downloadable; this workflow does not populate
repository Code Scanning alerts or post pull request comments.

Expected vulnerabilities do not fail the job. Scan errors and incomplete scans
do fail it, with available reports retained. There is no exact-count or recall
gate yet: compare returned root causes with the QA manifest, and review extras
and duplicates separately. A successful scan job means the scan completed, not
that the sample is secure or that all ten scenarios were detected.

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
