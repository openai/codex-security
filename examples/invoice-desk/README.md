# Invoice Desk security sample

This is a deliberately insecure, self-contained application for Codex Security
QA. All people, workspaces, invoices, and credentials are synthetic. Run it only
locally; do not deploy it or supply real data or credentials.

For a first scan, follow the [walkthrough](walkthrough.md). It copies only
`app/` into a new directory, then takes you through inspecting a finding,
patching it and verifying the fix. Keep this sample guide, the [sample threat
model](SECURITY.md), the [QA answer key](qa/README.md), and previous results
outside the copy. The app retains nine seeded weaknesses. The tenth scenario, ID-009,
checks that profile updates preserve the caller's role.

To evaluate a pull request or inspect the scheduled baseline, see
[CI and OpenAI scans](#ci-and-openai-scans).

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
They exercise nine seeded weaknesses, the repaired profile boundary, ordinary
application workflows, and secure controls. **Passing vulnerability scenario tests
mean the remaining intended weaknesses are present.** ID-009 instead requires the
profile boundary to hold. Passing tests do not mean the application is secure or
that a scanner found nine issues. The repository's Invoice Desk workflow runs this
suite in CI without installing dependencies.

## Scan without including the answer key

Copy only [`app/`](app/) to a fresh directory outside this checkout. Its
README describes the product and roles. The copy has no dependency on the
surrounding repository and the source scan can run with the server stopped.
The [walkthrough](walkthrough.md#1-prepare-a-standalone-copy) gives the commands.

After the scan, use the [scoring guide](qa/README.md#scanner-evaluation) and
[scenario manifest](qa/expected-findings.json) to match distinct root causes.
The fixed seed accounts, loopback HTTP, and in-memory storage are fixture
assumptions. Compare each finding with the intended boundary before counting it.

## CI and OpenAI scans

| Workflow | When it runs | What it tells you |
| --- | --- | --- |
| [Invoice Desk behavior tests](../../.github/workflows/invoice-desk.yml) | When a PR targeting `main` changes the sample, its helpers, or its workflows, including drafts and forks. | The sample still exhibits its intended behavior. The suite runs without inference credentials. |
| [Invoice Desk OpenAI scan](../../.github/workflows/invoice-desk-scan.yml) | A manual run for an exact PR head or `main`, or a weekly baseline on `main`. | The pinned, published CLI scanned the full app. Check the run's completion status before scoring it. Each scan consumes API usage. |

### Setup

Run the scan workflow from protected `main`. Configure a deployment branch rule
for the `codex-security-smoke-test` environment allowing only protected `main`.
Store the dedicated service account's `OPENAI_API_KEY` in that environment.
Manual and scheduled scans both wait for any required environment approval.

The account needs access to the workflow's model and US endpoint from the
runner's network. The workflow sets `openai_base_url` explicitly on protected
`main`. Its version and inference settings apply even when evaluating a PR that
changes the SDK. Use the package and runtime checks to test the proposed SDK.

### Triggers and source selection

Select **Actions → Invoice Desk OpenAI scan → Run workflow** on `main`. Leave
both inputs empty for a baseline. For an open PR targeting `main`, supply its
number in `pr_number` and its exact head SHA in `source_sha`. After pushing
another revision, dispatch a new run for the new head.

The workflow checks the PR base and head before queuing and immediately before
inference. It skips closed, retargeted, and superseded PRs. Duplicate requests
for the same PR and revision replace each other. Different revisions use separate
concurrency groups. Manual and scheduled baselines share a group at the same SHA.

The trusted workflow installs the published CLI outside the checkout and copies
committed `app/` files into a fresh directory. It rejects links, submodules,
and unsafe paths. It removes both checkouts before inference, keeping the guides
and answer key out of the scan. Only the scan step receives the API key.

### Results

Open the workflow run to check completion, the selected source SHA, finding and
severity counts, scope, elapsed time, and package-cache reuse. A completed scan
passes regardless of its finding count. An execution or required-reporting error
fails the run. Treat missing measurements from a stopped scan as unknown.

Download the artifact within seven days. It contains the readable report,
findings, manifest, CLI result JSON, SARIF, and `invoice-desk-metrics.json`.
For the pinned CLI's older output layout, the manifest's `scan.coverageRef`
identifies the additional coverage file. Metrics include the source and workflow
revisions, CLI version, settings, exit code, elapsed time, cache hits, and any
usage or cost estimate supplied by the CLI. The workflow makes SARIF available
for download and keeps credentials and transcripts out of the artifact.

### Cache persistence

The trusted preparation job caches public npm downloads for the pinned CLI
before it checks out PR source or receives inference credentials. The scan job
restores that cache read-only. Its key includes the cache schema, OS,
architecture, Node major, and CLI version. On a miss, npm downloads the packages.

Each scan starts with fresh analysis state. A package-cache hit explains time
saved during setup. To assess inference costs, use the token and cost metrics
reported by the CLI.

### Establishing the first baseline

Run a baseline twice at the same revision. Check the source SHA, cache reuse,
elapsed time, and reported token use. Then evaluate a PR and confirm that its
artifact names the head you selected. For each completed scan, compare the
distinct root causes with the [QA scoring guide](qa/README.md#scanner-evaluation).
Record matches, misses, uncertain cases, duplicates, and additional findings
before comparing recall across revisions.
