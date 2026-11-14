# Security workflow sample

This sample supplies **three benchmark examples** for an order API security
workflow: cross-customer order access, reporting SQL injection, and coverage
across a synthetic deployed environment. All identities, orders, and deployment
names are invented. The local API binds to `127.0.0.1`, stores data in memory,
and needs only Python 3.9 or later.

| Directory | Purpose |
| --- | --- |
| `app/` | Standalone source target with the two seeded flaws. |
| `qa/` | Expected findings and local behavior checks. Do not include in a source scan. |
| `deployment/` | Mock topology, two additional source roots, and a Lambda deployment template. |

## Run and verify the fixture

From this directory:

```bash
python3 -m unittest discover -s qa -p 'test_*.py' -v
python3 -m app.server
```

The server prints its loopback address. `app/README.md` lists the API routes and
synthetic bearer tokens. Stop and restart the process to reset its database.
The tests intentionally confirm vulnerable behavior; they are not a scanner
recall score or a secure post-fix test suite.

## Scan the two code findings together

Copy only `app/` into a fresh directory. Keep `qa/`, `deployment/`, and this
guide outside the scanner's source tree. For example, from this directory:

```bash
sample_run="$(mktemp -d "${TMPDIR:-/tmp}/security-workflow.XXXXXX")"
cp -R app "$sample_run/app"
cd "$sample_run"
codex-security scan app --mode standard --effort high --format json \
  --output-dir "$sample_run/scan"
```

This command uses the locally configured Codex Security CLI and model access.
Check the saved scan status and scope before comparing findings with
`qa/expected-findings.json`. A completed scan can report zero, one, two, or
additional findings; the fixture does not guarantee discovery.

## Exercise environment coverage

`deployment/inventory.json` models three source roots and their network entry
points. It is useful for checking expected reachability and negative controls
without an AWS account. An actual AWS Continuum exercise needs three connected
code sources, corresponding workloads in an authorized test account, a
collector, and saved scan evidence. The local inventory alone does not
establish what Continuum would find in a live environment. Follow the
[SW-003 AWS runbook](deployment/aws/README.md) to deploy the Lambda variant
and retain observed evidence.

Use [the QA guide](qa/README.md) for the expected scanner results and
disposition rules. No automatic merge runs as part of this sample; that step
requires a separately configured repository policy.
