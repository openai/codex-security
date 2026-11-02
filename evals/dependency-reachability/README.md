# Dependency reachability eval

Can the production `attack-path-analysis` skill determine whether a caller can
trigger a dependency advisory? Use these 23 cases to compare accuracy, analysis
time, and token use against a candidate implementation.

Each case gives the caller's entry point and permissions, the advisory, and a
snapshot of the application. Where processing spans services, the analysis has
to discover that from the source and deployment configuration. Paired cases get
the same question. The case IDs, expected verdicts, and grading criteria stay
outside the model's readable directories.

| Cases | What varies |
| --- | --- |
| [MailParser](cases.mts) (9) | Routing, parser options, a backported fix, and a receiver whose implementation is missing. |
| [Pillow wheels](cases.mts) (3) | Decoding or encoding with the same library, and decoding after the wheel updates libwebp. |
| [Backstage](cases.mts) (1) | Whether a task parameter becomes executable JavaScript in the full v1.14.1 checkout (8,794 files). |
| [Pillow deployments](rollout-cases.mts) (3) | Which libwebp build the serving process loaded and whether retained package records identify it. |
| [Mail attachments](sanitizer-cases.mts) (2) | Whether an attachment can change the headers seen by the parser. |
| [Archived mail](service-cases.mts) (3) | Which stored message the subscribed consumer reads and which headers survive. |
| [ZIP imports](zip-cases.mts) (2) | Whether validation and processing select the same ZIP member when names repeat. The verdict covers the advisory's input prerequisite. |

The package sources and fixes are pinned public revisions. The application code
and deployment records added to those checkouts are synthetic.
[Nodemailer fix](https://github.com/nodemailer/nodemailer/compare/v7.0.10...v7.0.11) · [Alpine backport](https://github.com/alpinelinux/aports/commit/29a91ff19585ca3eebd4bf53d275f600a093a73d) · [Backstage advisory](https://github.com/backstage/backstage/security/advisories/GHSA-wg6p-jmpc-xjmr)

## Run locally

Use Node.js 22.22+ and Git. From the repository root, install the dependencies
and build the SDK.

```sh
pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir plugins/codex-security/mcp-app install --frozen-lockfile
pnpm --dir evals/triage-finding install --frozen-lockfile
pnpm --dir sdk/typescript run build:evals
```

The runner reads local Git objects from `<repo-root>/<owner>/<repository>`.
For a quick run, the MailParser backport case needs only two clones.

```sh
repos="$(mktemp -d)"
mkdir -p "$repos/nodemailer"
git clone --no-checkout https://github.com/nodemailer/mailparser.git "$repos/nodemailer/mailparser"
git clone --no-checkout https://github.com/nodemailer/nodemailer.git "$repos/nodemailer/nodemailer"
node --experimental-strip-types evals/dependency-reachability/run.mts --repos "$repos" --case address-backport
```

To run all cases, add the remaining repositories and omit the case selector.

```sh
mkdir -p "$repos/python-pillow" "$repos/backstage" "$repos/alpinelinux"
git clone --no-checkout https://github.com/python-pillow/Pillow.git "$repos/python-pillow/Pillow"
git clone --no-checkout https://github.com/python-pillow/pillow-wheels.git "$repos/python-pillow/pillow-wheels"
git clone --branch v1.14.1 --single-branch --no-checkout https://github.com/backstage/backstage.git "$repos/backstage/backstage"
git clone --no-checkout https://github.com/alpinelinux/aports.git "$repos/alpinelinux/aports"
node --experimental-strip-types evals/dependency-reachability/run.mts --repos "$repos"
```

Use `--suite mailparser`, `--suite pillow`, or `--suite backstage` to select
one project. `--suite challenge` selects the ten downstream patch, attachment,
archived mail, and ZIP cases. Each model run uses a fresh read-only snapshot,
the pinned Codex SDK and CLI, and xhigh reasoning. Omit `--model` to use the
default. Model runs consume usage on the caller's Codex account or API key.
[Shared eval runtime](../secret-discovery/README.md#run)

## Compare a candidate

Append a trusted local command after `--`. It runs in a copy of the snapshot
with the caller's OS permissions, reads the question and output instructions
from stdin, and writes one JSON answer to stdout. Diagnostics can go to stderr.

```sh
node --experimental-strip-types evals/dependency-reachability/run.mts --repos "$repos" --case address-backport -- /absolute/path/to/adapter
```

A full pass requires the expected verdict (`exploitable`, `ruled_out`, or
`unknown`), the bare dependency version, a reason, and source citations for
each deciding step. The grader verifies repository-relative paths, inclusive
line ranges, and exact quotes against the original snapshot. [Grader](grade.mts)

Compare runs in `reports/run-*/report.json`. Each report separates verdict,
version, and citation accuracy, records snapshot and prompt hashes, and times
analysis separately from staging. SDK runs also record token usage when available.
The runner exits successfully when all selected cases pass.

CI runs the deterministic checks without model calls or upstream clones.

```sh
node --experimental-strip-types --test evals/dependency-reachability/test_*.mts
python3 -B -m unittest discover -s evals/dependency-reachability/fixtures/zip -p test_catalog.py
```
