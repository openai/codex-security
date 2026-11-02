# Dependency reachability eval

Given a public advisory and a caller, can the production `attack-path-analysis`
skill determine whether the caller can trigger that vulnerability? The 23
cases use immutable upstream revisions. They exercise a reachable native
decoder, unchanged package versions with different behavior, an unknown worker,
and a larger background task workflow. Each case runs in a fresh source tree.
[Case definitions](cases.mts)

In the mail upload cases, the **gateway** is the service that accepts the upload
and puts a job on a queue. The **worker** is the separate process that picks up
the job and parses the mail. The worker can end up reading different bytes from
the ones the gateway checked. A **fixture** is a small piece of code, configuration,
or sample data that recreates one of these conditions for the test.

## Run locally

Use Node.js 22.22+ and Git. From the Codex Security repository root, install
the repository’s pinned eval dependencies and build the SDK once.

```sh
pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir plugins/codex-security/mcp-app install --frozen-lockfile
pnpm --dir evals/triage-finding install --frozen-lockfile
pnpm --dir sdk/typescript run build:evals
```

The runner reads local Git objects from `<repo-root>/<owner>/<repository>`.
Only the repositories for the selected cases are required. For example, to
run the MailParser backport case, prepare its two repositories once.

```sh
repos="$(mktemp -d)"
mkdir -p "$repos/nodemailer"
git clone --no-checkout https://github.com/nodemailer/mailparser.git "$repos/nodemailer/mailparser"
git clone --no-checkout https://github.com/nodemailer/nodemailer.git "$repos/nodemailer/nodemailer"
node --experimental-strip-types evals/dependency-reachability/run.mts --repos "$repos" --case address-backport
```

To run the whole suite, add the Pillow, Backstage and Alpine repositories and omit the selector.

```sh
mkdir -p "$repos/python-pillow" "$repos/backstage" "$repos/alpinelinux"
git clone --no-checkout https://github.com/python-pillow/Pillow.git "$repos/python-pillow/Pillow"
git clone --no-checkout https://github.com/python-pillow/pillow-wheels.git "$repos/python-pillow/pillow-wheels"
git clone --branch v1.14.1 --single-branch --no-checkout https://github.com/backstage/backstage.git "$repos/backstage/backstage"
git clone --no-checkout https://github.com/alpinelinux/aports.git "$repos/alpinelinux/aports"
node --experimental-strip-types evals/dependency-reachability/run.mts --repos "$repos"
```

Use `--suite mailparser`, `--suite pillow`, or `--suite backstage` to run a
repository cohort. Use `--suite challenge` for the ten downstream-patch,
sanitizer, queue and archive cases. That cohort reads only MailParser,
Nodemailer, Pillow and aports. Use `--model MODEL` for a specific model. The default uses the pinned
Codex SDK and CLI, xhigh reasoning, and the checkout’s production skill. Each
case gets a new thread, a read-only snapshot, and offline source tools. The
parent clone, answer key, and other cases stay outside the model’s readable
directories. Model runs use the caller’s Codex account or API key and consume
model usage. [Shared eval runtime](../secret-discovery/README.md#run)

## Score and compare

The report at `reports/run-*/report.json` records each answer and separate
checks for the verdict, resolved dependency version, and source evidence.
Every citation must quote the complete lines at its claimed location, and
together the citations must cover the case’s deciding steps. Review the free-text
reasoning alongside the score. The runner records staging and analysis times
separately, a digest of the pinned tree and staged inputs, SDK token usage when available, and completion status for partial
runs. A run exits successfully when every selected case passes.

To compare a candidate module, append `--` and a trusted local adapter command.

```sh
node --experimental-strip-types evals/dependency-reachability/run.mts --repos "$repos" --case address-backport -- /absolute/path/to/adapter
```

The adapter runs in the case snapshot under the caller’s normal OS permissions.
The grader keeps the original copy of the snapshot for verifying citations.
It reads the case and output instructions from stdin and writes one JSON object
to stdout. Use `exploitable`, `ruled_out`, or `unknown` for `verdict`, a
bare version string for `dependency_version`, and short, repository-relative source citations
with 1-based inclusive line numbers. On MailParser the requested version is the
one in the supplied image. The external adapter can write diagnostics to stderr.
[Answer schema and grader](grade.mts)

Run the deterministic case, staging, model-harness, and grading checks locally
with the same command as CI. These checks require neither upstream clones nor a model.

```sh
node --experimental-strip-types --test evals/dependency-reachability/test_*.mts
python3 -B -m unittest discover -s evals/dependency-reachability/fixtures/zip -p test_catalog.py
```

## Backstage

The `task-parameter` case runs on all 8,794 tracked files of Backstage v1.14.1.
It asks whether a user who chooses the `name` for the starter app’s Node.js
template can trigger CVE-2023-37466 through normal Scaffolder task submission.
The resolved `vm2` version is 3.9.19. Exploiting this CVE requires executing
attacker-controlled JavaScript inside the sandbox. [Pinned release](https://github.com/backstage/backstage/tree/99d7a6f42d71e86578c89c0669a3d962088ed8ae)
· [vm2 advisory](https://github.com/advisories/GHSA-cchq-frgv-rjh5)

The expected verdict is `ruled_out` for this requester. The task worker
renders the registered template’s steps using the supplied parameters. The
`fetch:template` action then renders files from a fixed skeleton with those
values. On both passes the name is data. The worker writes the generated
JavaScript file and publishes it without executing it. As a benign check, a name of
`${{ 6 * 7 }}` survives literally in the generated file. The same expression
in template source evaluates to `42`. Backstage’s advisory identifies write
access to the registered template as a different attacker capability.
[Starter template](https://github.com/backstage/backstage/blob/99d7a6f42d71e86578c89c0669a3d962088ed8ae/packages/create-app/templates/default-app/examples/template/template.yaml)
· [Backstage advisory](https://github.com/backstage/backstage/security/advisories/GHSA-wg6p-jmpc-xjmr)

## MailParser

The first nine examples below ask whether an unauthenticated sender can trigger a dependency
CVE through `POST /inbox`. The upstream project has 54 tracked files at both
pinned revisions. A small example service adds an HTTP route, an optional worker,
and one deployment configuration per case. The caller and deployment are
synthetic. MailParser, its dependency versions, and the Nodemailer fix are real.
Cases for the same CVE receive the same question.

| Case | Expected verdict | Deciding evidence |
| --- | --- | --- |
| `direct-links` | Exploitable | The request body reaches `linkify-it.match()` with fuzzy matching enabled. |
| `disabled-links` | Ruled out | The deployed parser sets `skipTextLinks`, bypassing the vulnerable call. |
| `queued-links` | Exploitable | The HTTP service forwards the original bytes to a child process that parses the email. |
| `unmounted-route` | Ruled out | The parser and handler exist, but the route table gives this request a 404. |
| `external-worker` | Unknown | The service forwards the bytes to a separate worker. Its code and configuration are missing. |
| `address-groups` | Exploitable | Attacker-controlled address headers reach Nodemailer 7.0.10’s unbounded group recursion. |
| `address-backport` | Ruled out | The installed parser contains the upstream recursion limit while its manifest still says 7.0.10. |
| `stripped-headers` | Ruled out | The service discards the entire submitted header block and supplies constant address headers before parsing. |
| `native-charset` | Ruled out | The image inventory specifies an affected system glibc. The native binding receives the sender’s charset as the source and UTF-8 as the destination. The CVE requires conversion **to** ISO-2022-CN-EXT. |

The linkification and charset cases use MailParser 3.9.2. The address cases use
3.9.0, which pins Nodemailer 7.0.10. In the backport case only, the staged
dependency contains the address parser implementation from 7.0.11. [MailParser 3.9.2](https://github.com/nodemailer/mailparser/tree/bb325f156d35c28d78a18c7f61c0f2a54a2b7854)
· [MailParser 3.9.0](https://github.com/nodemailer/mailparser/tree/3e1e0291d7757501d334d19fe6553a78b45cc1eb)
· [Nodemailer fix](https://github.com/nodemailer/nodemailer/compare/v7.0.10...v7.0.11)

The prompts include the advisory’s affected versions and trigger so the analysis
can run offline against each source snapshot. [linkify-it advisory](https://github.com/advisories/GHSA-22p9-wv53-3rq4)
· [Nodemailer advisory](https://github.com/advisories/GHSA-rcmh-qjqh-p98v)
· [glibc advisory](https://github.com/bminor/glibc/blob/master/advisories/GLIBC-SA-2024-0004)

## Pillow

A responder has a libwebp advisory and wants to know whether a particular Pillow
operation reaches the affected decoder. These three cases exercise CVE-2023-4863
on the official CPython 3.12 Linux x86-64 manylinux_2_28 wheels.

| Pillow | Caller operation | Expected | Deciding evidence |
| --- | --- | --- | --- |
| 10.0.0 | Open and load attacker-supplied image bytes | `exploitable` | A crafted lossless WebP reaches libwebp 1.3.1 through `WebPAnimDecoderGetNext`. |
| 10.0.1 | Same caller and bytes | `ruled_out` | The decoder is still reachable, but this wheel ships the fix in libwebp 1.3.2. |
| 10.0.0 | Save attacker-supplied raw RGB pixels as a lossless WebP | `ruled_out` | The same affected library handles the pixels through `WebPEncode`. The caller never passes encoded input to the WebP decoder. |

The Pillow release notes identify the fixed wheel. The wheel build recipes pin
libwebp, and the Pillow source shows which native function the caller reaches.
The cases assume these specific wheels. Source builds can link a different copy
of libwebp. [Release notes](https://pillow.readthedocs.io/en/stable/releasenotes/10.0.1.html)
· [Maintainer’s decoder trace](https://github.com/python-pillow/Pillow/issues/7626#issuecomment-1862498577)
· [10.0.0 wheel recipe](https://github.com/python-pillow/pillow-wheels/blob/b2eed6e689596fefacf5bcbec10193a23ba5df12/config.sh#L25)
· [10.0.1 wheel recipe](https://github.com/python-pillow/pillow-wheels/blob/deb384b86e39beec75bd0b52027faf784fb17625/config.sh#L25)

## Downstream patches, sanitizers and separate services

These cases use matched deployments. Both versions of a pair get the same question.
The application, deployment and incident captures are synthetic. The package
recipes, dependency source and advisories come from the pinned upstream projects.

| Case | Expected | What decides the verdict |
| --- | --- | --- |
| `thumbnail-blue` | Ruled out | The serving worker still maps the inode from Alpine’s patched libwebp 1.3.1-r1 after the on-disk package rolled back to r0. |
| `thumbnail-green` | Exploitable | The proxy selects a worker started with r0. It decodes the submitted bytes with the original library. |
| `thumbnail-receipt-window` | Unknown | Both workers report 1.3.1. The selected worker maps a deleted file, and the retained receipts identify only the new inode. Either package revision could own the old mapping. |
| `archive-east` | Exploitable | The quoted-printable encoder can produce the configured MIME boundary inside an attachment. The parser then sees caller-controlled part headers. |
| `archive-west` | Ruled out | The configured boundary contains a sequence the encoder cannot emit. The caller can supply attachment data only. |
| `archive-worker-pinned-original` | Exploitable | The gateway writes an upload and then overwrites it with a new envelope. Its queue message pins the first object version, so the worker parses the original. |
| `archive-worker-pinned-normalized` | Ruled out | With S3 versioning suspended, both writes to the fresh key refer to its null version. The worker receives a plain-text body with fixed headers. |
| `archive-worker-mime-parts` | Exploitable | The worker receives the normalized object, but the gateway preserves its multipart content type. MailParser processes address headers on child parts, even though the final top-level recipient is trusted. |
| `zip-import-alpha` | Exploitable | The gateway validates ZIP entries by filename. Duplicate names resolve to the last entry, while the worker reads each individual member and can pass an unchecked address header to the parser. |
| `zip-import-beta` | Ruled out | Both services read by member identity. If any member’s headers fail the gateway’s allowlist, the archive is rejected before enqueueing. |

Alpine added the Huffman-table allocation fix without changing the upstream
1.3.1 version. A benign loader check reproduces the distinction between workers:
atomically replace the shared object after loading it, then compare the original
process’s mapped inode with a fresh process. Both libraries report 1.3.1 and can
decode an ordinary lossless image. [Alpine backport](https://github.com/alpinelinux/aports/commit/29a91ff19585ca3eebd4bf53d275f600a093a73d) · [Pillow package recipe](https://github.com/alpinelinux/aports/blob/29a91ff19585ca3eebd4bf53d275f600a093a73d/community/py3-pillow/APKBUILD) · [Case definitions](rollout-cases.mts)

The mail labels can be checked with ordinary recipient markers. Trace which
addresses reach Nodemailer in the worker, including addresses on child MIME parts.
Reading only the latest object or the worker’s final top-level recipient misses
the relevant distinction. [S3 suspended-version semantics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/AddingObjectstoVersionSuspendedBuckets.html) · [Service cases](service-cases.mts) · [Sanitizer cases](sanitizer-cases.mts)

The ZIP cases scope the verdict to whether a caller-controlled address header
can reach the installed parser. Their deterministic test uses two ordinary
recipients and records which bytes the worker passes to its mail index.
[Python ZIP member lookup](https://docs.python.org/3/library/zipfile.html#zipfile.ZipFile.open) · [ZIP cases](zip-cases.mts)
