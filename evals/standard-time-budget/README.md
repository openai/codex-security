# Standard Scan time allowance comparison

Compare production Standard scans with and without `maxTimeMinutes`. Both
arms call `CodexSecurity.run`, including setup, delegation, canonical artifact
validation, report generation, and completion. The treatment uses the shared
[investigation-time-budget.md](../../plugins/codex-security/references/investigation-time-budget.md)
policy, not an eval-only prompt.

The SDK stamps one shared UTC deadline after setup, immediately before the
first scan turn. The allowance is advisory: there is no abort timer, automatic
continuation, or minimum runtime. Finalization is outside the allowance.

## Run

The checked-in [experiment](experiment.json) runs two pairs of Standard scans, including delegated work. Each pair compares a baseline with a five-minute advisory allowance. Both arms use `xhigh` reasoning and alternate which runs first. There is no enforced time or spend cap. Two pairs can expose differences worth investigating, but cannot establish a general effect on quality or cost.

Set `OPENAI_API_KEY` or `CODEX_API_KEY` for this model-backed experiment. It uses the bundled Codex SDK without loading saved logins. [Build the evaluation tools](../README.md#build-the-evaluation-tools) and [download the native package inputs](../../plugins/codex-security/native/README.md#package-inputs), then run from the repository root:

```sh
pnpm --dir sdk/typescript run build:plugin
node --experimental-strip-types evals/standard-time-budget/run.mts
```

Rebuild the bundle after a plugin change. For a harness-only check, run the [deterministic tests](#interpretation-and-checks) after the builds and omit the model command. To choose the model, pair count, or allowance, pass a configuration file:

```sh
node --experimental-strip-types evals/standard-time-budget/run.mts /path/to/experiment.json
```

The fields are `model`, `pairs`, and `budgetMinutes`; positive fractional
minutes are accepted. Production deadline validation runs before either arm
starts. Ctrl+C saves the interrupted attempt, stops future arms, and waits for
child processes before cleaning temporary state.

## Fixture and isolation

The synthetic application covers tenant authorization, SQL injection, file
traversal, reflected HTML, and server-side request forgery (SSRF). Each case
has a safe control. The SSRF pair checks whether a tenant can choose the
destination of a server-side status request. The billing route accepts only
the two approved URLs. Both routes return the status of the first response,
including redirects. The statement-download routes both confine file paths,
but only one derives the tenant directory from the session. The grant routes
both verify a signed tenant grant. One consumes the first submitted element
and the other uses the verified element. The model receives source and
deployment context. The evaluator holds the gold labels and locations.

Each arm runs in an opaque temporary directory outside the artifact tree; pair
and variant labels appear only in evaluator reports and archives. After the
client closes, its scan output is archived and its state is removed before the
next arm. If state removal fails, the failed attempt is recorded and the
comparison stops before another arm starts. Gold labels and prior-arm results
are not next to the model's working directory or included in prompts. This is layout separation, not a filesystem
security boundary: production API-key authentication and root-read permissions
remain unchanged. This eval does not test resumption or external publication.

## Focused investigator exercise

Materialize the application source in a fresh directory from the repository root:

```sh
node --experimental-strip-types --input-type=module <<'JS'
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFixture } from "./evals/secret-discovery/fixtures.mts";
import { createFixture } from "./evals/standard-time-budget/fixtures.mts";
const dir = await mkdtemp(join(tmpdir(), "portal-review-"));
await writeFixture(dir, createFixture());
console.log(dir);
JS
```

Start a fresh read-only Codex session in the printed directory. Supply the
[focused investigator brief](../../plugins/codex-security/references/focused-investigator.md)
from the revision under test. For earlier revisions that embed the brief in
[`core-scan.md`](../../plugins/codex-security/references/core-scan.md), supply its
**Shared Worker Instructions** and **Focused Investigator Prompt** blocks.
Give the investigator this single packet:

> Review `src/statements.py`, using `README.md` and `src/app.py` for context. Can a download request escape the resolved statement directory by path traversal?

Grade without the revision label. Both routes contain the path. Credit the
independent finding if it connects the request-selected tenant to another
tenant’s private statement and distinguishes the session-selected sibling.
For comparisons, keep the fixture, model, effort and packet fixed and record
incomplete attempts separately.

## Results

Open `evals/standard-time-budget/reports/run-*/summary.json` for the paired comparison. Each delta is treatment minus baseline for completed pairs. The summary lists excluded pairs separately. The run directory also contains:

- `experiment.json`: settings, evaluator/shared-helper, source, full-plugin,
  and built-SDK file hashes, plus SDK/Codex package versions and the selected
  Codex executable paths and SHA-256 hashes, including a `CODEX_CLI_PATH` override.
  npm launchers also record their native executable. Generated reports
  are excluded from evaluator hashes.
- `fixture.json`: synthetic source and held-out gold labels for review.
- `pair-<number>-<variant>/prompt.txt`: the actual first dispatched scan prompt.
- Per-arm `scan/`, `result.json`, and `report.json`: canonical scan artifacts,
  semantic output, grading, usage, elapsed time, and exact failure text.
- `runs.json` and `summary.json`: all attempts and the paired comparison.

Elapsed time is monotonic and includes SDK setup, investigation, finalization,
scan archival, cleanup, and grading, but not subsequent evaluator JSON writing.
A canonical scan that misses a bug still completed successfully. The runner
exits nonzero for execution failures, not low recall.

Automatic recall uses a finite set of accepted CWEs and source locations for
each case. A `root_control` or `sink` location needs authentic source evidence.
When an affected location omits its role or identifies an entrypoint
(`entrypoint` or `entrypoint/wrapper`), an
authentic `root_control`, `sink`, or `entrypoint` snippet must cover a gold line
within that location and the snippet's cited range. An unlabelled location on
a safe sibling is a comparison when verified `expected_control` evidence covers
it and no competing citation claims that line.
The statement routes send the file where they select the tenant.
For the grant case, the discarded verification result and the next line that
uses the unchecked tenant identify the vulnerable route. Both routes call the
same invoice query, so a citation to that query alone needs manual review.
A different CWE, another equivalent source location, or missing roles in both
the location and its evidence can leave a valid finding unmatched. Adjudicate
these reports before counting discovery misses. Duplicates do not increase recall.
Safe-control overlaps, unmatched findings, and citation errors are separate
signals; overlaps and unmatched findings require adjudication, not automatic
false-positive labels. Free-text location roles can flag benign context
citations. Preserve raw scores and record adjudication separately: source
matching is a heuristic, not independent exploit validation.

Each attempt's top-level `usage` includes delegated
workers, even when completion or grading fails. Missing usage stays unknown,
cached input is a subset of input tokens, and no dollar cost is inferred.

## Interpretation and checks

Use the `fixtures.mts` hash in `experiment.json` to identify the corpus revision.
If two runs have different revisions, compare their results on the shared case IDs.

Review findings
without variant labels and compare grounded recall, adjudicated false
positives, completion, tokens, and elapsed time together. More findings or a
longer run alone is not an improvement, and these arms do not have matched
spend. Expand the corpus if both arms saturate the fixture; use more pairs and
pinned public repository revisions before drawing quality/cost conclusions.

After the builds above, run deterministic checks without model calls:

```sh
node --experimental-strip-types --test evals/standard-time-budget/test_*.mts evals/secret-discovery/test_*.mts
```

The integration test uses the real SDK and canonical artifact helpers with
mocked model/workbench boundaries, verifying isolated state, completion, prompt
capture, and parent-plus-worker usage. CI reuses its host native build, builds
the plugin with `build_mcp_app.mjs --native host`, and links it at
`sdk/typescript/_bundled_plugin`; universal release artifacts are not required.

A second integration test sends synthetic findings for every positive fixture case
through the shipped draft tool and the real workbench. It checks that an empty
terminal draft preserves previously accepted findings, source evidence, and
validation details in the sealed scan. Each accepted finding must appear in
the generated report. A control leaves one candidate in deferred work and
verifies that discovery text earns no recall.
