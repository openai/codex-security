# Security scan benchmark corpus v1

This is an initial corpus for the broader benchmark proposal in issue #763.
Three small Python repositories exercise path traversal (CWE-22), SQL injection
(CWE-89), and unsafe deserialization (CWE-502). Each contains a vulnerable public
function and a safe control. They use only the standard library and contain no
credentials, external services, exploit payloads, or production data.

`expected.schema.json` versions the grading contract. Each case records its
runtime and scan mode, required/optional/absent findings, acceptable CWE IDs and
severity levels, source regions, required evidence regions, and an optional
duplicate allowance. Multiple expectations can express distinct root causes;
`allowedDuplicates` expresses the allowance for one root cause. Matching uses
CWE and source-region overlap, not the title, summary, or category wording.
Required evidence must overlap the recorded sink region. This checks cited
source evidence, not whether a natural-language attack path is correct.

## Generate scan inputs

Model scans are opt-in and consume the configured account's usage. Copy only a
case's `repo/` contents into a fresh directory outside this checkout and initialize
a Git repository there. Do not scan the corpus directory or its parent: that
would expose grading expectations to the model and include other cases. Keep
scan output outside that isolated Git repository. The fixture README documents
its input trust boundary without exposing the expected scoring contract.

Use the existing CLI, for example:

```bash
codex-security scan /path/to/isolated/repo --mode deep --workers 1 \
  --output-dir /path/to/results/path_traversal
```

Repeat with a fresh isolated repository for each case. Keep the model, project
configuration, and worker settings fixed when comparing runs; record these
externally alongside the report. This initial scorer does not launch models or
provide a new public CLI command. Replaying saved artifacts avoids charging
model usage in CI, though model scans themselves are not deterministic.

## Score saved artifacts

Install the existing Python test dependencies:

```bash
python -m pip install -e 'plugins/codex-security[test]'
```

Place canonical `findings.json` and `coverage.json` under
`RESULTS/<caseId>/` for **all three cases**, then run:

```bash
python evals/scan-benchmark/score.py /path/to/results > report.json
python evals/scan-benchmark/score.py /path/to/results \
  --baseline /path/to/previous-report.json > comparison.json
```

Artifacts are validated against the production schemas and must have matching
scan IDs. Exit status is 0 for passing cases, 1 for grading failures or baseline
regressions, and 2 for missing or invalid input. No artifacts are modified.

Reports include required-finding recall, unexpected findings, absent-control
violations, duplicate rate, coverage status, and aggregate recall/unexpected
counts. A one-to-one maximum matching prevents one broad finding from earning
credit for multiple root causes. Optional expectations do not reduce recall.
Absent-control matches fail regardless of their severity or cited evidence.
Extra matches exceeding a duplicate allowance count as unexpected. Partial or
wrong-mode coverage cannot pass even with full recall.

Optionally provide a canonical `candidates.json` document from the same scan
before validation. The report then measures how many matched required findings
survive into final artifacts. Without that document survival is `null`; with no
matched candidates its rate is `null`, not an invented success. The scorer does
not interpret model-specific validation prose or claim reachability proof.

Baseline comparisons reject different corpus versions, source/expectation
contents, or case sets. They flag decreased recall, increased unexpected counts
or duplicate rates, and newly incomplete coverage. Only compare reports produced
with identical model/settings: this tool cannot infer them from saved artifacts.
This small corpus is a regression signal, not a comprehensive security-quality
measurement. More categories and an isolated live scan harness remain follow-up
work.

## Deterministic checks

```bash
python -m unittest discover -s evals/scan-benchmark -p 'test_*.py' -v
python -m ruff check --config plugins/codex-security/pyproject.toml evals/scan-benchmark
python -m ruff format --check --config plugins/codex-security/pyproject.toml evals/scan-benchmark
```

CI runs the scorer tests without model calls. Tests replay synthetic canonical
artifacts and cover misses, false positives, duplicate allowances, ambiguous
matching, severity/evidence mismatch, incomplete scans, validation survival,
schema errors, scan binding, and baseline regressions.
