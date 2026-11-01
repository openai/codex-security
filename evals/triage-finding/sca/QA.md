# SCA evaluation QA

Validation performed on September 30, 2026:

- All 26 deterministic Node tests passed.
- The pinned Promptfoo 0.123.1 configuration validated successfully.
- A live smoke ran three synthetic cases (one advisory family, all three labels)
  through both prompts using `gpt-5.5`, `xhigh`, Codex SDK/CLI 0.158.0, and three
  concurrent calls. Both arms returned the correct three verdicts, with no
  provider or schema errors.
- The typed-match prototype passed all three mechanical citation assertions.
  The existing-triage baseline passed two: its remaining quote included a closing
  brace outside the cited source span. The strict Promptfoo result is therefore
  **five passes and one citation failure**, not a fully passing model benchmark.
- Reported costs for that six-call smoke were $1.56 for existing triage and $1.24
  for the prototype; median call latency was approximately 86 and 81 seconds.
  These are measurements of this small run, not performance or cost guarantees.
- A separate live `scanDependencies` SDK smoke used the affected fictional case,
  a local executable returning its frozen scanner response, and a real
  `gpt-5.5` assessment with low reasoning effort. After fixing the model's strict
  output-schema projection, it returned `completed`, retained one component and
  one advisory match, attached a completed `confirmed` assessment, and saved all
  report/raw-evidence artifacts with no diagnostics. Reported model cost was
  approximately $0.256. This verifies SDK orchestration and model integration;
  the scanner response in this particular test was simulated. Earlier failed
  stages retained the scanner match in partial results.

The runner explicitly includes the native Codex CLI package in its read-only
runtime roots because sandboxed shell tools need that executable. Gold labels
remain outside those roots. Earlier local bootstrap failures remain separate
from the successful smoke's results.

The local ignored artifacts are `artifacts/sca-smoke.json` and
`artifacts/sca-smoke-summary.json`, relative to the parent triage evaluation
directory. `fixtures/corpus.json` records the frozen input digests.

This smoke checks the evaluation machinery and prompt behavior. It does not
establish production accuracy or an improvement over the baseline. No human
labels or developer/update pilot results have been collected. SDK tests and a
separate SDK live smoke cover application integration; this directory's
Promptfoo configuration compares static triage prompt variants only.
