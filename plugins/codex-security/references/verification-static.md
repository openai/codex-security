# Verification mode: static

Apply source-only verification throughout the task, including delegated reviews and caller-provided validation instructions. Do not install dependencies or run builds, tests, reproducers, or the application. Use repository-reading tools.

Inspect the final source and diff. Trace the original exploit path and plausible bypasses through the relevant control. Read callers and existing tests as source to establish that legitimate behavior and compatibility are preserved. Cite specific evidence for each gate.

State that runtime checks were not performed. Missing runtime tooling alone does not block static verification. Report any material gap in the source evidence using the skill’s outcome for insufficient proof.
