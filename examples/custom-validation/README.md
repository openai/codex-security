# Custom validation demo

This deliberately vulnerable invoice API contains only synthetic data. Do not
deploy it. The validation script starts a real loopback HTTP server, tests
cross-account access, saves the evidence, and stops the server. It needs Python
3.10 or later and no extra packages or Docker.

From the repository root, build the CLI and run the demo:

```bash
pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir sdk/typescript run build
node examples/custom-validation/run.mjs
```

The runner uses your existing Codex Security sign-in or API key. It copies the
fixture to a temporary directory and prints the scan output path. Extra CLI
options can be appended, for example `--model gpt-5.6-terra --effort high`.

Look for these files in the printed scan directory:

- `report.md`: the completed security report.
- `artifacts/custom-validation/candidates.json`: the fixed candidate set.
- `artifacts/custom-validation/http-proof.json`: observed HTTP responses.
- `artifacts/custom-validation/results.json`: the structured dispositions.

The expected result is a reportable cross-account invoice read. The proof should
show an anonymous 401, Alice's own invoice returning 200, Alice reading Bob's
invoice with 200, and `server_stopped: true`. The scan fails if custom validation
cannot complete; it does not fall back to the default validation workflow.

Adapt [validation.md](validation.md) for your own setup, tests, and cleanup.
For a Docker-based project, the same prompt can run your existing compose or
test script instead of `validate.py`.
