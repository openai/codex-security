# Custom validation demo

This deliberately vulnerable invoice API contains only synthetic data. Do not
deploy it. The validation script starts a real loopback HTTP server, tests
cross-account access, saves the evidence, and stops the server. The fixture uses
only Python's standard library and needs no Docker. Running the scan also needs
the [CLI prerequisites](../../sdk/typescript/README.md#install) and Bun 1.3.14
for the source build.

From the repository root, build the CLI and run the demo:

```bash
bun install --cwd sdk/typescript --frozen-lockfile
bun install --cwd plugins/codex-security/mcp-app --frozen-lockfile
bun run --cwd sdk/typescript build:plugin
bun run --cwd sdk/typescript build
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
