# Deep reducer paging eval

This optional model eval runs one reducer against synthetic persisted worker findings and a previous aggregate. It uses the pinned Codex CLI, its external code-mode host, the production reducer prompt, and the production artifact tool handlers. It does not launch a repository scan.

The fixture has a 32 MiB individual semantic field containing quotes, backslashes, newlines, and Unicode. Its old duplicated MCP response is about 114 MiB. The first input read deliberately returns that old response; all subsequent calls use the production paged implementation. The IPC error comes from the real transport, not a mocked error message.

The grader requires a smaller byte budget on the retry with the same cursor and reference, byte-bounded subsequent pages, one successful result submission, every source accounted for exactly once, complete original payloads matching their SHA-256 hashes, and preservation of the previous finding identity and synthesized history.

Install the SDK and MCP app’s locked dependencies using the repository's normal setup, then run from the repository root:

```sh
pnpm --dir sdk/typescript run build:evals
node --experimental-strip-types evals/deep-reducer/run.mts
```

The run uses the caller's normal Codex credentials and configuration and consumes model usage. An optional final argument selects a model; otherwise Codex uses its configured model. This eval is opt-in and does not run in CI. The model receives only the production reducer prompt and must discover and carry out recovery itself. The SDK does not expose every code-mode error event, so the grade relies on the observed oversized response, changed request, and saved result.

The command prints the path to an ignored directory under `evals/deep-reducer/reports/` containing `report.json`, the compact tool-call trace, and the generated artifacts. The fixture is generated at runtime; no large payload files are checked in.

## Deterministic regression test

The same fixture, real transport, and grading helpers live under `plugins/codex-security/mcp-app/tests/support/reducer-paging/`. The normal MCP test suite exercises them with scripted model responses from a local HTTP provider, a private temporary Codex home, and no model credentials or external model requests. It additionally asserts the exact transport diagnostic and checks that the grader rejects missing input pages and collapsed independent findings.

Run that test directly from the repository root:

```sh
node --experimental-strip-types --test plugins/codex-security/mcp-app/tests/test_deep_reducer_paging_eval.ts
```
