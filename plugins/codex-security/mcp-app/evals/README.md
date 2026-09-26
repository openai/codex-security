# Deep reducer paging eval

This eval runs one reducer against synthetic persisted worker findings and a previous aggregate. It uses the pinned Codex CLI, its external code-mode host, and the production artifact tool handlers. It does not launch a repository scan.

The fixture has a 32 MiB individual semantic field containing quotes, backslashes, newlines, and Unicode. Its old duplicated MCP response is about 114 MiB. The first input read deliberately returns that old response; all subsequent calls use the production paged implementation. The IPC error comes from the real transport, not a mocked error message.

The grader requires a smaller byte budget on the retry with the same cursor and reference, byte-bounded subsequent pages, one successful result submission, every source accounted for exactly once, complete original payloads matching their SHA-256 hashes, and preservation of the previous finding identity and synthesized history.

Install the MCP app's locked dependencies using the repository's normal setup, then run from the repository root:

```sh
node plugins/codex-security/mcp-app/evals/deep-reducer-paging.mjs deterministic
```

The deterministic mode supplies scripted model responses through a local HTTP provider. It uses a private temporary Codex home and no model credentials or external model requests. The script reads every input page, fetches original and prior canonical details by reference, and records the reduction through the real tools. This mode also runs in the normal MCP test suite as `test_deep_reducer_paging_eval.mjs`.

To evaluate a model's recovery decisions using the production reducer prompt:

```sh
node plugins/codex-security/mcp-app/evals/deep-reducer-paging.mjs model
```

The model run uses the caller's normal Codex credentials and configuration and consumes model usage. An optional final argument selects a model; otherwise Codex uses its configured model. The fault injection and result grader are the same. This mode is opt-in and does not run in CI. Unlike the deterministic run, it does not supply the recovery code to the model. The SDK does not expose every code-mode error event, so the model-mode grade relies on the observed oversized response, changed request, and saved result; the deterministic mode additionally asserts the exact transport diagnostic.

Each command prints the path to an ignored directory under `mcp-app/reports/` containing `report.json`, the compact tool-call trace, and the generated artifacts. The fixture is generated at runtime; no large payload files are checked in.
