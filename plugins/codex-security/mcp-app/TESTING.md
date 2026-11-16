# MCP tests

[Install the SDK and MCP app dependencies](https://github.com/openai/codex-security/blob/main/sdk/typescript/TESTING.md#install-dependencies) and [download the universal native payload](../native/README.md#package-inputs). Run the following from the **repository root**.

To rebuild the bundled plugin and run the MCP tests:

```sh
pnpm --dir sdk/typescript run test:mcp
```

To rerun the MCP tests against that build or type-check the MCP sources and tooling:

```sh
pnpm --dir plugins/codex-security/mcp-app run test:mcp
pnpm --dir plugins/codex-security/mcp-app run typecheck
```

The runner streams TAP to the terminal. Read the failing test and assertion there. It also writes `plugins/codex-security/mcp-app/reports/junit.xml` when the output path is available. A report-writing warning leaves the test exit status intact.

Node runs up to two files at a time in separate processes. Tests inside each file run sequentially. Add tests as `tests/test_*.ts` and keep shared helpers outside that pattern. To compare a failure with serial execution, run this command **from `plugins/codex-security/mcp-app`**:

```sh
node --experimental-strip-types --test --test-concurrency=1 "tests/test_*.ts"
```

Use the existing injected clocks for retry policy tests. Keep real timers, subprocesses, SQLite files, and isolated temporary directories in the lifecycle, locking, permissions, and stdio tests. Do not share writable fixtures between test files or rebuild the bundled plugin while another test is reading it.
