# `@openai/codex-security`

TypeScript SDK and CLI for running the Codex Security plugin. The package is
ESM-only, includes TypeScript declarations, and installs the `codex-security`
executable with the aligned `@openai/codex` runtime dependency.

> [!WARNING]
> Codex Security is in beta. APIs, CLI options, and output formats may change.

## Install

```bash
npm install @openai/codex-security@beta
npx codex-security --version
```

Node.js 22 or later is required. Running a scan also requires Python for the
bundled plugin; configure its interpreter with `--python`, `pythonPath`, or
`PYTHON` when automatic discovery is not appropriate.

Before scanning, set `OPENAI_API_KEY` or `CODEX_API_KEY`, or reuse an existing
file-backed Codex sign-in.

## CLI

```bash
npx codex-security scan /path/to/repository
npx codex-security scan /path/to/repository --path src --path tests
npx codex-security scan /path/to/repository --diff origin/main --json
npx codex-security scan /path/to/repository --output-dir /path/outside/repository/results
```

`--path` scopes a scan to one or more paths, `--diff` scans committed changes,
and `--working-tree` scans staged and unstaged changes. Deep scans support
repository and path targets. The output directory must be outside the scanned
repository. When SARIF is produced, it is written to
`<scan-dir>/exports/results.sarif`.

Run `npx codex-security scan --help` for the complete CLI reference.

## SDK

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();
try {
  const result = await security.run("/path/to/repository");
  console.log(result.reportPath);
} finally {
  await security.close();
}
```

The SDK also supports scoped and diff targets, streaming, cancellation, API-key
and Codex sign-in flows, and typed scan results. See the
[SDK and CLI reference](https://github.com/openai/codex-security/blob/main/sdk/typescript/compatibility/PARITY_MATRIX.md) for supported methods,
options, output, and exit behavior.

Product documentation is available in the
[Codex Security guide](https://developers.openai.com/codex/security). Please
report bugs using [GitHub issues](https://github.com/openai/codex-security/issues)
and vulnerabilities using the repository security policy.
