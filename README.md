# Codex Security

Run Codex Security scans from the command line or a TypeScript application.

> [!WARNING]
> Codex Security is in beta. APIs, CLI options, and output formats may change.

## Requirements

The SDK and CLI require Node.js 22 or later. Running a scan also requires a
Python interpreter for the bundled Codex Security plugin. Python is not needed
to install the package or run `--help` and `--version`.

Before running a scan, set `OPENAI_API_KEY` or `CODEX_API_KEY`, or reuse an
existing file-backed Codex sign-in.

## Install and scan

```bash
npm install @openai/codex-security@beta
npx codex-security scan /path/to/repo
```

Scan a subset of a repository or write machine-readable results:

```bash
npx codex-security scan /path/to/repo --path src --path tests
npx codex-security scan /path/to/repo --diff origin/main --json
npx codex-security scan /path/to/repo --output-dir /path/outside/repo/results
```

The output directory must be outside the scanned repository. When SARIF is produced, it is written to
`<scan-dir>/exports/results.sarif`. Use `npx codex-security scan --help` for all
target, output, and runtime options.

## TypeScript SDK

```ts
import { CodexSecurity } from "@openai/codex-security";

await using security = new CodexSecurity();
const result = await security.run("/path/to/repo");
console.log(result.reportPath);
```

See the [TypeScript SDK and CLI reference](sdk/typescript/README.md) for
authentication, targets, output, and API details. Product documentation is
available in the [Codex Security guide](https://developers.openai.com/codex/security).

## Support and security

Please use [GitHub issues](https://github.com/openai/codex-security/issues) for
bugs and feature requests. Report vulnerabilities privately using the
[security policy](SECURITY.md).

This project is licensed under the [Apache-2.0 License](LICENSE).
