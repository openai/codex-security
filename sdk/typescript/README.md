# `@openai/codex-security`

Scan a repository, selected paths, or Git changes for vulnerabilities. The CLI
and TypeScript SDK can validate findings, generate patches, verify fixes, and
export results as SARIF, JSON, or CSV. The package includes the Codex runtime
and security plugin.

## Install

Use Node.js 22.x (22.13.0 or later), 24.x, or 26.x on macOS, Linux, or Windows.
Scans also require Python 3.10 or later. On Python 3.10, install `tomli`.

### Install the CLI

```sh
npm install --global @openai/codex-security
```

The CLI runs as `cs` or `codex-security`. To skip the global install, use
`npx @openai/codex-security` in place of `cs` in the examples below.

### Install the TypeScript SDK

Install the package in your project directory.

```sh
npm install @openai/codex-security
```

Before 1.0, minor releases may change the public API.

## Authentication

Run `cs login` to sign in with ChatGPT. With a local SDK installation, run
`npx @openai/codex-security login` from your project. In CI, set
`OPENAI_API_KEY` or `CODEX_API_KEY` in the scan environment.
Some requests require [Trusted Access for Cyber](https://chatgpt.com/cyber).

## CLI

Run a scan from the repository you want to review.

```sh
cs scan .
```

To scan only committed changes from `origin/main` to `HEAD`, run
`cs scan . --diff origin/main`. A completed scan exits with code `0` by default,
even when it finds vulnerabilities. Add `--fail-on-severity high` to exit with
code `1` for high or critical findings.

## Run a scan from TypeScript

Run this ES module from the repository you want to scan.

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();
try {
  const result = await security.run(".");
  console.log(result.reportPath);
  console.log(`${result.findings.findings.length} findings`);
} finally {
  await security.close();
}
```

### Read results

By default, results are saved in the private Codex Security state directory.
Open the Markdown report at the CLI’s **REPORT** path or the SDK’s
`result.reportPath`. Reports and logs can contain source code, credentials, and
vulnerability details. Review them before sharing.

## Local security model

Scans run with your operating-system permissions. Start them with only the
credentials they need because subprocesses can inherit your environment.

## Documentation and security

- [CLI reference](https://github.com/openai/codex-security/blob/main/sdk/typescript/docs/cli.md) for scan options, authentication, and exports.
- [SDK guide](https://github.com/openai/codex-security/blob/main/sdk/typescript/docs/sdk.md) for configuration, progress events, and the full set of examples.
- [Security policy](https://github.com/openai/codex-security/blob/main/SECURITY.md) for reporting vulnerabilities in this package privately.
