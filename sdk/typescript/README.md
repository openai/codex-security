# `@openai/codex-security`

Scan your repository for vulnerabilities and get a Markdown report with findings
and source locations. This package includes a command-line tool and a TypeScript
SDK, along with the Codex runtime and security plugin.

## Install

Use Node.js 22.x (22.13.0 or later), 24.x, or 26.x on macOS, Linux, or Windows.
Scans also require Python 3.10 or later. On Python 3.10, install `tomli`.

### Scan from the command line

From the repository you want to scan, install the CLI, sign in with ChatGPT,
and scan the current directory.

```sh
npm install --global @openai/codex-security
cs login
cs scan .
```

Open the Markdown file at the **REPORT** path printed by the CLI. In CI, set
`OPENAI_API_KEY` or `CODEX_API_KEY` in the scan environment to authenticate.

### Scan from TypeScript

Install the SDK in your project. If you haven't signed in yet, use the local CLI
to log in.

```sh
npm install @openai/codex-security
npx @openai/codex-security login
```

Run this ES module from the repository you want to scan.

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();
try {
  const result = await security.run(".");
  console.log(result.reportPath);
} finally {
  await security.close();
}
```

## Documentation

- [CLI reference](https://github.com/openai/codex-security/blob/main/sdk/typescript/docs/cli.md) for scan options, authentication, and exports.
- [SDK guide](https://github.com/openai/codex-security/blob/main/sdk/typescript/docs/sdk.md) for configuration, progress events, and reading findings.
- [Security policy](https://github.com/openai/codex-security/blob/main/SECURITY.md) for reporting vulnerabilities in this package privately.
