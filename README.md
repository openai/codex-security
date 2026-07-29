# Codex Security

`@openai/codex-security` is a CLI and TypeScript SDK for finding, validating, and fixing security vulnerabilities in your code. Scan repositories, review changes, track findings over time, and run security checks in CI.

**[Documentation](http://learn.chatgpt.com/docs/security/cli)**

## Quick start

Requires Node.js 22 or later, Python 3.10 or later, and access to Codex Security.

```bash
npm install @openai/codex-security
npx @openai/codex-security login
npx @openai/codex-security scan .
npx @openai/codex-security scan . --model gpt-5.6-terra --effort high
```

For CI, set `OPENAI_API_KEY` instead of signing in.

If both a ChatGPT sign-in and an API key are available, interactive scans ask
which credential to use. CI and other noninteractive scans keep the existing
API-key precedence. Select a credential explicitly when needed:

```bash
npx @openai/codex-security scan . --auth chatgpt
npx @openai/codex-security scan . --auth api-key
```

To make your ChatGPT sign-in the automatic default, unset any configured API
keys:

```bash
unset OPENAI_API_KEY CODEX_API_KEY
```

Scan history is stored in the Codex Security workbench state directory. If that
directory cannot be written, set `CODEX_SECURITY_STATE_DIR` to a writable
directory outside the repository.

## TypeScript SDK

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();
const result = await security.run(".");

console.log(result.reportPath);
await security.close();
```

For installation, authentication, scan options, and CI setup, see the [official documentation](http://learn.chatgpt.com/docs/security/cli).
