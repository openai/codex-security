# Codex Security

`@openai/codex-security` is a CLI and TypeScript SDK for finding, validating, and fixing security vulnerabilities in your code. Scan repositories, review changes, track findings over time, and run security checks in CI.

**[Documentation](http://learn.chatgpt.com/docs/security/cli)**

## Quick start

Requires Node.js 22 or later, Python 3.10 or later, and access to Codex Security.

```bash
npm install @openai/codex-security
npx codex-security login
npx codex-security scan .
```

For CI, set `OPENAI_API_KEY` instead of signing in.

## TypeScript SDK

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();
const result = await security.run(".");

console.log(result.reportPath);
await security.close();
```

For installation, authentication, scan options, and CI setup, see the [official documentation](http://learn.chatgpt.com/docs/security/cli).
