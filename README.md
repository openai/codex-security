# Codex Security

`@openai/codex-security` is a CLI and TypeScript SDK for finding, validating, and
fixing security vulnerabilities in your code. It can also draft security policies
to guide future scans.

See the [online documentation](https://learn.chatgpt.com/docs/security/cli)
for a walkthrough.

## Quick start

Requires Node.js 22.13.0+ within 22.x, or Node.js 24.x or 26.x, and Python 3.10+.
Python 3.10 also requires `tomli`.

```bash
npm install @openai/codex-security
npx @openai/codex-security login
npx @openai/codex-security scan /path/to/repository
```

For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY` in the scan process's environment.
On remote or headless machines, use `login --device-auth` if your workspace
allows it, or [sign in over SSH](sdk/typescript/README.md#remote-login-with-ssh-forwarding).

Some cybersecurity requests and protected findings require
[Trusted Access for Cyber](https://chatgpt.com/cyber) approval.

## TypeScript SDK

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

The [SDK guide](sdk/typescript/README.md) covers scan options, deep scans,
and working with findings.

## Generate SECURITY.md

```bash
npx @openai/codex-security policy .
```

The command saves a draft outside the checkout. Review it before installing it
to guide future scans. See the [policy guide](sdk/typescript/docs/cli.md#generate-a-security-policy)
for component policies, supporting documents, and SDK usage.

## Other providers

Use [Amazon Bedrock](docs/bedrock.md) with AWS credentials, or
[OpenRouter and Fireworks AI](sdk/typescript/docs/cli.md#native-command-authentication-and-other-providers)
with the provider's API key and a supported model.

## Findings service (preview)

The findings service stores findings, shows them in a dashboard, and supports
deduplication. Its API has no built-in authentication, and imports send complete
finding JSON to the configured embeddings endpoint. See the
[setup guide](sdk/typescript/docs/findings-service.md) for credentials, storage,
and deployment.

## Documentation

- [CLI reference](sdk/typescript/docs/cli.md): scan options, history, validation,
  patching, and integrations.
- [Project configuration](docs/project-configuration.md): shared YAML or JSON
  settings for the CLI and SDK.
- [Exports and CI](sdk/typescript/docs/cli.md#exports-and-ci): export saved findings
  and threat models without starting another analysis.
- [Severity classification](sdk/typescript/docs/cli.md#classify-finding-severity):
  assess findings against your own rubric.
- [Owner suggestions](sdk/typescript/docs/cli.md#suggest-finding-owners): suggest
  contributors based on source and Git history.
- [Containerized bulk scans](sdk/typescript/docs/cli.md#containerized-bulk-scans)
  and the [workflow runner](docker/README.md#workflow-runner): run scans and
  individual CLI stages in containers.
- [Examples](examples/README.md): CI workflows, custom validation, and a sample app.

To report a vulnerability privately, follow the [security policy](SECURITY.md).
