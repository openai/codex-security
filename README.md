# Codex Security

`@openai/codex-security` is a CLI and TypeScript SDK for finding, validating, and fixing security vulnerabilities in your code.

**👉👉 See the [Codex Security documentation](https://learn.chatgpt.com/docs/security/cli)** for full documentation.

Some cybersecurity requests and protected findings require approval through
Trusted Access for Cyber. To join the program, visit
[chatgpt.com/cyber](https://chatgpt.com/cyber).

## Quick start

Requires Node.js 22.13.0 or later and Python 3.10 or later.

```bash
npm install @openai/codex-security
codex-security login
codex-security scan /path/to/directory
```

For CI, set `OPENAI_API_KEY` instead of signing in.

## TypeScript SDK

Codex Security is a Javascript package:

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();
const result = await security.run("/path/to/directory");
await security.run("/path/to/directory", {
  mode: "deep",
  workers: 2,
  subagents: 0,
  stopAfterNoNew: 3,
  maxDiscoveryRuns: 10,
  maxTimeHours: 1.5,
});

console.log(result.reportPath);
await security.close();
```

## Containerized bulk scans

Use the included Docker Compose configuration for scans of many repositories. See the [container quick start](sdk/typescript/README.md#containerized-bulk-scans) for more detail.

For individual CLI stages with durable state and access to a separately deployed
findings service, use the same scanner image with the
[workflow runner Compose example](docker/README.md#workflow-runner).

## Findings service (preview)

Run `codex-security serve` to start the service without Docker. See
[running without Docker](sdk/typescript/README.md#running-without-docker)
for prerequisites, credentials, and storage configuration.

The [findings service](sdk/typescript/README.md#findings-service-preview) runs
from the same `ghcr.io/openai/codex-security` image as the scanner (or a local
source build), with a separate container and state volume configured by
`compose.findings.yaml`. It stores findings and embeddings in SQLite and lists
findings with pagination. Its read-only dashboard at `/dashboard` refreshes every
five seconds and shows stored findings and duplicate groups from the service's
database. It also returns potential duplicates by embedding similarity within a
repository or an explicit all-repository scope. The
`codex-security publish scan --to custom --findings-url http://localhost:3000`
command uploads completed findings and their repository ID. The SDK and
`codex-security dedupe` command retrieve candidates, run independent Codex
reviews locally, and persist accepted duplicate groups; `--all-repositories`
opts into the broader scope.

## Other providers

To use another inference provider, set its API key and select a model:

```bash
export AWS_BEARER_TOKEN_BEDROCK="<your-bedrock-api-key>"
export AWS_REGION="us-east-2"
codex-security scan . --provider amazon-bedrock --model openai.gpt-5.6-luna

export OPENROUTER_API_KEY="<your-openrouter-api-key>"
codex-security scan . --provider openrouter --model anthropic/claude-sonnet-4.5

export FIREWORKS_API_KEY="<your-fireworks-api-key>"
codex-security scan . --provider fireworks --model accounts/fireworks/models/qwen3-235b-a22b
```

## Documentation

**👉👉 See the [Codex Security documentation](https://learn.chatgpt.com/docs/security/cli)** for full documentation.
