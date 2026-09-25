# Codex Security

`@openai/codex-security` is a CLI and TypeScript SDK for defining security policy and finding, validating, and fixing security vulnerabilities in your code.

**👉👉 See the [Codex Security documentation](https://learn.chatgpt.com/docs/security/cli)** for full documentation.

Some cybersecurity requests and protected findings require approval through
Trusted Access for Cyber. To join the program, visit
[chatgpt.com/cyber](https://chatgpt.com/cyber).

## Quick start

Requires Node.js 22.13.0 or later and Python 3.10 or later.

```bash
npm install @openai/codex-security
npx @openai/codex-security login
npx @openai/codex-security scan /path/to/directory
```

For CI, set `OPENAI_API_KEY` instead of signing in.

## Generate SECURITY.md

Draft repository-wide or component-scoped `SECURITY.md` guidance for future scans:

```bash
npx @openai/codex-security policy .
npx @openai/codex-security policy . --path services/api --knowledge-base architecture.md
```

The command saves a draft outside the checkout; it does not install it or run a
vulnerability scan. Review the proposed diff before copying the policy. Supporting architecture,
threat-model, and review documents stay outside the repository and may contain
sensitive details. See the [SDK policy guide](sdk/typescript/README.md#generate-a-security-policy)
for headless generation, saved artifacts, and SDK usage.

## TypeScript SDK

To suggest owners for existing findings from source and Git history, see
[Suggest finding owners](sdk/typescript/README.md#suggest-finding-owners).

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

## GitHub Actions

Scan your repository on a scheduled basis, in PR, or on demand. Add an OpenAI API key as the repository
secret `CODEX_SECURITY_API_KEY`, then save this workflow in
`.github/workflows/codex-security.yml`. Replace `REPLACE_WITH_REVIEWED_COMMIT`
with the full SHA of an Action commit.

```yaml
name: Codex Security
on:
  workflow_dispatch:
  schedule:
    - cron: '23 7 * * 1' # Mondays at 07:23 UTC

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: openai/codex-security@REPLACE_WITH_REVIEWED_COMMIT
        with:
          model: gpt-5.6-sol
          effort: high
        env:
          OPENAI_API_KEY: ${{ secrets.CODEX_SECURITY_API_KEY }}
```

Findings are report-only by default. Valid partial scans warn; scanner and
required reporting errors fail the job. Severity thresholds apply to complete scans.
See the [Action setup and input reference](github-action/README.md) for PR scans,
severity thresholds, and report uploads.

## Containerized bulk scans

Use the included Docker Compose configuration for scans of many repositories. See the [container quick start](sdk/typescript/README.md#containerized-bulk-scans) for more detail.

For individual CLI stages with durable state and access to a separately deployed
findings service, use the same scanner image with the
[workflow runner Compose example](docker/README.md#workflow-runner).

## Findings service (preview)

Run `npx @openai/codex-security serve` to start the service without Docker. See
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
`npx @openai/codex-security publish scan --to custom --findings-url http://localhost:3000`
command uploads completed findings and their repository ID. The SDK and
`npx @openai/codex-security dedupe` command retrieve candidates, run independent Codex
reviews locally, and persist accepted duplicate groups; `--all-repositories`
opts into the broader scope.

Use `npx @openai/codex-security classify-severity --scan SCAN_ID --rubric /path/to/policy.md`
to assess selected findings under your own policy before publishing tickets.
Scan classification checkpoints each finding in SQLite and reuses matching
assessments on reruns; `--reprocess` forces reassessment. The SDK exposes the same
classification operation; original scan severity stays unchanged. See [severity classification](sdk/typescript/README.md#classify-finding-severity).

## Other providers

To use another inference provider, set its API key and select a model:

```bash
export AWS_BEARER_TOKEN_BEDROCK="<your-bedrock-api-key>"
export AWS_REGION="us-east-2"
npx @openai/codex-security scan . --provider amazon-bedrock --model openai.gpt-5.6-luna

export OPENROUTER_API_KEY="<your-openrouter-api-key>"
npx @openai/codex-security scan . --provider openrouter --model anthropic/claude-sonnet-4.5

export FIREWORKS_API_KEY="<your-fireworks-api-key>"
npx @openai/codex-security scan . --provider fireworks --model accounts/fireworks/models/qwen3-235b-a22b
```

## Documentation

**👉👉 See the [Codex Security documentation](https://learn.chatgpt.com/docs/security/cli)** for full documentation.

See [project configuration](docs/project-configuration.md) for reusable YAML/JSON
settings, CLI overrides, and editor schema support.
