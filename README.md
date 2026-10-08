# Codex Security

`@openai/codex-security` is a CLI and TypeScript SDK for finding, validating, and
fixing security vulnerabilities in your code.

## Features

- Scan repositories, selected paths, or Git changes. Deep scans run parallel
  discovery workers on repositories and selected paths.
- Validate candidate findings, generate patches, and verify existing fixes.
- Draft `SECURITY.md` policies and save threat models for later review.
- Browse saved scans and findings, identify duplicates, assess severity against
  your own rubric, and suggest owners from source and Git history.
- Import GitHub code scanning alerts, export SARIF, JSON, or CSV, and publish
  findings to Linear or a findings service.
- Automate scans across repositories or project components, including in CI and
  containers.

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

### Scan options

Choose a scope and scan mode:

```bash
# Scan selected paths.
npx @openai/codex-security scan . --path src --path tests

# Scan committed changes from a base revision to HEAD.
npx @openai/codex-security scan . --diff origin/main

# Run a deep scan of the repository.
npx @openai/codex-security scan . --mode deep
```

Use `npx @openai/codex-security --help` to browse commands, or `scan --help`
for scan options, cost limits, and patching after a scan.

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

The [SDK guide](sdk/typescript/README.md) includes deep-scan configuration,
validation, severity classification, owner suggestions, and result handling.

## Generate SECURITY.md

Draft security guidance for a repository or one of its components:

```bash
npx @openai/codex-security policy .
npx @openai/codex-security policy . --path services/api --knowledge-base architecture.md
```

The command saves a draft outside the checkout. Review it before installing it
as guidance for future scans. See the [policy guide](sdk/typescript/docs/cli.md#generate-a-security-policy)
for supporting documents and SDK usage.

## Save and export threat models

Scans and policy generation save threat models with their results. Export a saved
model without starting another analysis:

```bash
npx @openai/codex-security export --scan SCAN_ID --artifact threat-model --output threatmodel.md
```

Omit `--scan` to use the current repository's latest completed scan. The
[export guide](sdk/typescript/docs/cli.md#exports-and-ci) also covers findings,
SARIF output for CI, and the offline TypeScript API.

## GitHub Actions

Run scheduled, manual, or pull request scans with the GitHub Action. For a weekly
repository scan, add an OpenAI API key as the repository secret
`CODEX_SECURITY_API_KEY`, then save this workflow in
`.github/workflows/codex-security.yml`. Replace `REPLACE_WITH_REVIEWED_COMMIT`
with the full SHA of an Action commit.

```yaml
name: Codex Security
on:
  workflow_dispatch:
  schedule:
    - cron: "23 7 * * 1" # Mondays at 07:23 UTC

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-24.04
    steps:
      - name: Set up the Ubuntu sandbox
        run: |
          sudo apt-get update
          sudo apt-get install --yes bubblewrap apparmor-profiles
          sudo apparmor_parser -r /usr/share/apparmor/extra-profiles/bwrap-userns-restrict
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

Findings are report-only by default. Partial scans with valid results produce a
warning; scanner and required reporting errors fail the job. Severity thresholds
apply to complete scans.
See the [Action setup and input reference](github-action/README.md) for PR scans,
severity thresholds, and report uploads.

## Containerized bulk scans

Scan a list of repositories with the included Docker Compose configuration,
which keeps results and authentication between runs. See the
[container quick start](sdk/typescript/docs/cli.md#containerized-bulk-scans).
The [workflow runner](docker/README.md#workflow-runner) runs individual CLI stages
in containers and can connect to a separately deployed findings service.

## Findings service (preview)

Store findings, browse them in a dashboard, and review potential duplicates.
Start the local service with:

```bash
npx @openai/codex-security serve
```

Publish a completed scan with `publish scan --to custom`, then use `dedupe` to
review potential duplicates and save accepted groups. Point both commands at the
service with `--findings-url`. The [service guide](sdk/typescript/docs/findings-service.md)
covers setup, publishing, deduplication, and Docker deployment.

The API has no built-in authentication. Imports send complete finding JSON to
the configured embeddings endpoint and need an embedding API key, even after
ChatGPT login.

## Other providers

Scans support OpenAI, Amazon Bedrock, OpenRouter, and Fireworks AI. Bedrock uses
AWS credentials and does not require a separate OpenAI login. See
[Bedrock setup](docs/bedrock.md) for AWS profiles, regions, and model access.

For OpenRouter and Fireworks AI, set the provider's API key and choose a supported
model. See [provider configuration](sdk/typescript/docs/cli.md#native-command-authentication-and-other-providers)
for examples.

## Documentation

- [Online documentation](https://learn.chatgpt.com/docs/security/cli)
- [CLI reference](sdk/typescript/docs/cli.md)
- [Project configuration](docs/project-configuration.md)
- [Examples](examples/README.md)

To report a vulnerability privately, follow the [security policy](SECURITY.md).
