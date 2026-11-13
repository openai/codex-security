# Codex Security

Codex Security helps you find, investigate, and fix vulnerabilities in your code.
Use its security workflows in Codex, or automate them with the
`@openai/codex-security` CLI and TypeScript SDK.

- **In Codex:** [choose a security workflow](docs/agent-workflows.md).
- **In a terminal:** [install the CLI and scan your repository](#quick-start).
- **In automation:** use the [TypeScript SDK](#typescript-sdk) or
  [GitHub Action](#github-actions).

## Features

- Scan repositories, selected paths, or Git changes. Deep scans repeat Standard scans and return their deduplicated findings.
- Validate candidate findings, generate patches, and verify existing fixes.
- Draft `SECURITY.md` policies and save threat models for later review.
- Browse saved scans and findings, identify duplicates, assess severity against
  your own rubric, and suggest owners from source and Git history.
- Preview third-party scanner findings, save them locally, or publish supported reports to Codex Security Cloud. [Scanner import guides](docs/scanner-imports/README.md).
- Track findings in Linear, Jira, or GitHub, publish completed scans, or export SARIF, JSON, and CSV. [Integration workflows](docs/plugin-connectors.md).
- Automate scans across repositories or project components, including in CI and
  containers.

## Use in Codex

Open your repository in a Codex session with the Codex Security plugin enabled,
then ask:

> Run a Codex Security scan on this repository, focusing on authentication and
> authorization. Return the saved report, source evidence, and coverage limits.

A completed scan saves a report and findings. Read the report for source
evidence and exclusions, then request a patch or ask Codex to verify an
existing fix. See the [agent workflow guide](docs/agent-workflows.md) for setup,
task selection, and recovery.

## Quick start

Requires Node.js 22.13.0+ within 22.x, or Node.js 24.x or 26.x, and Python 3.10+.
Python 3.10 also requires `tomli`.

Install the CLI globally and sign in:

```bash
npm install --global @openai/codex-security
cs login
```

Run your first scan from the repository directory:

```bash
cs scan .
```

When the scan completes, open the Markdown file at the **REPORT** path in the
terminal. Run `cs scans show` from the same repository to find its latest
completed scan again. See [scan scope and follow-up work](sdk/typescript/docs/cli.md#understand-scan-scope-and-follow-up-work)
for how to interpret exclusions in the report.

`cs` and `codex-security` run the same CLI. If the short name conflicts with
another command, use `codex-security`. To skip the global install, or if npm
reports an `EEXIST` conflict, use `npx @openai/codex-security` in place of
`cs` for both login and scanning.

For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY` in the scan process's environment.
For a headless machine, see [device or SSH login](sdk/typescript/docs/cli.md#authentication).

### Scan options

Choose a scope and scan mode:

```bash
# Scan selected paths.
cs scan . --path src --path tests

# Scan committed changes from a base revision to HEAD.
cs scan . --diff origin/main

# Run a deep scan of the repository.
cs scan . --mode deep
```

Use `cs scan . --max-time 15` for an advisory 15-minute Standard investigation
allowance. See [investigation time](sdk/typescript/docs/cli.md#set-investigation-time)
for timing semantics and Deep Scan limits.

Use `cs --help` to browse commands, or `cs scan --help`
for scan options, cost limits, and patching after a scan.

For an application spread across repositories, see
[review one system across repositories](sdk/typescript/docs/cli.md#review-one-system-across-repositories).
Use [bulk scans](sdk/typescript/docs/cli.md#bulk-scans) for independent repository
reviews in one resumable campaign.

Scans use existing root and component `SECURITY.md` guidance. To write or
revise it, see [Generate SECURITY.md](#generate-securitymd).

Some cybersecurity requests and protected findings require
[Trusted Access for Cyber](https://chatgpt.com/cyber). For accounts with Daybreak
access, see [Daybreak opt-in](sdk/typescript/docs/cli.md#daybreak-opt-in) for the
Codex toggle and [Cyber access programs](sdk/typescript/docs/cli.md#select-a-cyber-access-program)
to select a program explicitly.

## TypeScript SDK

Install the package locally in your TypeScript project:

```bash
npm install @openai/codex-security
```

Then import it:

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

The [SDK guide](sdk/typescript/docs/sdk.md) includes deep-scan configuration,
validation, severity classification, owner suggestions, and result handling.

Linked Git worktrees share scan history and saved findings when they use the same
Codex Security state directory. Keep `CODEX_SECURITY_STATE_DIR` stable to retain
that shared history and sign-in scope. See the [scan history guide](sdk/typescript/docs/cli.md#scan-history-and-reruns).

## Read existing Cloud findings

When Codex Security Cloud is available to your account, the Security plugin's
`$cloud-findings` skill can read findings, reports, recorded assignment and
verification, and scan status in Codex desktop or the Codex CLI. Cloud is an
optional connection; local scans work without it.

See [Cloud connection setup and CLI reads](sdk/typescript/docs/sdk.md#read-existing-cloud-findings)
for authentication requirements and a read-only example.

## Generate SECURITY.md

Use `policy` to draft a new `SECURITY.md` or update an existing one. Use `--path`
to select a component:

```bash
cs policy .
cs policy . --path services/api --knowledge-base architecture.md
```

The command saves its draft outside the repository and leaves existing files
unchanged. Review the diff and notes, edit the draft, then copy only `SECURITY.md`
to the displayed **Policy target**. Keep the saved architecture and threat-model
documents outside the repository.

Scans already use root and component `SECURITY.md` files. Keep your current policy
if it needs no changes. When updating it, preserve its vulnerability-reporting
instructions. If the command says the policy is already up to date, no copy is
needed.

Files at `.github/SECURITY.md` or `docs/SECURITY.md` often contain reporting
instructions. Preserve them when drafting a policy; those locations do not
automatically provide repository-wide scan guidance. See the
[policy guide](sdk/typescript/docs/cli.md#generate-a-security-policy) for policy
locations, unanswered questions, saved artifacts, and SDK usage.

## Save and export threat models

Scans and policy generation save threat models with their results. Export a saved
model without starting another analysis:

```bash
cs export --scan SCAN_ID --artifact threat-model --output threatmodel.md
```

Omit `--scan` to use the current repository's latest completed scan. The
[export guide](sdk/typescript/docs/cli.md#exports-and-ci) also covers findings,
SARIF output for CI, and the offline TypeScript API. For ServiceNow Application
Vulnerability Response, see [Export findings for ServiceNow](sdk/typescript/docs/cli.md#export-findings-for-servicenow).

## GitHub Actions

To run a weekly repository scan on GitHub-hosted Ubuntu:

1. Add an OpenAI API key as the repository secret `CODEX_SECURITY_API_KEY`.
2. Copy the [weekly workflow](github-action/examples/repository.yml) to
   `.github/workflows/codex-security.yml`. Replace `REPLACE_WITH_REVIEWED_COMMIT`
   with the reviewed distribution commit SHA from an Action release.
3. To try the workflow before the next scheduled run, open **Actions → Codex
   Security repository → Run workflow**.

The example uses an estimated $5 limit per scan and reports findings without
failing the job. Requests in progress can exceed the limit. For a severity
threshold, pull request checks, or runner requirements, see the
[Action guide](github-action/README.md). For eligible accounts, see
[Daybreak access](github-action/README.md#daybreak-access-and-refusals).

## Containerized bulk scans

Scan a list of repositories with the included Docker Compose configuration,
which keeps results and authentication between runs. See the
[container quick start](sdk/typescript/docs/cli.md#containerized-bulk-scans).
The [workflow runner](docker/README.md#workflow-runner) runs individual CLI stages
in containers and can connect to a separately deployed findings service.

## Findings storage and deduplication

The [findings guide](sdk/typescript/docs/findings-service.md) covers local
storage, deduplication, and compatibility with independently operated endpoints
through `publish scan --to custom` and explicit `--findings-url`. The local
`serve` command and browser dashboard have been removed; existing databases and
scan artifacts remain available.

## Other providers

Scans support OpenAI, Amazon Bedrock, OpenRouter, Fireworks AI, and Cheaper Inference. Bedrock uses
AWS credentials and does not require a separate OpenAI login. See
[Bedrock setup](docs/bedrock.md) for AWS profiles, regions, and model access.

For OpenRouter, Fireworks AI, and Cheaper Inference, set the provider's API key and choose a supported
model. See [provider configuration](sdk/typescript/docs/cli.md#native-command-authentication-and-other-providers)
for examples.

## Documentation

- [Online documentation](https://learn.chatgpt.com/docs/security/cli)
- [Agent workflows and recovery](docs/agent-workflows.md)
- [CLI reference](sdk/typescript/docs/cli.md)
- [Imported finding identity and evidence](docs/scanner-imports/schema-guide.md)
- [Project configuration](docs/project-configuration.md)
- [Examples](examples/README.md)

To report a vulnerability privately, follow the [security policy](SECURITY.md).

## Citation

Use **Cite this repository** on GitHub to copy an APA or BibTeX citation, or
download the metadata from [CITATION.cff](CITATION.cff). To cite the version
you used, run `codex-security --version` and include the publication date
from the matching `npm-vX.Y.Z` entry in [GitHub Releases](https://github.com/openai/codex-security/releases).
