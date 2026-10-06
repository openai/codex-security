# Contributing

Thanks for helping improve Codex Security. We welcome bug reports, feature
requests, documentation corrections, and feedback from open-source
maintainers.

## How this repository works

`plugins/codex-security/` is the canonical source for the Codex Security
plugin. Make plugin changes there.

The npm runtime under `sdk/typescript/_bundled_plugin/` is generated from the
plugin source by `pnpm run build:plugin` and automatically during `prepack` for
packages and releases. Do not edit or commit files in that directory. See the
[SDK testing guide](sdk/typescript/TESTING.md) for the generation and validation
commands.

Model-based evaluations live in [`evals/`](evals/README.md), outside the plugin
source. Deterministic triage checks and the MCP reducer IPC regression remain
part of normal CI.

Search [existing issues](https://github.com/openai/codex-security/issues)
before opening a new one.

## Support for open-source projects

If you maintain an open-source project,
[open an issue](https://github.com/openai/codex-security/issues/new) with the
repository, your role, and what you need. Support is best effort. Scan only
repositories you trust and either own or have permission to assess.

## Report a bug

Include your CLI or SDK version, operating system, reproduction steps, and
the expected and observed behavior. Remove credentials, private code,
customer data, and security findings before posting.

## Suggest a feature or improve the documentation

Open an issue describing the problem and the workflow you want to support.
Documentation corrections and safe examples are welcome.
Use synthetic examples when documenting expected behavior.
Keep example values fictional and safe to share.
Do not include credentials or private information in examples.

## Report a security issue

Report Codex Security vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). Do not post vulnerabilities, exploit details,
credentials, or sensitive scan results publicly.

If a scan finds a vulnerability in another project, report it to that
project's maintainers through their security policy.

## Dependency and release maintenance

Maintainers update package dependencies and committed lockfiles with the
affected source. The public release workflow installs those locked graphs,
tests the package, and publishes a verified artifact with npm provenance.
GitHub Actions dependencies are maintained separately in this repository.

Workflow and composite-action changes run `workflow-quality` through the existing
required Unix CI checks. actionlint validates workflow syntax, and ShellCheck
checks shell scripts in workflow `run` steps for warnings and errors. zizmor's
offline checks at medium severity and above cover workflows and composite
actions. The pinned tool versions are in `.github/workflows/workflow-quality.yml`;
run these checks locally with:

```bash
SHELLCHECK_OPTS=--severity=warning actionlint
zizmor --offline --strict-collection --min-severity medium --config .github/zizmor.yml .github
```

The actionlint configuration preserves GitHub's supported release queue and
job-level cache syntax until the linter supports them. The zizmor configuration
records reviewed privileged triggers and their trust boundaries. Review these
exceptions when changing the affected workflows.

CI package builds and npm release validation require the production dependency
audit to pass. Run it locally with `pnpm --dir sdk/typescript run audit:prod`.
The existing policy checks production dependencies at the high-severity threshold.
Resolve high or critical advisories, or audit service failures, before retrying.

[GitHub Releases](https://github.com/openai/codex-security/releases) is the
canonical changelog. Maintainers should follow [RELEASING.md](RELEASING.md) to
prepare, publish, verify, or repair a release.

See the [SDK testing guide](sdk/typescript/TESTING.md) for local checks,
test conventions, and the required and experimental CI jobs.
