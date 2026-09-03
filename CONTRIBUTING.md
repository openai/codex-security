# Contributing

Thanks for helping improve Codex Security. We welcome bug reports, feature
requests, documentation corrections, and feedback from open-source
maintainers.

## How this repository works

`plugins/codex-security/` is the canonical source for the Codex Security
plugin. Make plugin changes there.

The npm runtime under `sdk/typescript/_bundled_plugin/` is generated from the
plugin source by `bun run build:plugin` in `sdk/typescript`, and automatically during `prepack` for
packages and releases. Do not edit or commit files in that directory. See the
[SDK testing guide](sdk/typescript/TESTING.md) for the generation and validation
commands.

Search [existing issues](https://github.com/openai/codex-security/issues)
before opening a new one.

## Local development

Use Bun 1.3.14, matching `packageManager` in `sdk/typescript/package.json`,
and a [supported Node.js version](sdk/typescript/README.md#install). Node.js 24.x
works with both the SDK and the separate triage eval runner. Bun manages
dependencies and maintainer commands; the CLI, SDK, and builds still use Node.js.

Repository tests also need Python 3.12+ in a virtual environment and ripgrep
(`rg`) on `PATH`. The Python test requirement comes from
`plugins/codex-security/pyproject.toml`; it is separate from the published
CLI's Python 3.10+ runtime support.

With those tools installed and the virtual environment active, run from the
repository root:

```bash
python -m pip install -e 'plugins/codex-security[test]'
bun install --cwd sdk/typescript --frozen-lockfile
bun install --cwd plugins/codex-security/mcp-app --frozen-lockfile
bun run --cwd sdk/typescript build:plugin
bun run --cwd sdk/typescript build
node sdk/typescript/bin/codex-security.mjs --help
```

Install both JavaScript packages before building the bundled plugin. Each
package owns its lockfile; there is no `package.json` at the repository root.
Use `bun run --cwd <package-directory> <script>` for commands from another
directory. The [triage evals](plugins/codex-security/skills/triage-finding/evals/README.md)
have a separate setup and are not required for the SDK build.

Follow the [SDK testing guide](sdk/typescript/TESTING.md) for focused tests,
full checks, and package inspection. Published-package installation commands
and npm release publication remain unchanged.

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

[GitHub Releases](https://github.com/openai/codex-security/releases) is the
canonical changelog. Maintainers should follow [RELEASING.md](RELEASING.md) to
prepare, publish, verify, or repair a release.

See the [SDK testing guide](sdk/typescript/TESTING.md) for local checks,
test conventions, and the required and experimental CI jobs.
