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
