# Contributing

Thanks for helping improve Codex Security. We welcome bug reports, feature
requests, documentation corrections, and feedback from open-source
maintainers.

## How this repository works

Most Codex Security code is developed in OpenAI's canonical repository and
published here through a one-way mirror. The plugin source under
`plugins/codex-security/` is the exception: this repository is its canonical
source, and it is mirrored one way into OpenAI's internal repository.

The npm runtime under `sdk/typescript/_bundled_plugin/` is generated from the
plugin source during build and release. Do not edit or commit files in that
directory. See the [SDK testing guide](sdk/typescript/TESTING.md) for the
generation and validation commands.

Search [existing issues](https://github.com/openai/codex-security/issues)
before opening a new one. We can't import pull requests that change mirrored
code back into its canonical source. Maintainers can carry accepted changes
into that source or invite a focused pull request for a path maintained in this
repository.

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

Maintainers update package dependencies and committed lockfiles alongside
their canonical source. The public release workflow installs those locked
graphs, tests the package, and publishes a verified artifact with npm
provenance. GitHub Actions dependencies are maintained separately in this
repository.

[GitHub Releases](https://github.com/openai/codex-security/releases) is the
canonical changelog. Maintainers should follow [RELEASING.md](RELEASING.md) to
prepare, publish, verify, or repair a release.

See the [SDK testing guide](sdk/typescript/TESTING.md) for local checks,
test conventions, and the required and experimental CI jobs.
