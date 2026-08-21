# Contributing

Thanks for helping improve Codex Security. We welcome bug reports, feature
requests, documentation corrections, and feedback from open-source
maintainers.

## How this repository works

Codex Security is developed in OpenAI's canonical repository and published
here through a one-way mirror. We can't import pull requests from this
repository into the canonical source.

Search [existing issues](https://github.com/openai/codex-security/issues)
before opening a new one. Maintainers can carry accepted changes into the
canonical source or invite a focused pull request for this public repository.

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

Maintainers update package dependencies and the committed lockfile in the
canonical repository. The public release workflow installs that locked graph,
tests the package, and publishes a verified artifact with npm provenance.
GitHub Actions dependencies are maintained separately in this repository.

The `node-release-pr` workflow can propose the next patch version after `main`
passes `node-ci` and the current npm and GitHub releases are complete. It
preserves any same-repository pull request that already proposes a newer stable
version. Otherwise, when package files changed after the current release, it
creates a one-line version commit and a pull request with an unchecked public
disclosure checklist. It does not merge, tag, publish, or dispatch another
workflow.

The workflow requires a GitHub App installation with access to this repository
and Actions read, Contents write, and Pull requests write permissions. Its token
is scoped to this repository. Set `RELEASE_APP_CLIENT_ID` to the App's client ID
and `RELEASE_APP_PRIVATE_KEY` to its private key. The workflow has no
`GITHUB_TOKEN` fallback and does not need npm credentials or OIDC permissions.

The workflow will not recreate an intentionally closed proposal or reuse an
orphan `release/patch-X.Y.Z` branch. If a write or exact-head review request
fails, inspect the public branch and pull request, then finish or remove them
before rerunning. Maintainers must review every generated public artifact,
complete the disclosure checklist, and satisfy the normal approval and CI
requirements. To check eligibility without writing, run `node-release-pr`
manually from `main` with `dry_run` enabled.
