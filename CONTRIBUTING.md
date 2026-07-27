# Contributing

Codex Security is developed in OpenAI's canonical repository and published to
this repository through a one-way mirror. External pull requests cannot be
imported into the canonical source.

## Report a bug

Search [existing GitHub issues](https://github.com/openai/codex-security/issues)
before opening a new one. Include the installed CLI or SDK version, operating
system, reproduction steps, expected behavior, and the observed result.

Remove API keys, access tokens, repository contents, security findings, and
other sensitive information from public reports. Report security vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

## Request a feature or improve the documentation

Open a GitHub issue describing the problem, the workflow you want to support,
and any relevant product behavior. Documentation corrections and safe
reproduction details are welcome in the issue discussion.

Maintainers review issues and carry accepted changes into the canonical source.

## Dependency and release maintenance

Maintainers update package dependencies and the committed lockfile in the
canonical repository. The public release workflow installs that locked graph,
tests the package, and publishes a verified artifact with npm provenance.
GitHub Actions dependencies are maintained separately in this repository.
