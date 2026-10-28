<!-- release-version: 0.8.1 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security 0.8.1 improves scan output reliability and adds two ways to move findings between tools.

- **Scan output.** Scan directories preserve trailing hyphens in repository names. Hosted Linux path scans keep temporary file lists out of captured output when private state storage is available. If a sealed file changes after validation, the hosted SDK returns a failed receipt with no artifacts.
- **Dependabot imports.** With external imports enabled, import saved GitHub Dependabot alerts with `publish findings FILE --provider github`. Alerts keep their individual identities across imports, even when they share an advisory. See the [Dependabot import guide](https://github.com/openai/codex-security/blob/npm-v0.8.1/docs/scanner-imports/github-dependabot.md).
- **ServiceNow exports.** Export saved findings as a CSV for Manual AVIT Ingestion using `--export-format servicenow-avit` and `--avit-template`. See the [application template](https://github.com/openai/codex-security/blob/npm-v0.8.1/examples/servicenow-avit-template.csv).
- **Wolfi containers.** A manual release workflow can publish a versioned Linux amd64 scanner image with an SPDX software bill of materials. See the [Wolfi image guide](https://github.com/openai/codex-security/blob/npm-v0.8.1/docker/wolfi/README.md).

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

No additional migration steps are documented for this release.

<!-- release-section: upgrades:end -->
