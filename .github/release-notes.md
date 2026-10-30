<!-- release-version: 0.8.2 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security 0.8.2 adds threat-model explorers and Amazon Inspector imports, and improves scan progress and finding review.

- **Threat-model explorers.** Turn an existing threat model into a shareable HTML explorer with interactive architecture, scenarios, controls, and source evidence. Export HTML or SVG from the bundled skill.
- **Amazon Inspector imports.** With external imports enabled, import a complete Inspector Code Security repository findings export while retaining each finding's identity across imports. See the [Inspector import guide](https://github.com/openai/codex-security/blob/npm-v0.8.2/docs/scanner-imports/inspector.md).
- **Dedupe corrections.** Hosted reviewers can correct rejected decisions in the original open review when the host supports pending-call validation.
- **Interactive scans.** Finding review shows critical findings first, followed by high, medium, and low severity. Component tables show saved review progress, and scan titles resolve relative directory names.
- **Output directories.** Existing scan output directories keep their permissions across scans, saved-result reads, and resume. Newly created directories remain private by default.
- **Container releases.** The release workflow builds Debian and Wolfi images from the same verified scanner package and frozen runtime dependency lock. See the [container guide](https://github.com/openai/codex-security/blob/npm-v0.8.2/docker/README.md).

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

No migration is required for existing CLI workflows. Hosted integrations that opt into pending-call validation must keep the original review session open until they handle the CLI's feedback; existing hosts can continue returning final results.

Inspector imports remain opt-in. Cloud publication requires a connected GitHub repository and a deployment that accepts the Inspector provider. The import guide describes repository matching and complete-export requirements.

<!-- release-section: upgrades:end -->
