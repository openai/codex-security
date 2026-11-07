<!-- release-version: 0.8.3 -->

<!-- release-section: highlights:start -->

## Highlights

- **Scans and reporting.** Run a local scan without connecting an app. Standard and Deep scans include more concrete guidance for finding issues in source. The GitHub Action lists the highest-severity findings first in its job summary and annotations. Published evidence links to Markdown files open the cited source lines on GitHub.
- **Scanner imports.** Import Black Duck SCA project-version vulnerabilities, Veracode static policy flaws and AWS Continuum code findings. The [scanner guides](https://github.com/openai/codex-security/tree/npm-v0.8.3/docs/scanner-imports) describe the accepted formats and destinations.
- **Severity and remediation.** Standard scans can use a host-supplied severity rubric. Standalone classification reports the rubric it used. Generated patches for completed scans can be saved with the scan.

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

- See [Upgrading to 0.8.3](https://github.com/openai/codex-security/blob/main/CHANGELOG.md#upgrading-to-083) for changes to cost limits, required PR checks, and the tracking and deduplication helpers.

<!-- release-section: upgrades:end -->
