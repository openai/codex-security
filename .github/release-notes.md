<!-- release-version: 0.10.1 -->

<!-- release-section: highlights:start -->

## Highlights

- **Exclude paths from scans.** Run `cs scan . --exclude-path examples/` to exclude a directory from review in Standard, Deep, or diff scans. Repeat the flag for more paths, or set `scan.exclude_paths` in your project configuration. Paths are literal and relative to the repository. The scanner can still read excluded files for context and filters out findings whose locations all fall under excluded paths.
- **Import scanner findings.** Use `cs import continuum` to collect AWS Continuum code issues with their supporting evidence. Attack-path analysis can use observations from the tested target when assessing reachability and severity. You can also import saved CrowdStrike Falcon Cloud Security IaC reports into your local workbench.
- **Deep Scan.** When Codex blocks a worker request because of a misalignment policy violation, Deep Scan now stops and reports the refusal without retrying the request.
- **Threat modeling.** When a route appears in a test or on a deleted line, the threat-modeling instructions now ask the scanner to verify that the application still serves it.

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

If you used the bundled AWS Continuum helper `collect_continuum.py`, switch to `cs import continuum ENVIRONMENT_ID --finding-id FINDING_ID --source-root /absolute/checkout --format json`. For environments with multiple Git repositories or an S3 source, supply `--repository-name` with the AWS source name. Existing saved finding exports and patch captures remain compatible. [Collect a finding with patches](https://github.com/openai/codex-security/blob/npm-v0.10.1/docs/scanner-imports/continuum.md#collect-a-finding-with-patches)

<!-- release-section: upgrades:end -->
