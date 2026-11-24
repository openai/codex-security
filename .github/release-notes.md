<!-- release-version: 0.11.0 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security 0.11.0 adds two opt-in ways to investigate a finding. You can check whether a dependency advisory applies to your code or ask AWS Continuum to assess a code finding in a deployed environment.

- **Dependency investigations.** Set `CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY=1` and run `cs exploitability check "$CVE_ID" --format html` from your checkout. You can also supply captured call stacks. The check asks an independent reviewer to verify the evidence. The report shows which advisory conditions are met and where the evidence is incomplete. [Experimental CLI guide](https://github.com/openai/codex-security/blob/npm-v0.11.0/sdk/typescript/docs/cli.md#experimental-dependency-investigations)
- **AWS Continuum validation.** Select a trusted project file that configures Continuum. The CLI sends findings to AWS when you request validation. The packaged plugin submits them automatically after a Standard, Deep, or diff scan with that file. Check the destination first. Finding details can contain sensitive information. Local validation notes stay on the host by default. Codex severity and `--fail-on-severity` stay unchanged. [Choose what to send and resume a check](https://github.com/openai/codex-security/blob/npm-v0.11.0/docs/validation-providers.md)
- **Patch and verify.** On the original host, `cs patch` and `cs verify-fix` can reuse current Continuum evidence. They distinguish issue-wide results from findings assessed individually and evaluate the fix independently. If a finding moves to another issue, rerun `cs validate --scan` with the original options to refresh it. Disputed verdicts and scores require newer evidence.
- **Deep Scan on Windows.** Deep Scan retries a heartbeat or receipt update when another process briefly holds the file open. If the write fails, the previous file stays intact.
- **Workbench.** Listing global findings no longer hangs when a legacy finding links scans across worktrees.

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

The experimental CLI change requires no migration from 0.10.1. If a development build script called `cs exploitability run read-stacks`, switch to `cs exploitability run next --state "$STATE"` and read `workItem` and `receiptId` from its JSON output.

If a saved Continuum assessment shows `outdated`, keep the original state directory and repeat plugin completion or rerun the saved CLI validation on the same host before using the assessment for remediation.

Static verification asks Codex to skip running the code. If you also pass `--assess-patch-risk`, the separate risk assessment may run local tests. [Patch verification guide](https://github.com/openai/codex-security/blob/npm-v0.11.0/sdk/typescript/docs/cli.md#patch-existing-findings)

<!-- release-section: upgrades:end -->
