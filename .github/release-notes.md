<!-- release-version: 0.5.1 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security 0.5.1 improves saved-scan replay, Deep Scan coverage recovery, and Windows runtime setup. It also fixes progress reporting and saved finding exports, and coordinates container publication with npm and the GitHub Action.

- **Saved scan settings.** Daybreak selections persist across scans and remediation, including fresh and resumed Deep Scan workers. Saved Bedrock scans retain the effective AWS region and profile. Severity classification uses the saved repository to select helpers, and configuration reports identify the source of retained settings correctly. ([#1740](https://github.com/openai/codex-security/pull/1740), [#1811](https://github.com/openai/codex-security/pull/1811), [#1815](https://github.com/openai/codex-security/pull/1815), [#1807](https://github.com/openai/codex-security/pull/1807))
- **Deep Scan coverage.** Reports and recovered results retain accepted worker coverage and its original evidence, including coverage recovered after cancellation or a discovery deadline. ([#1593](https://github.com/openai/codex-security/pull/1593))
- **Windows setup.** Runtime preparation uses private workspaces in the state directory so elevated-sandbox permissions on `TEMP` do not prevent scans from starting. Policy generation also supports the default elevated Windows sandbox; see the access details below. ([#1803](https://github.com/openai/codex-security/pull/1803), [#1741](https://github.com/openai/codex-security/pull/1741))
- **Scan progress.** Standard and diff scans refresh phase and review counts from saved state even when the model emits no new progress markers. ([#1757](https://github.com/openai/codex-security/pull/1757))
- **Release publication.** The release workflow waits for npm, GitHub Action, and container publication. Container releases keep their place in the queue, and each run uses the same revision of the release helpers. ([#1796](https://github.com/openai/codex-security/pull/1796), [#1806](https://github.com/openai/codex-security/pull/1806))

<details>
<summary>Other fixes</summary>

- Saved scopes preserve literal `~` paths during rerun and resume. Helper values that start with `-` remain values rather than being parsed as options. Literal configuration strings also retain their values when passed to Codex. ([#1812](https://github.com/openai/codex-security/pull/1812), [#1809](https://github.com/openai/codex-security/pull/1809), [#1792](https://github.com/openai/codex-security/pull/1792))
- Scanning a repository subdirectory includes tracked files matched by `.gitignore`. ([#1768](https://github.com/openai/codex-security/pull/1768))
- Scan history, feedback selection, and automatic matching use scan start times consistently when choosing and comparing results. ([#1772](https://github.com/openai/codex-security/pull/1772), [#1774](https://github.com/openai/codex-security/pull/1774), [#1776](https://github.com/openai/codex-security/pull/1776), [#1779](https://github.com/openai/codex-security/pull/1779))
- SARIF export preserves sealed scan artifacts. CSV imports handle large quoted fields without misreading record separators and preserve literal paths, candidate IDs, and notes. ([#1769](https://github.com/openai/codex-security/pull/1769), [#1785](https://github.com/openai/codex-security/pull/1785), [#1786](https://github.com/openai/codex-security/pull/1786))
- Patch and verification commands wait for required output to finish and report asynchronous write failures. Deduplication reviews retry temporary Codex rate-limit errors. ([#1777](https://github.com/openai/codex-security/pull/1777), [#1767](https://github.com/openai/codex-security/pull/1767))

</details>

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

### Windows policy generation

With the elevated Windows sandbox, policy generation can read other local source, including sibling components. The policy prompt retains the selected component's scope. Credential, configuration, and Git metadata denials, read-only access, and disabled network access remain enforced. Explicit sandbox choices and Unix read scope are unchanged. ([#1741](https://github.com/openai/codex-security/pull/1741))

### GitHub Action

The Action's Marketplace display name is now **OpenAI Codex Security**. This does not change the repository reference: use `openai/codex-security@action-v0.5.1`, or pin the full distribution commit recorded in the Action release manifest. The npm package name remains `@openai/codex-security`. Wait for the release workflow and Marketplace publication to finish before treating the listing as updated. ([#1797](https://github.com/openai/codex-security/pull/1797))

<!-- release-section: upgrades:end -->
