<!-- release-version: 0.5.1 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security 0.5.1 adds hosted patch generation and fix verification, and improves saved-scan replay, Deep Scan recovery, and Windows setup.

- **Hosted patching and verification.** Integrations can generate patches and independently verify candidate fixes through `runHostedRemediation()` and its JSON-RPC adapter using a supplied executor. Hosts own checkout isolation, sandbox enforcement, candidate patch identity, and publication. See the [hosted remediation guide](https://github.com/openai/codex-security/blob/npm-v0.5.1/sdk/typescript/docs/hosted-remediation.md). ([#1684](https://github.com/openai/codex-security/pull/1684))
- **Saved scan settings.** Daybreak selections persist across scans and remediation, including fresh and resumed Deep Scan workers. Saved Bedrock scans retain the effective AWS region and profile, and inline patches preserve the selected profile's provider settings. Severity classification uses the saved repository to select helpers. ([#1740](https://github.com/openai/codex-security/pull/1740), [#1811](https://github.com/openai/codex-security/pull/1811), [#1810](https://github.com/openai/codex-security/pull/1810), [#1815](https://github.com/openai/codex-security/pull/1815))
- **Deep Scan recovery and progress.** Reports retain accepted worker coverage and its original evidence, including coverage recovered after cancellation or a discovery deadline. Standard and diff scans refresh phase and review counts from saved state even when the model emits no new progress markers. ([#1593](https://github.com/openai/codex-security/pull/1593), [#1757](https://github.com/openai/codex-security/pull/1757))
- **Windows setup.** Runtime preparation uses private workspaces in the state directory so elevated-sandbox permissions on `TEMP` do not prevent scans from starting. Policy generation supports the default elevated Windows sandbox; see the access details below. Update notices also recognize global installations managed by nvm-windows. ([#1803](https://github.com/openai/codex-security/pull/1803), [#1741](https://github.com/openai/codex-security/pull/1741), [#1801](https://github.com/openai/codex-security/pull/1801))
- **Reliable command results.** Optional logging, update notices, and scratch cleanup no longer override completed scan, import, or publication outcomes. Failed commands do not print success output, and patch and verification commands wait for required output writes to finish. ([#1800](https://github.com/openai/codex-security/pull/1800), [#1818](https://github.com/openai/codex-security/pull/1818), [#1824](https://github.com/openai/codex-security/pull/1824), [#1826](https://github.com/openai/codex-security/pull/1826), [#1775](https://github.com/openai/codex-security/pull/1775), [#1777](https://github.com/openai/codex-security/pull/1777))

<details>
<summary>Other fixes</summary>

- Saved scopes, component scans, CSV imports, and activity displays preserve literal paths. Helper values beginning with `-` and literal TOML strings retain their values. ([#1812](https://github.com/openai/codex-security/pull/1812), [#1814](https://github.com/openai/codex-security/pull/1814), [#1786](https://github.com/openai/codex-security/pull/1786), [#1827](https://github.com/openai/codex-security/pull/1827), [#1809](https://github.com/openai/codex-security/pull/1809), [#1792](https://github.com/openai/codex-security/pull/1792))
- Basic patching supports Git repositories before their first commit. Directory inventories exclude `.svn` metadata, and component scans include tracked files matched by `.gitignore`. ([#1552](https://github.com/openai/codex-security/pull/1552), [#1768](https://github.com/openai/codex-security/pull/1768))
- Scan history, feedback selection, and automatic matching consistently use scan start times when choosing and comparing results. ([#1772](https://github.com/openai/codex-security/pull/1772), [#1774](https://github.com/openai/codex-security/pull/1774), [#1776](https://github.com/openai/codex-security/pull/1776), [#1779](https://github.com/openai/codex-security/pull/1779))
- SARIF exports preserve sealed scan artifacts. CSV processing preserves large quoted fields and finalized Deep Scan candidate metadata. ([#1769](https://github.com/openai/codex-security/pull/1769), [#1785](https://github.com/openai/codex-security/pull/1785), [#1828](https://github.com/openai/codex-security/pull/1828))
- Canceled fix verification restores an already applied patch's state. Deduplication reviews retry temporary Codex rate-limit errors, and cancellation is honored around embedding callbacks and saved result writes. ([#1819](https://github.com/openai/codex-security/pull/1819), [#1767](https://github.com/openai/codex-security/pull/1767), [#1789](https://github.com/openai/codex-security/pull/1789), [#1821](https://github.com/openai/codex-security/pull/1821))
- Runtime telemetry preserves analytics and OpenTelemetry controls across workers and remediation. ([#1691](https://github.com/openai/codex-security/pull/1691))
- Release automation waits for npm, installed-package checks, the GitHub Action, and container publication. Containers retain their place in the publication queue. ([#1796](https://github.com/openai/codex-security/pull/1796), [#1806](https://github.com/openai/codex-security/pull/1806))

</details>

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

### Windows policy generation

With the elevated Windows sandbox, policy generation can read other local source, including sibling components. The policy prompt retains the selected component's scope. Credential, configuration, and Git metadata denials, read-only access, and disabled network access remain enforced. Explicit sandbox choices and Unix read scope are unchanged. ([#1741](https://github.com/openai/codex-security/pull/1741))

### Saved scans of SVN working copies

Directory scans and patch identities now exclude `.svn` metadata. If a saved scan or patch included that metadata and no longer matches its source, restart the scan or regenerate the patch. Git diff and working-tree scans still require Git. ([#1552](https://github.com/openai/codex-security/pull/1552))

### Custom component and CSV scan clients

Custom component clients and clients handling explicit CSV scopes now receive absolute scan targets. Component callers intentionally using home shorthand should supply an absolute path inside the repository. Saved plans and receipts retain their existing formats, and completed campaign receipts remain reusable. ([#1814](https://github.com/openai/codex-security/pull/1814))

### GitHub Action

The Marketplace display name is now **OpenAI Codex Security**. Use `openai/codex-security@action-v0.5.1`, or pin the full distribution commit recorded in the Action release manifest. The npm package name remains `@openai/codex-security`. Marketplace publication is a separate step after the automated release. ([#1797](https://github.com/openai/codex-security/pull/1797))

### Upgrading from earlier releases

If upgrading from before 0.5.0, also review the [0.5.0 upgrade notes](https://github.com/openai/codex-security/releases/tag/npm-v0.5.0), including custom capability-preflight integrations and selected-profile approval settings.

If upgrading from before 0.4.0, upgrade CLI and plugin installations together when they share a Codex Security state directory. The shared issue-history migration preserves existing Linear receipts, but older publishers cannot write to the migrated database. ([#1426](https://github.com/openai/codex-security/pull/1426))

<!-- release-section: upgrades:end -->
