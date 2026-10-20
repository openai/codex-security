<!-- release-version: 0.5.1 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security 0.5.1 improves scan configuration, progress reporting, and saved
finding exports. It also adds Windows elevated-sandbox compatibility for policy
generation and coordinates container publication with npm and the GitHub Action.

- Daybreak selections persist across scans and remediation, including fresh and
  resumed Deep Scan workers. Literal configuration strings retain their values
  when passed to Codex.
  ([#1740](https://github.com/openai/codex-security/pull/1740),
  [#1792](https://github.com/openai/codex-security/pull/1792))
- Standard and diff scans refresh progress from saved state, including phase and
  review counts, even when the model emits no new progress markers.
  ([#1757](https://github.com/openai/codex-security/pull/1757))
- Scanning a repository subdirectory includes tracked files matched by
  `.gitignore`. Policy generation works with the default elevated Windows
  sandbox; see the access details below.
  ([#1768](https://github.com/openai/codex-security/pull/1768),
  [#1741](https://github.com/openai/codex-security/pull/1741))
- Scan history, feedback selection, and automatic matching use scan start times
  consistently when choosing and comparing results.
  ([#1772](https://github.com/openai/codex-security/pull/1772),
  [#1774](https://github.com/openai/codex-security/pull/1774),
  [#1776](https://github.com/openai/codex-security/pull/1776),
  [#1779](https://github.com/openai/codex-security/pull/1779))
- SARIF export preserves sealed scan artifacts. CSV imports handle large quoted
  fields without misreading record separators and preserve literal paths,
  candidate IDs, and notes.
  ([#1769](https://github.com/openai/codex-security/pull/1769),
  [#1785](https://github.com/openai/codex-security/pull/1785),
  [#1786](https://github.com/openai/codex-security/pull/1786))
- Patch and verification commands wait for required output to finish and report
  asynchronous write failures.
  ([#1777](https://github.com/openai/codex-security/pull/1777))
- The release workflow waits for npm, GitHub Action, and container publication.
  The Action's Marketplace display name is now **OpenAI Codex Security**.
  ([#1796](https://github.com/openai/codex-security/pull/1796),
  [#1797](https://github.com/openai/codex-security/pull/1797))

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

### Windows policy generation

With the elevated Windows sandbox, policy generation can read other local source,
including sibling components. The policy prompt retains the selected component's
scope. Credential, configuration, and Git metadata denials, read-only access, and
disabled network access remain enforced. Explicit sandbox choices and Unix read
scope are unchanged.
([#1741](https://github.com/openai/codex-security/pull/1741))

### GitHub Action

The Marketplace display-name change does not change the repository reference:
use `openai/codex-security@action-v0.5.1`, or pin the full distribution commit
recorded in the Action release manifest. The npm package name remains
`@openai/codex-security`. Wait for the release workflow and Marketplace
publication to finish before treating the listing as updated.

<!-- release-section: upgrades:end -->
