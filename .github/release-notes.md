<!-- release-version: 0.5.1 -->

<!-- release-section: highlights:start -->

## Highlights

- preserve Daybreak settings across scans and remediation ([#1740](https://github.com/openai/codex-security/pull/1740))
- support the elevated Windows sandbox ([#1741](https://github.com/openai/codex-security/pull/1741))
- refresh scan progress from saved state ([#1757](https://github.com/openai/codex-security/pull/1757))
- support unborn Git worktrees and ignore SVN metadata ([#1552](https://github.com/openai/codex-security/pull/1552))
- preserve controls and share request attribution ([#1691](https://github.com/openai/codex-security/pull/1691))
- include tracked ignored files in component scans ([#1768](https://github.com/openai/codex-security/pull/1768))
- select feedback by the latest scan start instant ([#1776](https://github.com/openai/codex-security/pull/1776))
- preserve sealed SARIF artifacts during export ([#1769](https://github.com/openai/codex-security/pull/1769))
- order occurrence history by scan start time ([#1772](https://github.com/openai/codex-security/pull/1772))
- use chronological cutoffs for explicit comparisons ([#1774](https://github.com/openai/codex-security/pull/1774))
- await required patch and verification output ([#1777](https://github.com/openai/codex-security/pull/1777))
- reject non-finite numbers before storage ([#1773](https://github.com/openai/codex-security/pull/1773))
- read scan counts and latest scans together ([#1771](https://github.com/openai/codex-security/pull/1771))
- avoid success output after command failures ([#1775](https://github.com/openai/codex-security/pull/1775))
- preserve CODEOWNERS token grammar ([#1787](https://github.com/openai/codex-security/pull/1787))
- stabilize Python discovery and native worker tests ([#1793](https://github.com/openai/codex-security/pull/1793))
- retain finding details with own JSON keys ([#1780](https://github.com/openai/codex-security/pull/1780))
- order automatic matches by scan start time ([#1779](https://github.com/openai/codex-security/pull/1779))
- preserve literal TOML override strings ([#1792](https://github.com/openai/codex-security/pull/1792))
- preserve validation behavior for malformed scan usage ([#1781](https://github.com/openai/codex-security/pull/1781))
- preserve record endings in large finding exports ([#1785](https://github.com/openai/codex-security/pull/1785))
- honor cancellation around embedding callbacks ([#1789](https://github.com/openai/codex-security/pull/1789))
- resolve stdin context after argument parsing ([#1784](https://github.com/openai/codex-security/pull/1784))
- compare stored numeric JSON exactly ([#1788](https://github.com/openai/codex-security/pull/1788))
- reject non-finite values in retained scan drafts ([#1783](https://github.com/openai/codex-security/pull/1783))
- publish containers with coordinated npm releases ([#1796](https://github.com/openai/codex-security/pull/1796))

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

No additional migration steps are documented for this release.

<!-- release-section: upgrades:end -->
