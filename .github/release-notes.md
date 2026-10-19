<!-- release-version: 0.5.0 -->

<!-- release-section: highlights:start -->

## Highlights

- support host-provided standalone reviews ([#1682](https://github.com/openai/codex-security/pull/1682))
- retire advisory capability preflight ([#1609](https://github.com/openai/codex-security/pull/1609))
- support scan CLI inference providers ([#1677](https://github.com/openai/codex-security/pull/1677))
- do not report a successful envelope for a failed dedupe ([#1071](https://github.com/openai/codex-security/pull/1071))
- separate Git transport from review providers ([#1551](https://github.com/openai/codex-security/pull/1551))
- update Bedrock workflow to CLI 0.3.0 ([#1675](https://github.com/openai/codex-security/pull/1675))
- avoid copying unused dictionary items ([#1661](https://github.com/openai/codex-security/pull/1661))
- normalize hostnames before credential lookup and API routing ([#1069](https://github.com/openai/codex-security/pull/1069))
- clean up imports and expected test exceptions ([#1665](https://github.com/openai/codex-security/pull/1665))
- honor selected profile approval policy ([#530](https://github.com/openai/codex-security/pull/530))
- remove reasoning effort allowlist ([#1712](https://github.com/openai/codex-security/pull/1712))
- use the SHA-256 empty tree for root commit diffs ([#1716](https://github.com/openai/codex-security/pull/1716))
- read diff blobs with Git before 2.38 ([#1715](https://github.com/openai/codex-security/pull/1715))
- bump the third-party group across 3 directories with 3 updates ([#1696](https://github.com/openai/codex-security/pull/1696))
- separate diff revisions from paths in scan inputs ([#1694](https://github.com/openai/codex-security/pull/1694))
- bump ruff from 0.16.10 to 0.17.0 in /plugins/codex-security ([#1695](https://github.com/openai/codex-security/pull/1695))
- preserve generated-note command failures ([#1729](https://github.com/openai/codex-security/pull/1729))
- drop deleted revisions and field codes from DOCX ([#1714](https://github.com/openai/codex-security/pull/1714))
- URL-encode generated schema references ([#981](https://github.com/openai/codex-security/pull/981))
- detect Windows Yarn global installs in update notices ([#1692](https://github.com/openai/codex-security/pull/1692))
- add Cheaper Inference inference provider ([#1623](https://github.com/openai/codex-security/pull/1623))
- describe positive numeric input bounds ([#1605](https://github.com/openai/codex-security/pull/1605))
- import schema APIs directly from Zod ([#1726](https://github.com/openai/codex-security/pull/1726))
- normalize CWE identifiers without integer conversion ([#1723](https://github.com/openai/codex-security/pull/1723))
- remove the empty editable Python distribution ([#1724](https://github.com/openai/codex-security/pull/1724))
- delete whole characters when editing patch instructions ([#1549](https://github.com/openai/codex-security/pull/1549))
- adopt the registered target kind when sealing a scan draft ([#828](https://github.com/openai/codex-security/pull/828))
- reject remote targets the SDK reader refuses to load ([#1569](https://github.com/openai/codex-security/pull/1569))

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

Review migration steps for these breaking changes:

- retire advisory capability preflight ([#1609](https://github.com/openai/codex-security/pull/1609))

<!-- release-section: upgrades:end -->
