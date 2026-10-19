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

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

Review migration steps for these breaking changes:

- retire advisory capability preflight ([#1609](https://github.com/openai/codex-security/pull/1609))

<!-- release-section: upgrades:end -->
