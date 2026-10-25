<!-- release-version: 0.6.1 -->

<!-- release-section: highlights:start -->

## Highlights

- simplify user guides and correct setup instructions ([#1857](https://github.com/openai/codex-security/pull/1857))
- verify Codex before caching installation ([#1855](https://github.com/openai/codex-security/pull/1855))
- update incur to 0.7.1 and react to 19.3.1 ([#1862](https://github.com/openai/codex-security/pull/1862))
- build owner reports without extra model calls ([#1845](https://github.com/openai/codex-security/pull/1845))
- isolate audits and retain exact file identities ([#1859](https://github.com/openai/codex-security/pull/1859))
- update Node to security release 26.12.1 ([#1870](https://github.com/openai/codex-security/pull/1870))
- preserve large Git configuration environments ([#1882](https://github.com/openai/codex-security/pull/1882))
- accept large security policy files ([#1883](https://github.com/openai/codex-security/pull/1883))
- preserve complete scan failure diagnostics ([#1884](https://github.com/openai/codex-security/pull/1884))
- preserve all reviewed scan feedback ([#1885](https://github.com/openai/codex-security/pull/1885))
- update OpenCode SDK to 1.19.2 ([#1880](https://github.com/openai/codex-security/pull/1880))
- preserve complete local vendor evidence ([#1886](https://github.com/openai/codex-security/pull/1886))
- preserve MCP connections for large scan checkpoints ([#1873](https://github.com/openai/codex-security/pull/1873))
- persist large scan usage at completion and failure ([#1874](https://github.com/openai/codex-security/pull/1874))
- skip work cancelled before it starts ([#1733](https://github.com/openai/codex-security/pull/1733))
- preserve scan directory identities and isolate Git fixtures ([#1833](https://github.com/openai/codex-security/pull/1833))
- isolate artifact upload failures ([#1719](https://github.com/openai/codex-security/pull/1719))
- report usage and extend integration attribution ([#1703](https://github.com/openai/codex-security/pull/1703))
- recover publication after a lost reply ([#938](https://github.com/openai/codex-security/pull/938))
- render MCP threat models in TypeScript ([#1839](https://github.com/openai/codex-security/pull/1839))
- recover checkpoints at discovery deadlines ([#1594](https://github.com/openai/codex-security/pull/1594))
- validate findings after a scan ([#1007](https://github.com/openai/codex-security/pull/1007))
- bump ruff from 0.17.0 to 0.17.1 in /plugins/codex-security ([#1878](https://github.com/openai/codex-security/pull/1878))
- bump @linear/sdk from 97.2.0 to 98.0.0 in /sdk/typescript ([#1881](https://github.com/openai/codex-security/pull/1881))
- bump ip-address from 10.7.2 to 10.7.4 in /plugins/codex-security/mcp-app ([#1876](https://github.com/openai/codex-security/pull/1876))
- bump taiki-e/install-action from 2.87.28 to 2.87.29 ([#1877](https://github.com/openai/codex-security/pull/1877))
- keep saved-results source within import limit ([#1891](https://github.com/openai/codex-security/pull/1891))
- allow readable interactive verification results ([#1836](https://github.com/openai/codex-security/pull/1836))
- upgrade Codex and preserve oversized MCP recovery ([#1879](https://github.com/openai/codex-security/pull/1879))
- normalize location paths before deduplicating ([#1867](https://github.com/openai/codex-security/pull/1867))
- report verification failures in structured output ([#1835](https://github.com/openai/codex-security/pull/1835))
- retain unfinished deadline checkpoints ([#1710](https://github.com/openai/codex-security/pull/1710))
- clarify requested scope and deferred work ([#586](https://github.com/openai/codex-security/pull/586))
- preserve literal scope paths across renderers ([#1850](https://github.com/openai/codex-security/pull/1850))
- preserve Unicode colon source paths ([#542](https://github.com/openai/codex-security/pull/542))
- simplify security skill instructions ([#1676](https://github.com/openai/codex-security/pull/1676))
- update the GitHub Action runtime to 0.6.0 ([#1906](https://github.com/openai/codex-security/pull/1906))
- separate report readers from source providers ([#1871](https://github.com/openai/codex-security/pull/1871))
- persist run warnings in SARIF exports ([#1893](https://github.com/openai/codex-security/pull/1893))
- keep HTML entities literal in report text ([#1851](https://github.com/openai/codex-security/pull/1851))
- keep saved findings consistent through recovery ([#1310](https://github.com/openai/codex-security/pull/1310))
- preserve unrated vulnerability severity on import ([#1898](https://github.com/openai/codex-security/pull/1898))
- match scan owner hints across email case variants ([#1900](https://github.com/openai/codex-security/pull/1900))
- preserve worker coverage during recovery ([#1064](https://github.com/openai/codex-security/pull/1064))
- update bundled undici to 6.29.1 ([#1915](https://github.com/openai/codex-security/pull/1915))
- bump @opencode-ai/sdk from 1.19.2 to 1.19.3 in /evals/triage-finding in the third-party group across 1 directory ([#1919](https://github.com/openai/codex-security/pull/1919))
- bump libc from 0.2.190 to 0.2.191 in /plugins/codex-security/native ([#1918](https://github.com/openai/codex-security/pull/1918))
- verify merge parents after a pull request retarget ([#1948](https://github.com/openai/codex-security/pull/1948))
- wait for static checks before validating container images ([#1949](https://github.com/openai/codex-security/pull/1949))
- trace failures to the original job attempt ([#1922](https://github.com/openai/codex-security/pull/1922))
- document the deterministic triage CI checks ([#1932](https://github.com/openai/codex-security/pull/1932))
- validate generated files before rebuilding them ([#1934](https://github.com/openai/codex-security/pull/1934))
- consolidate required check forwarding into one matrix ([#1938](https://github.com/openai/codex-security/pull/1938))
- refresh triage eval transport dependencies ([#1935](https://github.com/openai/codex-security/pull/1935))
- preserve required checks after pull request edits ([#1944](https://github.com/openai/codex-security/pull/1944))
- let reducers page inputs without code mode ([#1910](https://github.com/openai/codex-security/pull/1910))
- show scan usage timestamps and account allowance ([#1911](https://github.com/openai/codex-security/pull/1911))
- keep local action dependencies up to date ([#1961](https://github.com/openai/codex-security/pull/1961))
- distinguish file inventory from review progress ([#1960](https://github.com/openai/codex-security/pull/1960))
- omit excerpts for unknown diff target kinds ([#515](https://github.com/openai/codex-security/pull/515))

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

No additional migration steps are documented for this release.

<!-- release-section: upgrades:end -->
