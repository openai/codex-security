<!-- release-version: 0.1.27 -->

<!-- release-section: highlights:start -->
## Highlights

- port source and test report checks to TypeScript ([#768](https://github.com/openai/codex-security/pull/768))
- port custom validation to TypeScript ([#792](https://github.com/openai/codex-security/pull/792))
- add Python-free Unix OS primitives ([#794](https://github.com/openai/codex-security/pull/794))
- add Python-free Windows OS primitives ([#795](https://github.com/openai/codex-security/pull/795))
- add Python-free musl native artifacts ([#796](https://github.com/openai/codex-security/pull/796))
- bundle verified native runtime artifacts ([#797](https://github.com/openai/codex-security/pull/797))
- preserve Windows filenames in native helpers ([#798](https://github.com/openai/codex-security/pull/798))
- port security policy resolution to TypeScript ([#799](https://github.com/openai/codex-security/pull/799))
- budget package installation and verification ([#834](https://github.com/openai/codex-security/pull/834))
- open ready pull requests ([#833](https://github.com/openai/codex-security/pull/833))
- draft SECURITY.md for owner review ([#536](https://github.com/openai/codex-security/pull/536))
- resolve Windows Node to an absolute executable ([#788](https://github.com/openai/codex-security/pull/788))
- shard automatic component planning for large repositories ([#845](https://github.com/openai/codex-security/pull/845))
- import CSV and JSON findings as saved scans ([#850](https://github.com/openai/codex-security/pull/850))
- add a feedback command ([#854](https://github.com/openai/codex-security/pull/854))
- improve scan usage and cost reports ([#853](https://github.com/openai/codex-security/pull/853))
- recover interrupted Deep Scans and bulk campaigns ([#835](https://github.com/openai/codex-security/pull/835))
- reject owned plugin keys inside Codex profiles ([#861](https://github.com/openai/codex-security/pull/861))
- include CommonJS and TypeScript module extensions in scan inventories ([#859](https://github.com/openai/codex-security/pull/859))
- include workflow files in diff inventories ([#820](https://github.com/openai/codex-security/pull/820))
- accept a UTF-8 byte order mark in imported findings JSON ([#856](https://github.com/openai/codex-security/pull/856))
- authenticate deep workers with OpenAI API keys ([#870](https://github.com/openai/codex-security/pull/870))
- drop canonical document size limits that do not exist ([#868](https://github.com/openai/codex-security/pull/868))
- pin native Rust formatting edition ([#863](https://github.com/openai/codex-security/pull/863))
- detect a Linear URL contradiction over plain HTTP ([#867](https://github.com/openai/codex-security/pull/867))
- pipeline dedupe with configurable concurrency ([#852](https://github.com/openai/codex-security/pull/852))
- disable reasoning summaries by default for Bedrock ([#869](https://github.com/openai/codex-security/pull/869))
- reuse scan authentication for patch and validation ([#871](https://github.com/openai/codex-security/pull/871))
- bump smol-toml from 1.6.1 to 1.7.1 in /sdk/typescript ([#873](https://github.com/openai/codex-security/pull/873))
<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->
## Upgrade notes

Review compatibility and document any required migration steps before releasing.
<!-- release-section: upgrades:end -->
