<!-- release-version: 0.1.33 -->

<!-- release-section: highlights:start -->
## Highlights

- restore omitted target and scope metadata ([#1083](https://github.com/openai/codex-security/pull/1083))
- prevent scans from failing before custom validation ([#1085](https://github.com/openai/codex-security/pull/1085))
- include C++ headers in scan inventories ([#1079](https://github.com/openai/codex-security/pull/1079))
- skip already tagged unchanged versions ([#1091](https://github.com/openai/codex-security/pull/1091))
- upgrade Codex CLI and SDK to 0.159.0 ([#1088](https://github.com/openai/codex-security/pull/1088))
- upgrade OpenCode SDK to 1.18.32 ([#1090](https://github.com/openai/codex-security/pull/1090))
- fall back on Python AST recursion errors ([#1094](https://github.com/openai/codex-security/pull/1094))
- probe the Codex sandbox before starting a billed scan ([#1084](https://github.com/openai/codex-security/pull/1084))
- preserve source excerpt line numbering ([#1098](https://github.com/openai/codex-security/pull/1098))
- bump Codex CLI and SDK to 0.159.2 ([#1100](https://github.com/openai/codex-security/pull/1100))
- update Linear SDK, smol-toml, and Prettier ([#1101](https://github.com/openai/codex-security/pull/1101))
- exclude nested Git metadata from scan inventories ([#1099](https://github.com/openai/codex-security/pull/1099))
- bump fast-uri from 3.1.7 to 3.1.8 in /sdk/typescript ([#1106](https://github.com/openai/codex-security/pull/1106))
- bump fast-uri from 3.1.7 to 3.1.8 in /plugins/codex-security/mcp-app ([#1109](https://github.com/openai/codex-security/pull/1109))
- bump brace-expansion from 5.0.9 to 5.0.12 in /sdk/typescript ([#1107](https://github.com/openai/codex-security/pull/1107))
- bump ip-address from 10.7.0 to 10.7.2 in /plugins/codex-security/mcp-app ([#1108](https://github.com/openai/codex-security/pull/1108))
- reuse unchanged plugins across concurrent scans ([#1082](https://github.com/openai/codex-security/pull/1082))
- deduplicate tracked ignored files in scoped inventories ([#1077](https://github.com/openai/codex-security/pull/1077))
- bump Codex SDK and CLI to 0.159.3 ([#1170](https://github.com/openai/codex-security/pull/1170))
- bump MCP SDK to 1.30.1 in MCP app and evals ([#1171](https://github.com/openai/codex-security/pull/1171))
- support custom inference providers in patch commands ([#1131](https://github.com/openai/codex-security/pull/1131))
- allow opting out of log redaction ([#1176](https://github.com/openai/codex-security/pull/1176))
- organize and clarify command help ([#1142](https://github.com/openai/codex-security/pull/1142))
- reuse native builds across package and container checks ([#1130](https://github.com/openai/codex-security/pull/1130))
- smoke test published npm installs across supported platforms ([#1129](https://github.com/openai/codex-security/pull/1129))
- require workflow checks and production dependency audits ([#1128](https://github.com/openai/codex-security/pull/1128))
- attribute records reviews to participating observations ([#1145](https://github.com/openai/codex-security/pull/1145))
- restore GPT-5.6 Sol as the default model ([#1181](https://github.com/openai/codex-security/pull/1181))
- share model options across commands ([#1143](https://github.com/openai/codex-security/pull/1143))
- add Invoice Desk fixture and OpenAI PR scans ([#1144](https://github.com/openai/codex-security/pull/1144))
- prohibit reintroducing CLI secret and log redaction ([#1178](https://github.com/openai/codex-security/pull/1178))
- preserve diagnostic text without secret redaction ([#1179](https://github.com/openai/codex-security/pull/1179))
- scope sample behavior concurrency to each revision ([#1182](https://github.com/openai/codex-security/pull/1182))
- update Codex for per-turn Cyber selection ([#1184](https://github.com/openai/codex-security/pull/1184))
- add wide Windows candidate file operations ([#836](https://github.com/openai/codex-security/pull/836))
- port candidate normalization to TypeScript ([#837](https://github.com/openai/codex-security/pull/837))
- improve authentication and Blue/Red support ([#1188](https://github.com/openai/codex-security/pull/1188))
- bump @linear/sdk from 95.2.0 to 96.0.0 in /sdk/typescript ([#1191](https://github.com/openai/codex-security/pull/1191))
- bump ruff from 0.16.8 to 0.16.9 in /plugins/codex-security ([#1189](https://github.com/openai/codex-security/pull/1189))
<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->
## Upgrade notes

Review compatibility and document any required migration steps before releasing.
<!-- release-section: upgrades:end -->
