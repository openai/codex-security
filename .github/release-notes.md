<!-- release-version: 0.1.17 -->

## Highlights

- Split a large repository into explicit or planned components, scan each one
  independently, and produce a combined coverage report. See
  [component scans](https://github.com/openai/codex-security/blob/npm-v0.1.17/sdk/typescript/README.md#scan-project-components).
- Supply validation setup, test, and cleanup steps for standard and diff scans.
  See
  [custom validation](https://github.com/openai/codex-security/blob/npm-v0.1.17/sdk/typescript/README.md#custom-validation).
- Recheck a saved finding without starting another scan. See
  [finding validation](https://github.com/openai/codex-security/blob/npm-v0.1.17/sdk/typescript/README.md#validate-an-existing-finding).

This release also improves Windows path and process handling, scan result
reporting, credential lock recovery, and Deep Scan recovery. The categorized
list below contains the individual changes.
