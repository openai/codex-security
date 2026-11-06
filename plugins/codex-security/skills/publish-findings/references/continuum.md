# AWS Continuum code findings

Use `--provider continuum` and `--source-repository-url` for an AWS Continuum for Code Vulnerabilities export. Verify which repository owns each selected finding. Use `aws continuum get-code-finding` for a selected ID, or `list-code-findings` with automatic pagination when every row belongs to the requested repository. Reuse the same source key for that environment and repository. [Continuum import guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/continuum.md)
