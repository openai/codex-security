# Trivy dependency vulnerabilities

Use `--provider trivy` with a saved schema-v2 repository or filesystem report (JSON or gzip). Preview with a stable project/branch source key and `--trivy-scan-root` relative to the checkout (`.` for the whole checkout). Omit the root only when the report's Git metadata corroborates a remote repository scan. Check the source, package paths and exclusions before importing. Trivy's `fixed` status identifies an available upstream fix. [Trivy import guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/trivy.md)
