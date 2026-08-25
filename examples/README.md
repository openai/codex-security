# Examples

These files are repository examples and are not included in the published
`@openai/codex-security` npm package.

- [`findings.csv`](findings.csv) is a header-only template for publishing
  findings from CSV. Copy it, add one finding per row, and validate the file
  locally before publishing:

  ```bash
  npx @openai/codex-security publish scan --to cloud \
    --csv /path/to/findings.csv --dry-run --json
  ```

  See [Publish findings to Cloud](../sdk/typescript/README.md#publish-findings-to-cloud)
  for the required columns and input rules.

- [`custom-validation/`](custom-validation/) is a local demo of a custom
  validation workflow against a deliberately vulnerable synthetic service.
  Follow its [README](custom-validation/README.md) to run it.
