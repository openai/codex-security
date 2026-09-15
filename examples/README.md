# Examples

Examples and templates for using Codex Security:

- [Findings CSV template](findings.csv): a header-only template for
  `codex-security publish scan --to cloud --csv PATH`. Copy it, add one finding
  per row, and validate the file before publishing:

  ```bash
  npx @openai/codex-security publish scan --to cloud \
    --csv /path/to/findings.csv --dry-run --json
  ```

  See [Publish findings to Cloud](../sdk/typescript/README.md#publish-findings-to-cloud)
  for the required columns and input rules.

- [Custom validation demo](custom-validation/README.md): run a scan with a custom
  validation script against a deliberately vulnerable API using synthetic data.
  Follow the demo's setup instructions, and do not deploy the example app.

## npm package

This top-level `examples/` directory is available in the repository only; it is
not included in the `@openai/codex-security` npm package. The package is built
from [`sdk/typescript`](../sdk/typescript/package.json), whose `files` list
includes only the CLI launcher, compiled SDK, bundled plugin, license, and
package README. The package check rejects files outside its expected contents.

The bundled plugin's own example artifacts are separate and remain part of the
package.
