<!-- release-version: 0.1.18 -->

## Highlights

- Attribute API-key scans to the originating end user with the CLI's
  `--safety-identifier` option or the SDK's `safetyIdentifier` option. Use a
  stable, privacy-preserving identifier rather than personal data. This
  requires a Codex runtime with native safety identifier support; the bundled
  runtime does not yet support it, so select a compatible build with
  `CODEX_CLI_PATH`. See
  [Safety ID setup and runtime requirements](https://github.com/openai/codex-security/blob/npm-v0.1.18/sdk/typescript/README.md#attribute-scans-to-end-users).
- Preserve accepted findings and partial artifacts when Deep Scan fails, is
  canceled, or is interrupted. Recovered results keep their terminal state and
  incomplete coverage explicit rather than appearing complete.

The categorized list below contains the individual changes.
