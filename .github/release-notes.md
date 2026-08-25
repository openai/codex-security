<!-- release-version: 0.1.19 -->

## Highlights

- Publish one or more completed scans to Codex Security Cloud with
  `publish scan --to cloud`. Choose saved scans interactively or with
  repeatable `--scan` options, or use repeatable `--scan-dir` options for
  external artifacts. `--dry-run` validates and previews findings without
  uploading. Live uploads require a file-backed ChatGPT sign-in and an account
  authorized for Cloud publication. See
  [Cloud publication setup and behavior](https://github.com/openai/codex-security/blob/npm-v0.1.19/sdk/typescript/README.md#publish-multiple-completed-scans-to-cloud).
- Select a saved scan for Linear publication by scan ID, unique ID prefix, or
  `latest`; omitting the selector opens the interactive picker. See
  [Linear publication](https://github.com/openai/codex-security/blob/npm-v0.1.19/sdk/typescript/README.md#publish-completed-scans-to-linear).

The categorized list below contains the individual changes.
