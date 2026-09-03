<!-- release-version: 0.2.0 -->

## Highlights

- Use one Codex Security release version across the CLI, TypeScript SDK,
  bundled plugin, and MCP server. Every product release now advances the plugin
  version so cached plugin installations recognize the upgrade. The findings
  service and dashboards continue to ship in the same package and image.
- Require container releases to use the same source commit as the matching npm
  release tag. An identical package version on a later commit no longer counts
  as the same release.
- Recognize BOM-marked UTF-16 source files and PowerShell module and data files
  in scan inventories.
- Improve Windows handling of long Codex executable paths, case-only renames,
  and dedupe environment settings.

## Upgrade notes

- SDK consumers using a range such as `^0.1.24` must explicitly update to
  `^0.2.0`. Existing CLI commands and public SDK version fields remain available.
- Version alignment does not change artifact schemas or database migration
  versions. Saved scans keep their original producer versions, and custom
  plugins continue to report their own versions. Codex runtime dependencies and
  external plugin catalogs retain their independent versions.
- Publish a container from `container-v0.2.0` at the same commit as
  `npm-v0.2.0`. Manual publication from `main` works only while `main` points to
  that release commit. See
  [container publishing](https://github.com/openai/codex-security/blob/npm-v0.2.0/docker/README.md#publishing).

The categorized list below contains the individual changes.
