# Endor Labs findings

Use authenticated `endorctl` for one verified project and context. Omit `--field-mask` to keep complete native Finding objects. Replace `/path/to/private/reports` with a private directory outside the checkout.

```sh
out=$(mktemp -d "/path/to/private/reports/endor.XXXXXX") &&
  endorctl api list --resource Finding --namespace "YOUR_NAMESPACE" \
    --filter 'context.type==CONTEXT_TYPE_MAIN and spec.project_uuid=="PROJECT_UUID"' \
    --list-all --output-type json > "$out/findings.tmp" &&
  mv "$out/findings.tmp" "$out/endor-findings.json" &&
  printf '%s\n' "$out/endor-findings.json"
```

Preview the completed file with `--provider endor` and a stable source key such as `YOUR_NAMESPACE/PROJECT_UUID/main`. Match the project to the destination repository. For another branch or scan context, change the filter and use a distinct source key. The [official Endor Labs Agent Kit for Codex](https://github.com/endorlabs/ai-plugins/tree/main/plugins/codex/endor-labs-agent-kit) can help with setup and investigation; its summaries, counts and field-masked results do not replace complete Finding objects. The [CLI API](https://docs.endorlabs.com/developers-api/cli/commands/api) supplies the export. The importer reads that saved file; it does not maintain an Endor API connection or write changes back to Endor.

Native JSON retains severity, scanned commit, package and advisory data, and primary SAST/AI SAST locations. Existing self-contained endorctl SARIF is a lossy compatibility format that retains finding UUIDs and links; unavailable severity or revisions stay unknown. Both formats use the Endor UUID within the selected repository and source key as identity. Importing SARIF after native JSON updates the same record by replacing its evidence snapshot, not merging it: native detail absent from SARIF is removed from that snapshot. Use native JSON consistently for ongoing imports. Keep the original evidence and inspect exclusions. Imported records remain unassessed source evidence. Follow the [local](../SKILL.md#import-locally) or [Cloud](../SKILL.md#publish-to-cloud) workflow for the chosen destination.
