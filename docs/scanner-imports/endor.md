# Import Endor Labs findings

Import findings from one Endor Labs project and scan context. Native Finding
JSON preserves the scanned commit, severity, and dependency and location
details reported by Endor.

## Quick start

[Enable external imports](README.md#preview-a-report) and
[export the native findings](#native-finding-json) from the intended project
and context. From the matching checkout root, preview the saved file. Replace
the file path, namespace, and project UUID.

```sh
codex-security publish findings /private/path/endor-findings.json \
  --to local --repository . --provider endor \
  --source-key "YOUR_NAMESPACE/PROJECT_UUID/main" --dry-run --format json
```

## Import and verify

Confirm the project and context belong to this repository. The importer retains
the project UUID but does not look up its Git repository.
[Save or publish and verify](README.md#save-or-publish-and-verify) using the same
source key for later exports from this context.

## Reference

### Native Finding JSON

Authenticate `endorctl` for the namespace that owns the project. Replace
`YOUR_NAMESPACE` and `PROJECT_UUID`, then export the findings.

```sh
out=$(mktemp -d) &&
  endorctl api list --resource Finding --namespace "YOUR_NAMESPACE" \
    --filter 'context.type==CONTEXT_TYPE_MAIN and spec.project_uuid=="PROJECT_UUID"' \
    --list-all --output-type json > "$out/endor-findings.tmp" &&
  mv "$out/endor-findings.tmp" "$out/endor-findings.json"
```

The filter selects default-branch findings. For another context, change both
the filter and source key. Keep `--list-all` and omit `--field-mask` to export
complete Finding objects. The saved file is `$out/endor-findings.json`.

The importer accepts a single Finding, an array, or a `ListFindingsResponse`
containing `list.objects`. An unfinished paginated response is rejected. Native
JSON retains the complete Finding and maps severity, dependency and advisory
details, scanned commit SHA, and primary SAST or AI SAST locations when
available. See the [Endor CLI API](https://docs.endorlabs.com/developers-api/cli/commands/api)
and [Finding model](https://github.com/endorlabs/endorlabs-sdk/blob/8a41756890c2dee3bb089fee881cae4f2adbde03/src/endorlabs/generated/models/finding_service.py).

The [Endor Labs Agent Kit for Codex](https://github.com/endorlabs/ai-plugins/tree/main/plugins/codex/endor-labs-agent-kit)
can help with setup or investigation. Findings Browser summaries, counts, and
field-masked results omit fields needed for import. Codex Security reads the
saved export offline. It does not change findings in Endor.

### SARIF and repeat imports

Self-contained `endorctl` SARIF 2.1.0 reports preserve finding UUIDs, links,
direct repository paths, and reported SAST or Secrets lines. Native severity
and scanned revision are unavailable. Diagnostic levels, CVSS, and indexed or
base-relative artifact references stay in the original evidence. Unrelated run
artifact inventories are omitted. For a new Cloud submission, declared
repository URLs must match the selected repository. For local imports, they
must match a comparable configured Git remote when one is available.

Both formats identify a record by finding UUID within the repository and source
key. Reimporting replaces its evidence snapshot. Importing SARIF after native
JSON can clear commit, package, and advisory details and make severity unknown.
For ongoing imports use native JSON and the same source key. Local records
omitted from later imports remain stored.

Upgrades, reachability, and dismissals remain Endor’s claims. Imported findings
start unassessed and are separate from completed scans.
