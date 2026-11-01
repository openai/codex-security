# Import Endor Labs findings

Import findings from one Endor Labs project and scan context. Native Finding
JSON preserves the scanned commit, severity, and dependency and location
details reported by Endor.

## Quick start

Authenticate `endorctl` for the namespace that owns the project. Confirm the
project and context correspond to the checkout. The importer retains the
project UUID but does not look up its repository. Run these commands from the
checkout root, replacing `YOUR_NAMESPACE` and `PROJECT_UUID` in both commands.

```sh
out=$(mktemp -d) &&
  endorctl api list --resource Finding --namespace "YOUR_NAMESPACE" \
    --filter 'context.type==CONTEXT_TYPE_MAIN and spec.project_uuid=="PROJECT_UUID"' \
    --list-all --output-type json > "$out/endor-findings.json"
```

After the export succeeds, keep the file and preview it in the same shell.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings "$out/endor-findings.json" \
  --to local --repository . --provider endor \
  --source-key "YOUR_NAMESPACE/PROJECT_UUID/main" --dry-run --format json
```

The filter selects default-branch findings. For another context, change both
the filter and source key. Keep `--list-all` and omit `--field-mask` to export
complete Finding objects.

## Import and verify

Check the destination, ready records, and exclusions. Rerun only the
`publish findings` command without `--dry-run` to import that saved file.
Local import needs no Cloud login or model call. Read back the stored evidence.

```sh
codex-security findings imported . --format json
```

For Cloud, replace `--to local --repository .` with
`--to cloud --repository CLOUD_REPOSITORY_ID` for the connected repository.
Review the Cloud preview before confirming. If the repository is renamed, a
saved submission can resume against the same Cloud repository ID.

## Reference

### Native Finding JSON

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
repository URLs must match the selected repository. For local imports, they must match a comparable
configured Git remote when one is available.

Both formats identify a record by finding UUID within the repository and source
key. Reimporting replaces its evidence snapshot. Importing SARIF after native
JSON can clear commit, package, and advisory details and make severity unknown.
For ongoing imports use native JSON and the same source key. Local records
omitted from later imports remain stored.

Upgrades, reachability, and dismissals remain Endor’s claims. Imported findings
start unassessed and are separate from completed scans.
