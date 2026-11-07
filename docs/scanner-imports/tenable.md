# Import Tenable One code repository findings locally

Select a **Code Repository** in Tenable Exposure Management Inventory. Copy its asset UUID and the finding UUIDs you want. Verify the HTTPS clone URL independently in your source control system and use a checkout with a matching Git fetch remote. [Tenable asset details](https://docs.tenable.com/exposure-management/Content/inventory/asset-details.htm)

## Export the selection

The [download and CSV capture helpers](../../examples/tenable-one/) are part of the Codex Security source repository. Run the Python commands from that repository's root. Set `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY` for a tenant with Inventory Export API access on `cloud.tenable.com`, or [use existing CSV exports](#from-existing-csv-exports). Keep the reports outside both the source repository and the checkout whose findings you are importing.

```sh
umask 077
reports=/private/path/tenable-export
mkdir -p "$reports"
asset_id=SELECTED_ASSET_UUID
repository_url=https://github.com/example/project
checkout=/path/to/project
python3 examples/tenable-one/download.py --asset-id "$asset_id" \
  --finding-id SELECTED_FINDING_UUID --repository-url "$repository_url" \
  --output "$reports/selection.json"
```

Repeat `--finding-id` for additional findings. The helper requests separate asset and finding exports, polls for completion, downloads the CSV chunks, and checks each finding against the selected asset. [Export assets](https://developer.tenable.com/reference/inventory-export-assets) · [Export findings](https://developer.tenable.com/reference/inventory-export-findings) · [Export status](https://developer.tenable.com/reference/inventory-export-status) · [Download chunks](https://developer.tenable.com/reference/inventory-export-download)

### From existing CSV exports

Use uncompressed CSVs with machine headers (`use_readable_name=false`). The asset export needs `asset_id,asset_class,asset_name`. The findings export needs `asset_id,finding_id,finding_name,finding_severity,state` for the selected repository. The default title header `finding_detection_name` is also accepted. Include `finding_description` and `finding_solution` when available. [Asset properties](https://developer.tenable.com/reference/inventory-asset-properties-list) · [Finding properties](https://developer.tenable.com/reference/inventory-finding-properties-list)

```sh
python3 examples/tenable-one/capture.py --assets "$reports/assets.csv" \
  --findings "$reports/findings.csv" --asset-id "$asset_id" \
  --repository-url "$repository_url" --output "$reports/selection.json"
```

Pass additional finding chunks after `--findings`. To retain file locations, add `--path-column file_path --line-column code_line_number`, substituting your tenant's column names. A path is repository-relative. A zero line number leaves the line unspecified.

## Preview, save and read back

Use the [installed CLI](../../README.md#quick-start) to preview the selection for the local checkout. Choose a stable tenant alias and keep it with the asset UUID in `--source-key` on repeat imports.

```sh
codex-security publish findings "$reports/selection.json" --provider tenable \
  --to local --repository "$checkout" --source-repository-url "$repository_url" \
  --source-key "TENANT_ALIAS/$asset_id" --dry-run --format json
```

Check the preview against your selection. Remove `--dry-run` and confirm to save, then run `codex-security findings imported "$checkout" --format json`. The saved record retains Tenable's exact finding ID and state. Its Codex assessment starts as `not_assessed`. With the same source key, changed evidence updates that record and identical evidence preserves its version.
