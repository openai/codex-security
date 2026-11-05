# Import Tenable One findings for one code repository

Use the experimental `tenable` reader in this checkout to import inventory
findings for one Tenable Exposure Management Code Repository asset into the
local Codex Security workbench. Cloud publication and Nessus scan reports are
outside the scope of this reader.

## Choose the repository and findings

In Tenable Exposure Management, open **Inventory → Assets** and select the
**Code Repository** asset. Record its asset UUID and the finding IDs you want
from that asset's details. Independently verify the asset's canonical HTTPS
clone URL in your source control system or connector configuration. A Tenable
asset or scanner profile link identifies a different resource. [Inventory assets](https://docs.tenable.com/exposure-management/Content/inventory/assets.htm) · [Asset details](https://docs.tenable.com/exposure-management/Content/inventory/asset-details.htm)

Run the examples from the Codex Security source tree. Substitute a private
output directory outside both checkouts, your tenant alias, the selected IDs,
the verified clone URL, and the destination checkout.

```sh
umask 077
reports=/private/path/tenable-export
mkdir -p "$reports"
asset_id=SELECTED_ASSET_UUID
finding_id=SELECTED_FINDING_UUID
repository_url=https://github.com/example/project
checkout=/path/to/project
source_key="TENANT_ALIAS/$asset_id"
```

## Download selected findings

Use Tenable API credentials for `cloud.tenable.com` with inventory export
access. Supply them through `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY`.
The download helper exports the chosen asset and findings with exact ID
filters. It waits for the exports, collects the CSV chunks, and writes a local
selection. Repeat `--finding-id` for each additional finding UUID.

```sh
python3 examples/tenable-one/download.py \
  --asset-id "$asset_id" --finding-id "$finding_id" \
  --repository-url "$repository_url" --output "$reports/selection.json"
```

The helper requests `finding_description`, `finding_solution`, `file_path`,
and `code_line_number`. If your tenant uses different keys or rejects those
properties, [capture a CSV export](#capture-from-csv-exports-instead) with
its available fields.

## Preview and save locally

Use a build of this checkout. After preparing the SDK dependencies and native
payloads, build the plugin and CLI. The Bash function invokes that exact build
for the rest of this session. [Source build setup](../../sdk/typescript/TESTING.md)

```bash
pnpm --dir sdk/typescript run build:plugin
pnpm --dir sdk/typescript run build
pilot_cli="$PWD/sdk/typescript/bin/codex-security.mjs"
codex-security() { node "$pilot_cli" "$@"; }
```

The destination must be a Git checkout with a configured fetch remote
matching the verified repository URL.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings "$reports/selection.json" --provider tenable \
  --to local --repository "$checkout" --source-repository-url "$repository_url" \
  --source-key "$source_key" --dry-run --format json
```

Compare the preview with the Tenable selection. Check the checkout, provider,
source key, exact finding IDs, severities, any file locations, and exclusions.
After review, run the same command without `--dry-run` and confirm. Read back
the saved findings using the checkout path shown in the preview.

```sh
codex-security findings imported "$checkout" --format json
```

In the saved records, compare `sourceFindingId` with the exact Tenable
`finding_id`, and `evidence.locations` with the reported path and line.
`evidence.source_data.finding.state` retains Tenable's state. The initial
Codex assessment is `not_assessed`.

For a repeat import, use the same checkout and `TENANT_ALIAS/ASSET_UUID` source
key. The CSV carries the asset UUID and finding ID. The operator supplies the
tenant alias, so choose a distinct, stable alias for each tenant. An identical
finding keeps its version. Changed evidence updates the record, and findings
omitted from a later selection stay in the workbench.

## Capture from CSV exports instead

1. Use a Tenable API client authenticated for this tenant with permission to
   read inventory properties and export the selected records. In the beta
   Inventory API, inspect `GET /api/v1/t1/inventory/assets/properties` and
   `GET /api/v1/t1/inventory/findings/properties`. Check the machine key,
   `filterable` flag and supported operators for each filter. The findings
   catalog can expose `asset_id` as a column while disabling it as a filter.
   [Asset properties](https://developer.tenable.com/reference/inventory-asset-properties-list) · [Finding properties](https://developer.tenable.com/reference/inventory-finding-properties-list)
2. Start two inventory exports using the requests below. In both, set the
   query parameters `file_format=CSV`, `use_readable_name=false`, and
   `compress=false`. Replace the example IDs with the ones you selected.

   | Export               | Method and path                             | `properties` query parameter                              | JSON body                                                                       |
   | -------------------- | ------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------- |
   | One repository asset | `POST /api/v1/t1/inventory/export/assets`   | `asset_id,asset_class,asset_name`                         | `{"filters":[{"property":"asset_id","operator":"=","value":["ASSET_UUID"]}]}`   |
   | One selected finding | `POST /api/v1/t1/inventory/export/findings` | `asset_id,finding_id,finding_name,finding_severity,state` | `{"filters":[{"property":"finding_id","operator":"=","value":["FINDING_ID"]}]}` |

   Repeat the findings request for each additional selected finding. If your
   findings property catalog allows an equality filter on `asset_id`, you can
   export findings for the whole selected repository by sending the asset
   request's filter in the findings request. Each row must carry the selected
   UUID. The default export uses `finding_detection_name` for the title.
   Requesting `finding_name` explicitly returns that header. [Export assets](https://developer.tenable.com/reference/inventory-export-assets) · [Export findings](https://developer.tenable.com/reference/inventory-export-findings)

   To carry more evidence, add `finding_description` and `finding_solution` if
   available. For source locations, identify the keys for Code File Path and
   Code Line Number in your tenant's finding properties, for example
   `file_path` and `code_line_number`. Include those keys in every findings
   export. Check that paths refer to files relative to this repository and that
   lines are one-based. If Tenable supplies zero, the capture keeps the finding
   and any file path and omits the line number.
   [Finding properties](https://developer.tenable.com/reference/inventory-finding-properties-list)

3. For each returned `export_id`, poll
   `GET /api/v1/t1/inventory/export/{export_id}/status` until `FINISHED`. For
   each ID in `chunks_available`, download
   `GET /api/v1/t1/inventory/export/{export_id}/download/{chunk_id}`. If this
   request returns HTTP 204, wait and retry the same chunk. Save
   the single-asset CSV as `assets.csv` and each finding chunk as a separate
   CSV in a private directory outside both checkouts. Each chunk has its own
   header. Check that every requested finding ID appears exactly once across
   the finished downloads. [Export status](https://developer.tenable.com/reference/inventory-export-status) · [Download a chunk](https://developer.tenable.com/reference/inventory-export-download)

Convert the downloaded CSVs into a selection using the same asset UUID and URL.

```sh
python3 examples/tenable-one/capture.py \
  --assets "$reports/assets.csv" --findings "$reports/findings.csv" \
  --asset-id "$asset_id" --repository-url "$repository_url" \
  --output "$reports/selection.json"
```

Put additional chunk paths after `--findings` and before `--asset-id`.
If the download includes verified location columns, add
`--path-column file_path --line-column code_line_number`, substituting the
actual header keys. Omit these options when locations are unavailable. Choose a
new output filename for each capture, then [preview and save it locally](#preview-and-save-locally).
