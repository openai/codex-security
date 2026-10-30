# Import Endor Labs findings

Vendor finding import and readback require `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1`.
See the [opt-in instructions](../../sdk/typescript/docs/cli.md#import-vendor-findings-locally)
and [how saved scanner reports map to imported evidence](schema-guide.md).

Use authenticated `endorctl` to export complete native Finding JSON through the
[official CLI API](https://docs.endorlabs.com/developers-api/cli/commands/api).
Scope the export to one project and context, omit `--field-mask`, and use
`--list-all` to fetch every page. Replace the namespace and project UUID below
to select the project's default-branch findings:

```sh
endorctl api list --resource Finding --namespace "YOUR_NAMESPACE" \
  --filter 'context.type==CONTEXT_TYPE_MAIN and spec.project_uuid=="PROJECT_UUID"' \
  --list-all --output-type json > endor-findings.json

codex-security publish findings endor-findings.json --to local \
  --provider endor --repository ./project \
  --source-key "YOUR_NAMESPACE/PROJECT_UUID/main" --dry-run
```

Use `--to local` with a local repository path to store unassessed source evidence
without a Cloud login or model call. After reviewing the preview, remove
`--dry-run` to confirm the import. Read the stored records with
`codex-security findings imported ./project --format json`.

To publish the same export to Cloud, select its connected repository instead:

```sh
codex-security publish findings endor-findings.json --to cloud \
  --provider endor --repository "CLOUD_REPOSITORY_ID" \
  --source-key "YOUR_NAMESPACE/PROJECT_UUID/main" --dry-run
```

Confirm that the selected Endor project and context correspond to the destination
repository. Native JSON retains the project UUID, but the importer does not look
it up to verify that association. For another branch or scan context, change the
Endor filter and use a distinct, stable source key. An unfinished paginated
response is rejected by the importer. Remove `--dry-run` to review and confirm
the upload.

The official [Endor Labs Agent Kit for Codex](https://github.com/endorlabs/ai-plugins/tree/main/plugins/codex/endor-labs-agent-kit)
can help with setup and interactive investigation. Its Findings Browser summaries,
counts and field-masked results do not replace the complete Finding objects used
here. `endorctl` reads the Endor API; the Codex Security importer reads the saved
export. It does not establish a persistent API connection or write changes back
to Endor.

Native JSON is the preferred import format: it preserves Endor severity,
dependency and advisory details, the scanned commit SHA, primary SAST/AI SAST
locations, and the complete original Finding. The importer accepts a single
Finding, an array, or a `ListFindingsResponse` containing `list.objects`. Mapping
follows Endor's public [Finding model](https://github.com/endorlabs/endorlabs-sdk/blob/8a41756890c2dee3bb089fee881cae4f2adbde03/src/endorlabs/generated/models/finding_service.py).

Existing self-contained `endorctl` SARIF 2.1.0 reports are accepted as a lossy
compatibility format. The importer retains finding UUIDs and links but does not
infer native Endor severity or scanned revisions from SARIF. Diagnostic levels
and CVSS stay in the original evidence;
displayed severity remains unknown. Direct repository paths and reported SAST or
Secrets lines are mapped. Indexed or base-relative artifact references remain in
the original evidence. Run artifact inventories that are unrelated to the selected
finding are omitted from its evidence. Declared SARIF repository URLs must
match the selected Cloud repository for a new upload. For local imports, those
URLs must match a configured Git remote when the checkout has remotes.

Both formats use the native finding UUID as identity within the selected
repository and source key. Keep the source key stable across repeated imports.
Importing the same UUID from SARIF after native JSON updates the same source
record: it replaces the evidence snapshot rather than merging it. Severity can
become unknown, and commit, package, advisory and other native detail absent from
SARIF is no longer present in that snapshot. Importing native JSON again replaces
it with the richer native evidence. Use native JSON consistently for ongoing
imports.

Recommended upgrades, reachability, dismissals and other Endor assessments remain
source claims. Local records remain unassessed and separate from completed scans;
imports do not automatically investigate or patch them. Records omitted from a
later local import remain stored. Saved Cloud requests retain their destination
repository ID when resumed.

The adapter can be tested with synthetic records and the public SARIF sample.
Verifying acquisition requires an authenticated Endor namespace with findings.
Verifying Cloud publication also requires a Cloud environment that supports
finding imports.
