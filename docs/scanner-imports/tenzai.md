# Import Tenzai Test findings locally

Export findings from one Tenzai Test and import them into the local workbench
with `--provider tenzai --to local`. This reader does not support Cloud publication.
It accepts the JSON array returned by the Tenzai CLI's `--paginate` option, a
complete single-page `items` response, or one `tenzai finding get` response
for a native per-Test finding UUID (containing `testId`).
Incomplete pages are rejected; export all pages before selecting findings.
Application-level finding summaries, PDF reports and DOCX reports are not inputs
to this reader.

## Export and preview

Install the Tenzai CLI from your Tenzai workspace and sign in with
`tenzai auth login`. Select the application's Test in Tenzai and set
`TENZAI_APP_ID` and `TENZAI_TEST_ID` to its application and Test UUIDs. This
workflow reads an existing Test; it does not start a new one.

From the source checkout, save the export in a private directory outside it:

```sh
report_dir=$(mktemp -d "${TMPDIR:-/tmp}/tenzai.XXXXXX")
tenzai --output json --no-ui-links finding list \
  --app-id "$TENZAI_APP_ID" --test-id "$TENZAI_TEST_ID" --paginate \
  > "$report_dir/tenzai-findings.json"
```

Verify in Tenzai that every selected finding belongs to this source repository.
A Test can cover multiple sources. Select only the findings for the checkout
you intend to assess. Set `SOURCE_REPOSITORY_URL` to its verified HTTP(S) clone
URL; it must match a configured Git fetch remote of the selected checkout.
The native export does not independently identify that repository.

```sh
codex-security publish findings "$report_dir/tenzai-findings.json" \
  --provider tenzai --to local --repository . \
  --source-repository-url "$SOURCE_REPOSITORY_URL" \
  --source-key "$TENZAI_APP_ID/$TENZAI_TEST_ID" --dry-run --format json
```

Review the repository, source key, findings and exclusions. Remove `--dry-run`
to save, then run `codex-security findings imported . --format json` to read
back the stored evidence. No Tenzai credentials are needed to import a saved
file. See the [synthetic export](../../examples/tenzai/findings.json) for an
example of the accepted JSON.

## Identity and evidence

Each record uses the native finding `id` UUID within the source key. Display IDs
such as `FIND-1` are retained as evidence, not used as occurrence IDs. Reuse the
same application/Test source key for later exports of that Test. A repeat import
updates matching evidence; omitted findings remain stored. A report containing
multiple Tests or conflicting application IDs is rejected. Duplicate finding
IDs are excluded rather than choosing one row.

The reader maps `name`, reported severity, description, impact, code-fix
remediation, CVE and Test ID. Informational findings stay informational; missing
or unrecognized severity stays unknown. The complete native record is retained
under `evidence.source_data.finding`, including status, CWE, CVSS, endpoints,
reproduction steps, verified claims, evidence and code references.

Code references use Tenzai's source-bundle paths, which can include numbered
source prefixes. They remain in the native evidence; the reader does not strip
prefixes or claim checkout-relative locations or a single code revision.
It also does not label runtime findings as SAST. Tenzai status and evidence do
not set a Codex verdict: new local assessments start as `not_assessed`.
