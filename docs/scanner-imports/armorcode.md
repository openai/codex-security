# Import ArmorCode findings

Import a saved response from ArmorCode's `POST /api/findings` endpoint into the
local workbench. Cloud publication of ArmorCode findings is unverified. The reader
accepts the API's `data.findings` envelope, as well as a top-level `findings`
array for exported reports. Each finding needs a stable numeric or string `id`
and a `title`. Reuse the same source key for repeat imports from the same
ArmorCode organization and finding selection.

Choose SAST findings for one repository in ArmorCode. Set `ARMORCODE_QUERY` to
the path of the JSON request body for that selection. Severity and status
filters alone can return findings from multiple repositories. From the checkout
root, save the response in a private temporary directory outside the checkout.

```sh
report_dir=$(mktemp -d "${TMPDIR:-/tmp}/armorcode.XXXXXX")
curl --fail-with-body -X POST "https://$HOST_URL/api/findings" \
  -H 'accept: application/json' \
  -H "authorization: Bearer $ARMORCODE_API_KEY" \
  -H 'content-type: application/json' \
  --data-binary "@$ARMORCODE_QUERY" > "$report_dir/armorcode-findings.json"
```

Preview the same file against the selected checkout.

```sh
codex-security publish findings "$report_dir/armorcode-findings.json" \
  --to local --repository . --provider armorcode \
  --source-key ORG_ID/APP_ID --dry-run --format json
```

If any SAST row omits its repository URL, verify the report's repository in
ArmorCode and add `--source-repository-url URL` to the command. The import
checks declared repository URLs against the checkout's configured remotes.
A conflicting repository in the report causes the import to fail.

The import preserves the complete source record as evidence. It maps severity,
description, mitigation, finding URLs, CVE identifiers, file path and line
number, and the last-updated timestamp when present. The evidence URL uses the
source scanner's `url` when present. ArmorCode's `findingUrl` remains in the
retained source record. Findings whose `scanType` contains `SAST` also expose
their source status, scanner origin and verdict, rule IDs, CWE IDs, and
mitigation as typed SAST details. A record's `sourceRepositoryUrl`,
`repositoryUrl`, or repository URL is projected when present. Unknown severities
are retained as `unknown`. The local assessment starts as `not_assessed`.
Repeated IDs in a single input are excluded as ambiguous. Repeat imports with
the same provider, source key and finding ID update the existing observation.

Review the preview's findings, exclusions, repository and source key. Remove
`--dry-run` to save the findings, then run
`codex-security findings imported . --format json` to read them back.
Records omitted from a later import remain stored. Use the normalized field
names above when an export uses different field names.
