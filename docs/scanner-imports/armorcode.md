# Import ArmorCode findings

Import the JSON response from ArmorCode's `POST /api/findings` endpoint. Keep
the saved response in a private directory outside the checkout. The reader
accepts the API's `data.findings` envelope, as well as a top-level `findings`
array for exported reports. Each finding needs a stable numeric or string `id`
and a `title`. Reuse the same source key for repeat imports from the same
ArmorCode organization and finding selection.

For example, use your ArmorCode host and API key to save the API response:

```sh
curl -X POST "https://$HOST_URL/api/findings" \
  -H 'accept: application/json' \
  -H "authorization: Bearer $ARMORCODE_API_KEY" \
  -H 'content-type: application/json' \
  --data '{
    "filters": {
      "severity": ["Critical", "High"],
      "status": ["OPEN", "CONFIRMED", "TRIAGE", "IN_PROGRESS"]
    },
    "maxSize": 100
  }' > armorcode-findings.json
```

Preview locally before saving or publishing:

```sh
codex-security publish findings armorcode-export.json \
  --to local --repository . --provider armorcode \
  --source-key ORG_ID/APP_ID --dry-run --format json
```

The import preserves the complete source record as evidence. It maps severity,
description, mitigation, finding URLs, CVE identifiers, file path and line
number, and the last-updated timestamp when present. The evidence URL uses the
source scanner's `url` when present; ArmorCode's `findingUrl` remains in the
retained source record. Findings whose `scanType` contains `SAST` also expose
their source status, scanner origin and verdict, rule IDs, CWE IDs, and
mitigation as typed SAST details. A record's `sourceRepositoryUrl`,
`repositoryUrl`, or repository URL is projected when present. Unknown severities are retained as `unknown`;
an ArmorCode status does not become a Codex assessment.
Repeated IDs in a single input are excluded as ambiguous. Repeat imports with
the same provider, source key and finding ID update the existing observation.

Review the preview's exclusions and confirm the repository and source key before
saving locally or publishing to Codex Security Cloud. API filters determine
which records the response contains; records omitted from a later import remain
stored. Use the normalized field names above when an export uses different
field names.
