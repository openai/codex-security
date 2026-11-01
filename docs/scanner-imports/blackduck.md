# Import Black Duck SCA findings

Import vulnerable BOM components from one Black Duck SCA project version.
Verify in the scan configuration that the version represents the Git repository
you want to import into. A project name or component download URL cannot
establish that connection.

## Quick start

Use a read-only token to [export the BOM-6 collection](#export-the-bom-6-collection)
to a private file outside the checkout. From the verified checkout root, replace the
file path, Git URL and source key with values for your project version.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings /private/path/blackduck.json \
  --to local --repository . --provider blackduck \
  --source-repository-url https://github.com/example/project \
  --source-key blackduck/deployment-alias/project-id/version-id \
  --dry-run --format json
```

## Import and verify

Check the source, destination, and excluded rows. Remove `--dry-run` to import
the ready records, then read the stored evidence.

```sh
codex-security findings imported . --format json
```

Reuse the same source key for that deployment, project, and version. A later
export updates matching occurrences and leaves omitted occurrences in place.

For Cloud, replace `--to local --repository .` with
`--to cloud --repository CLOUD_REPOSITORY_ID` on a deployment that accepts
`blackduck`. Preview again before confirming. Cloud compares declared and
retained source repository URLs with the authorized GitHub repository. Local
import compares them with the checkout’s Git remotes when comparable remotes
exist. Importing a saved report locally requires neither a Black Duck nor a
Cloud login.

If a Cloud upload is interrupted, follow the
[Cloud retry procedure](schema-guide.md#retry-a-cloud-submission).

## Reference

### Identity and evidence

Each occurrence is identified by its project version, component version,
origin, advisory source, and advisory name. Package URLs and origin coordinates
supply the package identity. The `advisory_ids` field preserves
`vulnerabilityName` and any distinct `relatedVulnerability` verbatim, including
Black Duck resource URLs. The original row retains its CWE, matched-files link,
and remediation status. Imported records start unassessed. The importer does
not infer a fix, Git revision, or source location. Aggregate product BOMs,
image-only scans, license violations, and global advisory catalogs are outside
this import.

For SDK imports, select the `blackduck` provider when replaying retained BOM
records. Reader-supplied repository references must agree with the repository
on local findings. Opaque IDs and caller-authored text alone cannot establish
repository ownership.

### Export the BOM-6 collection

Request the project version’s `vulnerable-components` relation with media type
`application/vnd.blackducksoftware.bill-of-materials-6+json`. The importer
requires BOM-6. If the deployment only serves BOM-8 or another inventory format,
it cannot supply this collection.

Install the vendor’s `blackduck` Python client in a trusted virtual environment
outside the checkout. Set `BLACKDUCK_URL` to the deployment’s HTTPS URL,
`BLACKDUCK_TOKEN` to the read-only token, and `BLACKDUCK_PROJECT_ID` and
`BLACKDUCK_VERSION_ID` to their UUIDs. Keep redirects disabled for the client
session, including the token exchange.

Save the script outside the checkout and run it with
`/path/to/venv/bin/python -I /private/path/export.py` to keep checkout modules
and `PYTHONPATH` off the import path. Redirect stdout to a private temporary file
and rename it to `blackduck.json` after the script succeeds.

```python
import json
import os
from hashlib import sha256
from urllib.parse import parse_qs, urlsplit
from uuid import UUID
from blackduck import Client

base = os.environ["BLACKDUCK_URL"].rstrip("/")
parts = urlsplit(base)
if (parts.scheme != "https" or not parts.hostname or parts.username is not None
        or parts.password is not None or parts.query or parts.fragment):
    raise ValueError("Use your trusted HTTPS Black Duck URL")
project = UUID(os.environ["BLACKDUCK_PROJECT_ID"])
version = UUID(os.environ["BLACKDUCK_VERSION_ID"])
collection = f"{project}/versions/{version}/vulnerable-bom-components"
url = f"{base}/api/projects/{collection}"
paths = {f"{parts.path}/api/{relation}/{collection}" for relation in ("projects", "project")}

def authority(url):
    return url.netloc.lower().removesuffix(":443")

client = Client(base_url=base + "/", token=os.environ["BLACKDUCK_TOKEN"])
client.session.max_redirects = 0
media_type = "application/vnd.blackducksoftware.bill-of-materials-6+json"
items = []
seen = set()
total = None
while True:
    offset = len(items)
    response = client.session.get(url, params={"offset": offset, "limit": 250},
                                  headers={"Accept": media_type}, allow_redirects=False)
    if response.status_code != 200:
        raise ValueError(f"Black Duck returned HTTP {response.status_code}; refusing partial export")
    received_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if received_type != media_type:
        raise ValueError("Expected a BOM-6 response")
    page = response.json()
    href = urlsplit(page["_meta"]["href"])
    if (href.scheme != "https" or authority(href) != authority(parts)
            or href.fragment or href.path not in paths):
        raise ValueError("Page identifies a different Black Duck collection")
    query = parse_qs(href.query, keep_blank_values=True)
    if "offset" in query and query["offset"] != [str(offset)]:
        raise ValueError("Page identifies a different or ambiguous offset")
    batch, declared = page["items"], page["totalCount"]
    if not isinstance(batch, list) or type(declared) is not int or declared < 0:
        raise ValueError("Invalid Black Duck collection")
    if total is not None and declared != total:
        raise ValueError("Collection changed; retry the export")
    total = declared
    for row in batch:
        digest = sha256(json.dumps(row, sort_keys=True).encode()).digest()
        if digest in seen:
            raise ValueError("Repeated row; retry the export")
        seen.add(digest)
    items.extend(batch)
    if len(items) == total:
        if any(link.get("rel") == "next" for link in page["_meta"].get("links", [])):
            raise ValueError("Final page has a next link; retry the export")
        break
    if not batch or len(items) > total:
        raise ValueError("Incomplete or inconsistent Black Duck collection")
print(json.dumps({"_meta": {"href": url}, "totalCount": total, "items": items}))
```

Keep the original rows and collection total. If the BOM changes during offset
pagination, export it again after the scan finishes. For a selection, supply
an array of native rows that each identify the same project version. See the
[Black Duck Python client](https://github.com/blackducksoftware/hub-rest-api-python)
and its [vulnerable BOM component example](https://github.com/blackducksoftware/hub-client-go/blob/5f78f7257c00fe9cebabf1bf89a6fc36a4d1f095/hubapi/testdata/vulnerableBomComponents.json).
