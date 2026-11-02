# Import Black Duck SCA repository vulnerabilities

Use `--provider blackduck` to import vulnerable BOM components from one Black Duck
SCA project version. Check the scan configuration to confirm which Git repository
the project version represents. Project names, API hosts and component download
URLs cannot establish that mapping. Aggregate product BOMs, image-only scans,
license violations and global advisory catalogs are outside this import.

## Export a complete collection

Use a read-only token and request the project version’s `vulnerable-components`
relation with media type `application/vnd.blackducksoftware.bill-of-materials-6+json`.
The importer requires BOM-6. If the deployment serves only BOM-8 or another
inventory format, stop the export.

Install the vendor’s `blackduck` Python client in a trusted virtual environment
outside the checkout. Set `BLACKDUCK_URL` to the deployment’s HTTPS URL,
`BLACKDUCK_TOKEN` to the read-only token and `BLACKDUCK_PROJECT_ID` and
`BLACKDUCK_VERSION_ID` to the two UUIDs. The client exchanges the token before
reading the collection, so disable redirects for the entire session.

Save the script outside the checkout and run it with
`/path/to/venv/bin/python -I /private/path/export.py` to keep checkout modules
and `PYTHONPATH` off the import path. Redirect stdout to a private temporary file
and rename it after the script succeeds.

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
pagination, export it again after the scan finishes. To import only selected
occurrences, supply an array of native rows that each identify the same project
version.

## Preview and repeat

```bash
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings blackduck.json \
  --to local --repository ./project --provider blackduck \
  --source-repository-url https://github.com/example/project \
  --source-key blackduck/deployment-alias/project-id/version-id \
  --dry-run --format json
```

Check the source, destination and excluded rows before repeating the command
without `--dry-run`. Reuse the source key for later exports from this deployment,
project and version. For Cloud, select an authorized GitHub repository with
`--to cloud` on a deployment that accepts `blackduck`. Reading a saved report
requires no Black Duck login. Local imports also require no Cloud login.

If an interrupted Cloud upload reports `result.savedSubmission`, keep its
checkpoint and use the same build, state directory, account and import settings.
Preview the original export with `--dry-run --format json`. Check `accountId`
and `destination`. When `resumed` is false, review the new upload before approving it.
For `prepareNormalizedExternalPublication`, pass your original normalized
`ExternalFindings` and check `preview.resumed` before calling `publish()`.
Different normalized findings prepare a new upload.

Cloud checks retained and declared source repository URLs against the selected
repository. For local SDK imports, reader-supplied repository references must
agree with the repository on the findings. Local imports also check comparable
Git remotes on the selected checkout. Select the `blackduck` provider for
retained Black Duck BOM records. Caller-authored text and opaque IDs alone
cannot establish repository ownership.

Each occurrence is identified by its project version, component version, origin,
advisory source and advisory name. Reimporting updates the occurrence when its
evidence changes. Rows absent from a later export remain open.

Supported package URLs and origin coordinates supply the package identity.
`advisory_ids` preserves the vendor’s `vulnerabilityName` and any distinct
`relatedVulnerability` value verbatim, including Black Duck resource URLs.
The native row retains its CWE, matched-files link and remediation status.
Findings start unassessed, with no inferred fix, Git revision or source location.

References: [official Python REST client](https://github.com/blackducksoftware/hub-rest-api-python),
[vendor example of vulnerable BOM components](https://github.com/blackducksoftware/hub-client-go/blob/5f78f7257c00fe9cebabf1bf89a6fc36a4d1f095/hubapi/testdata/vulnerableBomComponents.json).
