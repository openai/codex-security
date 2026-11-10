# Import Black Duck SCA findings

Export the vulnerable components from the bill of materials for one Black Duck
SCA project version. Request the BOM-6 JSON format. In the scan configuration,
verify which Git repository the version represents. A project name or component
download URL alone can't establish that link. [Export the collection](#export-the-bom-6-collection).

## Quick start

From the matching checkout, choose a saved report or export one.

**Saved report.** Set `report` to the complete BOM-6 collection. For a selection,
use an array of native rows that each identify the same project version.

```sh
report=/private/path/blackduck.json
```

**Export from Black Duck.** Use a read-only token and the
[BOM-6 export below](#export-the-bom-6-collection). Run it in the same shell
to set `report`.

**Preview the report.** Use the verified Git URL for `--source-repository-url`.
It must match a comparable local remote when available, or the selected Cloud
repository. Replace the source key with one for your deployment, project and
version.

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider blackduck --source-repository-url https://github.com/example/project \
  --source-key blackduck/deployment-alias/project-id/version-id \
  --dry-run --format json
```

In each finding's `evidence`, check `source_data.projectVersionUrl`,
`packages` and `advisory_ids`. Review any excluded rows. Reuse this key for
later exports of the same project version.
[Save locally or publish to Cloud and verify the result](README.md#save-or-publish-and-verify).

## Identity and evidence

The project version, component version, origin, advisory source and advisory
name identify each occurrence. Package URLs and origin coordinates identify
the package. For a GitHub dependency, a `pkg:github/owner/repo@tag` package URL
supplies the dependency's owner, repository name and installed tag or commit.
`--source-repository-url` identifies the repository Black Duck scanned.
The first entry in `evidence.advisory_ids` is `vulnerabilityName`. A second
entry identifies the related vulnerability, exactly as Black Duck reported it.
If that entry is a URL, it points to a Black Duck resource.

Look in the original row for CWE, matched-files links and remediation
status. The reader leaves fix verification, Git revision and source location
unknown.
Aggregate product BOMs, image-only scans, license violations and global
advisory catalogs fall outside this import.

For SDK replay, use the `blackduck` provider and keep the repository reference
from the reader. It must match the repository on local findings. An opaque ID
or a description alone can't establish repository ownership.

## Export the BOM-6 collection

In the [Black Duck SCA MCP](https://github.com/blackducksoftware/sca-mcp#capabilities),
`search_projects_versions` can locate the project version.
`fetch_project_vulnerabilities` returns a summary and CSV, and `scan` starts
a new scan. To export existing BOM rows, request the project version's
`vulnerable-components` relation with the BOM-6 media type shown below.
This reader requires BOM-6. BOM-8 inventories, Coverity reports and Polaris
reports use other formats.

Install the vendor's `blackduck` Python client in a trusted virtual environment
outside the checkout. Set `BLACKDUCK_URL` to the deployment's HTTPS URL,
`BLACKDUCK_TOKEN` to a read-only token, and `BLACKDUCK_PROJECT_ID` and
`BLACKDUCK_VERSION_ID` to the project and version UUIDs. Keep redirects disabled
for the client session, including the token exchange.

Save this script outside the checkout as `export.py`.

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

Run the script in isolated mode so Python loads packages from the trusted
environment. The example creates a private report directory under `TMPDIR`
or, if unset, under `/tmp`.

```sh
report=
out=$(mktemp -d "${TMPDIR:-/tmp}/blackduck.XXXXXX") &&
  /path/to/venv/bin/python -I /private/path/export.py > "$out/blackduck.tmp" &&
  mv "$out/blackduck.tmp" "$out/blackduck.json" &&
  report="$out/blackduck.json"
```

Keep the original rows and collection total. If the BOM changes during
pagination, export it again after the scan finishes.
[Black Duck Python client](https://github.com/blackducksoftware/hub-rest-api-python) · [Example BOM rows from a partial collection](https://github.com/blackducksoftware/hub-client-go/blob/5f78f7257c00fe9cebabf1bf89a6fc36a4d1f095/hubapi/testdata/vulnerableBomComponents.json)
