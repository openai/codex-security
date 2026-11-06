"""Download selected Tenable One Code Repository findings to a local selection file."""

import csv
import http.client
import json
import os
import time
from io import BytesIO
from urllib.parse import urlencode
from uuid import UUID

from capture import (
    ASSET_FIELDS,
    read_asset,
    read_findings,
    selection_parser,
    validate_repository_url,
    write_selection,
)

EXPORT_PATH = "/api/v1/t1/inventory/export"
FINDING_PROPERTIES = (
    "asset_id",
    "finding_id",
    "finding_name",
    "finding_severity",
    "state",
    "finding_description",
    "finding_solution",
    "file_path",
    "code_line_number",
)
# The Inventory Export API uses 20 MiB CSV chunks by default.
MAX_CHUNK_BYTES = 20 * 1024 * 1024


def tenable_request(access_key, secret_key):
    # http.client includes malformed header values in its exception messages.
    if any(not key.isascii() or not key.isprintable() for key in (access_key, secret_key)):
        raise ValueError("Tenable API keys must be printable ASCII header values")

    def request(method, path, payload=None):
        # A fixed-origin HTTPSConnection does not follow redirects or forward credentials.
        headers = {"X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload)
        # A chunk GET may return 204 while its contents are being prepared.
        retries_left = 4 if method == "GET" and "/download/" in path else 0
        while True:
            connection = http.client.HTTPSConnection("cloud.tenable.com", timeout=30)
            try:
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                if response.status == 200:
                    data = response.read(MAX_CHUNK_BYTES + 1)
                    if len(data) > MAX_CHUNK_BYTES:
                        raise ValueError("Tenable response exceeds the requested chunk size")
                    return data
                if response.status != 204 or retries_left == 0:
                    break
            finally:
                connection.close()
            retries_left -= 1
            time.sleep(2)
        raise ValueError(f"Tenable returned HTTP {response.status} for {method} {path}")

    return request


def export_chunks(kind, property_name, selected_id, columns, request, sleep):
    query = urlencode(
        {
            "properties": ",".join(columns),
            "file_format": "CSV",
            "use_readable_name": "false",
            "max_chunk_file_size": MAX_CHUNK_BYTES,
        }
    )
    payload = {"filters": [{"property": property_name, "operator": "=", "value": [selected_id]}]}
    job = json.loads(request("POST", f"{EXPORT_PATH}/{kind}?{query}", payload))
    export_id = job.get("export_id") if isinstance(job, dict) else None
    if not export_id or not isinstance(export_id, str):
        raise ValueError("Tenable did not return an export ID")
    job_id = str(UUID(export_id))
    job_path = f"{EXPORT_PATH}/{job_id}"
    for _ in range(60):
        status = json.loads(request("GET", f"{job_path}/status"))
        if not isinstance(status, dict) or status.get("export_id") != export_id:
            raise ValueError("Tenable returned a status for an unexpected export ID")
        if status.get("status") == "FINISHED":
            break
        if status.get("status") not in ("QUEUED", "PROCESSING"):
            raise ValueError(f"Tenable export {job_id} ended with status {status.get('status')}")
        sleep(2)
    else:
        raise ValueError(f"Tenable export {job_id} did not finish within 60 polls")

    chunks = status.get("chunks_available")
    if not isinstance(chunks, list) or any(type(chunk) is not int or chunk < 0 for chunk in chunks):
        raise ValueError("Tenable returned invalid chunk numbers")
    if len(set(chunks)) != len(chunks):
        raise ValueError("Tenable returned duplicate chunk numbers")
    for chunk in chunks:
        path = f"{job_path}/download/{chunk}"
        yield path, BytesIO(request("GET", path))


def download(asset_id, finding_ids, repository_url, output, request, sleep=time.sleep):
    asset_id = str(UUID(asset_id))
    finding_ids = [str(UUID(value)) for value in finding_ids]
    if not finding_ids or len(set(finding_ids)) != len(finding_ids):
        raise ValueError("Select one or more distinct Tenable finding UUIDs")
    validate_repository_url(repository_url)
    if output.exists():
        raise FileExistsError(f"Selection file already exists: {output}")

    assets = export_chunks("assets", "asset_id", asset_id, ASSET_FIELDS, request, sleep)
    asset = read_asset(assets, asset_id, exact=True)
    findings = []
    for finding_id in finding_ids:
        # finding_id is a single-value filter. On finding exports, asset_id is read-only.
        chunks = export_chunks(
            "findings", "finding_id", finding_id, FINDING_PROPERTIES, request, sleep
        )
        rows = read_findings(chunks, asset_id, "file_path", "code_line_number")
        if len(rows) != 1 or rows[0]["finding_id"].lower() != finding_id:
            raise ValueError(f"Tenable did not return exactly the selected finding {finding_id}")
        findings.extend(rows)
    write_selection(output, asset, repository_url, findings)
    return len(findings)


def main():
    parser = selection_parser(__doc__)
    parser.add_argument(
        "--finding-id",
        action="append",
        required=True,
        help="Finding UUID; repeat for each selection",
    )
    args = parser.parse_args()
    try:
        access_key = os.environ.get("TENABLE_ACCESS_KEY")
        secret_key = os.environ.get("TENABLE_SECRET_KEY")
        if not access_key or not secret_key:
            raise ValueError(
                "Set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY for your Tenable tenant"
            )
        count = download(
            args.asset_id,
            args.finding_id,
            args.repository_url,
            args.output,
            tenable_request(access_key, secret_key),
        )
    except (ValueError, OSError, csv.Error, http.client.HTTPException) as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")
    print(f"Wrote {count} finding(s) to {args.output}.")


if __name__ == "__main__":
    main()
