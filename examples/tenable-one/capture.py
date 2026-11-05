"""Capture one Code Repository asset and its findings from Tenable One CSV exports."""

import argparse
import csv
import json
import sys
from io import TextIOWrapper
from pathlib import Path
from uuid import UUID

PLUGIN_SCRIPTS = Path(__file__).resolve().parents[2] / "plugins/codex-security/scripts"
sys.path.insert(0, str(PLUGIN_SCRIPTS))
from finalize_scan_contract import _validate_remote, write_scan_local_bytes

ASSET_FIELDS = ("asset_id", "asset_class", "asset_name")
FINDING_FIELDS = ("asset_id", "finding_id", "finding_name", "severity", "state")
FINDING_ALIASES = {
    "finding_detection_name": "finding_name",
    "finding_severity": "severity",
    "finding_solution": "solution",
    "finding_description": "description",
}


def file_chunks(paths):
    for path in paths:
        yield path, path.open("rb")


def csv_rows(chunks, required, aliases=None, source_columns=()):
    """Read each chunk's header separately, including header-only chunks."""
    # A single exported description can exceed Python's default 128 KiB field limit.
    # Tenable permits CSV chunks up to 100 MiB.
    csv.field_size_limit(max(csv.field_size_limit(), 100 * 1024 * 1024))
    first_header = None
    for path, chunk in chunks:
        with TextIOWrapper(chunk, encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream, strict=True)
            header = reader.fieldnames or []
            # An export's default names can differ from explicitly selected properties.
            mapped = {
                source: target
                for source, target in (aliases or {}).items()
                if source in header and target not in header
            }
            missing = set(required).difference(header, mapped.values())
            missing.update(set(source_columns).difference(header))
            if missing:
                raise ValueError(f"{path}: missing CSV columns: {', '.join(sorted(missing))}")
            if len(set(header)) != len(header) or "" in header:
                raise ValueError(f"{path}: duplicate or empty CSV column name")
            if first_header is not None and header != first_header:
                raise ValueError(f"{path}: column names or order differ between chunks")
            first_header = header
            for row in reader:
                context = f"{path}, line {reader.line_num}"
                if None in row or None in row.values():
                    raise ValueError(f"{context}: row width does not match its CSV header")
                row.update({target: row[source] for source, target in mapped.items()})
                yield context, row


def required_values(fields, row, context):
    for field in fields:
        if not row[field].strip():
            raise ValueError(f"{context}: missing {field}")
    return {field: row[field] for field in fields}


def validate_repository_url(repository_url):
    _validate_remote(repository_url, "--repository-url")
    if not repository_url.lower().startswith("https://"):
        raise ValueError("--repository-url must be the repository's HTTPS URL")


def read_asset(chunks, asset_id, *, exact=False):
    asset = None
    for context, row in csv_rows(chunks, ASSET_FIELDS):
        if row["asset_id"].lower() != asset_id:
            if exact:
                raise ValueError(f"{context}: API returned an unrequested asset")
            continue
        if asset is not None:
            raise ValueError(f"{context}: multiple inventory rows match the selected asset ID")
        asset = required_values(ASSET_FIELDS, row, context)
        if asset["asset_class"] != "CODE_REPOSITORY":
            raise ValueError(f"{context}: selected asset must have asset_class CODE_REPOSITORY")
    if asset is None:
        raise ValueError("Selected asset ID was not found in the available asset chunks")
    return asset


def read_findings(chunks, asset_id, path_column, line_column):
    source_columns = [key for key in (path_column, line_column) if key]
    findings = {}
    for context, row in csv_rows(chunks, FINDING_FIELDS, FINDING_ALIASES, source_columns):
        if row["asset_id"].lower() != asset_id:
            raise ValueError(f"{context}: finding belongs to a different or missing asset_id")
        finding = required_values(FINDING_FIELDS, row, context)
        if finding["finding_id"] in findings:
            raise ValueError(f"{context}: duplicate finding_id in the selected export")
        for field in ("description", "solution"):
            if row.get(field):
                finding[field] = row[field]
        if path_column and row[path_column].strip():
            finding["code_file_path"] = row[path_column]
        if line_column and row[line_column].strip():
            line = row[line_column].strip()
            if not line.isascii() or not line.isdecimal():
                raise ValueError(f"{context}: {line_column} must be a nonnegative integer")
            number = int(line)
            if number > 0:
                if "code_file_path" not in finding:
                    raise ValueError(
                        f"{context}: a code line number requires a mapped repository path"
                    )
                finding["code_line_number"] = number
        findings[finding["finding_id"]] = finding
    return list(findings.values())


def write_selection(output, asset, repository_url, findings):
    selection = {
        "format": "tenable-one-code-repository/v1",
        "asset": asset,
        "repository_url": repository_url,
        "findings": findings,
    }
    payload = (json.dumps(selection, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    write_scan_local_bytes(
        output.parent,
        output.name,
        payload,
        external_name=True,
        owner_read_write=True,
        replace_existing=False,
    )


def selection_parser(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--asset-id", required=True, help="Tenable Code Repository asset UUID")
    parser.add_argument("--repository-url", required=True, help="Canonical HTTPS repository URL")
    parser.add_argument("--output", required=True, type=Path, help="New local selection JSON file")
    return parser


def main():
    parser = selection_parser(__doc__)
    parser.add_argument("--assets", required=True, type=Path, help="Asset inventory CSV")
    parser.add_argument(
        "--findings", required=True, type=Path, nargs="+", help="Findings CSV chunks"
    )
    parser.add_argument("--path-column", help="Verified export column for the repository file path")
    parser.add_argument(
        "--line-column", help="Verified export column for the one-based line number"
    )
    args = parser.parse_args()
    try:
        asset_id = str(UUID(args.asset_id))
        validate_repository_url(args.repository_url)
        asset = read_asset(file_chunks([args.assets]), asset_id)
        findings = read_findings(
            file_chunks(args.findings), asset_id, args.path_column, args.line_column
        )
        write_selection(args.output, asset, args.repository_url, findings)
    except (ValueError, OSError, csv.Error) as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")
    print(f"Wrote {len(findings)} finding(s) to {args.output}.")


if __name__ == "__main__":
    main()
