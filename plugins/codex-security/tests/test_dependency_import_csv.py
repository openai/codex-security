"""Exercise Endor CSV normalization and atomic import through the CLI."""

from __future__ import annotations

import csv
import importlib
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from workbench_test_support import initialize_git_repository, run_workbench

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
parse_report = importlib.import_module("dependency_imports.formats").parse_report
decode = importlib.import_module("dependency_imports.workbench")._decode
FIXTURE = Path(__file__).parent / "fixtures" / "dependency-imports" / "endor.csv"


def _rows() -> list[dict[str, str]]:
    with FIXTURE.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, strict=True))


def _csv(rows: list[dict[str, str]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\r\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def test_endor_csv_preserves_rows_and_vendor_evidence() -> None:
    rows = _rows()
    rows[0]["Risk Details"] = (
        "Multiline evidence larger than the CSV library default.\n" + "x" * 140000
    )
    previous_field_limit = csv.field_size_limit()
    parsed = parse_report("\ufeff" + _csv(rows), "endor")
    assert csv.field_size_limit() == previous_field_limit
    findings = parsed["findings"]
    assert len(findings) == 6
    assert parsed["excludedCount"] == 2
    assert [finding["original"] for finding in findings] == rows[:6]
    scoped, maven, malware, missing_version, go, missing_identity = findings
    assert scoped["package"] == {"ecosystem": "npm", "name": "@example/parser", "version": "1.2.3"}
    assert scoped["sourceId"] == rows[0]["UUID"]
    assert scoped["title"] == rows[0]["Title"]
    assert scoped["originalSeverity"] == rows[0]["Severity Level"]
    assert scoped["advisoryIds"] == ["CVE-2099-0001", "GHSA-aaaa-bbbb-cccc", "OSV-2099-1"]
    assert scoped["fix"] == {"proposed_version": "1.2.4", "remediation": rows[0]["Remediation"]}
    assert scoped["sourceRevision"] == "a" * 40
    assert scoped["locations"] == [{"path": "package-lock.json"}]
    assert scoped["evidence"]["finding_tags"] == [
        "FINDING_TAGS_DIRECT",
        "FINDING_TAGS_REACHABLE_FUNCTION",
    ]
    assert scoped["evidence"]["Risk Details"] == rows[0]["Risk Details"]
    assert maven["package"] == {
        "ecosystem": "maven",
        "name": "org.example:parser",
        "version": "2.0.0",
    }
    assert maven["locations"] == []
    assert maven["evidence"]["Location"] == "pom.xml,modules/pom.xml"
    assert malware["kind"] == "malware"
    assert malware["package"] == {
        "ecosystem": "githubaction",
        "name": "example/action",
        "version": "v1",
    }
    assert malware["locations"] == [{"path": "/.github/workflows"}]
    assert missing_version["package"] == {"ecosystem": "pypi", "name": "example-parser"}
    assert go["package"] == {
        "ecosystem": "go",
        "name": "example.org/tools/parser",
        "version": "v1.2.3",
    }
    assert missing_identity["package"] == {}
    assert any("2 finding(s) lack" in warning for warning in parsed["warnings"])
    assert any("comma-containing locations" in warning for warning in parsed["warnings"])
    assert all(
        "verdict" not in finding and finding["dependencyPaths"] == [] for finding in findings
    )
    default_columns = {
        "UUID",
        "Title",
        "Severity Level",
        "Attributes",
        "Finding Categories",
        "CVE",
        "Vulnerability ID",
        "Project Name",
    }
    default_rows = [
        {key: value for key, value in row.items() if key in default_columns} for row in rows
    ]
    default_export = parse_report(_csv(default_rows), "endor")
    assert len(default_export["findings"]) == 6
    assert all(
        finding["package"] == {} and finding["locations"] == []
        for finding in default_export["findings"]
    )
    assert any(
        "6 finding(s) lack a complete package" in warning for warning in default_export["warnings"]
    )
    assert any(
        "6 finding(s) lack a repository location" in warning
        for warning in default_export["warnings"]
    )


def test_csv_source_count_allows_large_exports_and_bounds_excluded_rows() -> None:
    row = _rows()[0]
    parsed = parse_report(_csv([row] * 2501), "endor")
    assert len(parsed["findings"]) == 2501
    row["Finding Categories"] = "FINDING_CATEGORY_LICENSE_RISK"
    with pytest.raises(ValueError, match="at most 10000 source findings"):
        parse_report(_csv([row] * 10001), "endor")


@pytest.mark.parametrize(
    "flaw", ["duplicate_headers", "short_row", "extra_field", "unterminated_quote"]
)
def test_malformed_csv_does_not_partially_persist(tmp_path: Path, flaw: str) -> None:
    target, state = tmp_path / "repo", tmp_path / "state"
    initialize_git_repository(target)
    content = _csv([_rows()[0]])
    if flaw == "duplicate_headers":
        content = content.replace("Explanation,CVE", "UUID,CVE", 1)
    elif flaw == "short_row":
        content += "too,few,columns\r\n"
    elif flaw == "extra_field":
        content += ",".join([""] * (len(_rows()[0]) + 1)) + "\r\n"
    else:
        content += '"unterminated quoted field\r\n'
    path = tmp_path / "bad.csv"
    path.write_text(content)
    rejected = run_workbench(
        state,
        "import-dependency-findings",
        "--target-path",
        str(target),
        "--report-path",
        str(path),
        "--vendor",
        "endor",
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "Endor CSV" in rejected["stderr"]
    assert run_workbench(state, "list-dependency-reports")["reports"] == []


def test_csv_dispatch_preserves_json_errors_and_vendor_scope() -> None:
    csv_bytes = ("\ufeff" + _csv(_rows())).encode("utf-8")
    assert len(parse_report(decode(csv_bytes, vendor="endor"), "endor")["findings"]) == 6
    for vendor in ("snyk", None):
        with pytest.raises(ValueError, match="valid JSON"):
            decode(csv_bytes, vendor=vendor)
    for malformed in (b'{"list":', b'[{"meta":'):
        with pytest.raises(ValueError, match="valid JSON"):
            decode(malformed, vendor="endor")
    with pytest.raises(ValueError, match="Endor CSV export headers"):
        parse_report(decode(b"name,severity\nexample,high\n", vendor="endor"), "endor")


def test_csv_import_checks_revision_and_retains_missing_revision_warning(tmp_path: Path) -> None:
    target, state = tmp_path / "repo", tmp_path / "state"
    initialize_git_repository(target)
    revision = subprocess.check_output(
        ["git", "-C", str(target), "rev-parse", "HEAD"], text=True
    ).strip()
    (target / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/@example/parser": {"version": "1.2.3"}}})
    )
    row = _rows()[0]
    for source_revision in (revision, "", "b" * 40):
        row["Commit SHA"] = source_revision
        path = tmp_path / "findings.csv"
        path.write_text("\ufeff" + _csv([row]), encoding="utf-8")
        report = run_workbench(
            state,
            "import-dependency-findings",
            "--target-path",
            str(target),
            "--report-path",
            str(path),
            "--vendor",
            "endor",
        )["report"]
        finding = run_workbench(state, "get-dependency-report", "--report-id", report["id"])[
            "findings"
        ][0]
        finding = run_workbench(
            state,
            "get-dependency-finding",
            "--report-id",
            report["id"],
            "--finding-id",
            finding["id"],
        )["finding"]
        assert finding["original"] == row
        assert finding.get("sourceRevision", "") == source_revision
        assert any(
            "immutable repository revision" in warning for warning in report["warnings"]
        ) is (not source_revision)
        assert bool(finding["inputWarnings"]) is (source_revision == "b" * 40)
