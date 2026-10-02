from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from workbench_test_support import checkpoint, register, run_workbench, write_completed_contract


@pytest.fixture
def projection_fixture(tmp_path):
    target = tmp_path / "target"
    for name in ("src/extract.py", "shared/control.py", "outside.py"):
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("print('synthetic fixture')\n" * 2)
    state = tmp_path / "state"
    parent_dir = tmp_path / "parent"
    parent = register(state, target, parent_dir, mode="deep")
    raw_fixture = (
        Path(__file__).parent / "fixtures/scan-projection/canonical-child.json"
    ).read_text()
    child_dir = parent_dir / json.loads(raw_fixture)["relativeDirectory"]
    child = register(
        state, target, child_dir, parent=parent["scanId"], role="deep_pass", paths=("src",)
    )
    fixture = json.loads(raw_fixture.replace("@CHILD@", child["scanId"]))
    write_completed_contract(
        child_dir,
        child["scanId"],
        target,
        include_paths=["src"],
        coverage_mode="scoped_path",
        inventory_strategy="scoped_path",
    )
    for name, values in (
        ("findings", {"findings": fixture["findings"]}),
        ("coverage", fixture["coverage"]),
    ):
        path = child_dir / f"{name}.json"
        path.write_text(json.dumps({**json.loads(path.read_text()), **values}))
    for name, contents in fixture["files"].items():
        path = child_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    return state, parent_dir, parent, child_dir, child, fixture


def completed_projection(state, parent_dir, parent, child_dir, child, **overrides):
    identity = parent_dir.stat()
    request = {
        "parentScanId": parent["scanId"],
        "sourceScanId": child["scanId"],
        "sourceDirectory": str(child_dir),
        "parentDirectory": str(parent_dir),
        "expectedParentIdentity": {"dev": str(identity.st_dev), "ino": str(identity.st_ino)},
        **overrides,
    }
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-X",
            "utf8",
            "-B",
            str(Path(__file__).parents[1] / "scripts/project_scan_artifacts.py"),
        ],
        input=json.dumps(request),
        env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state)},
        capture_output=True,
        text=True,
        check=False,
    )


def test_stopped_projection_shared_fixture(projection_fixture, workbench_api, monkeypatch):
    state, parent_dir, parent, child_dir, child, fixture = projection_fixture
    originals = json.loads((child_dir / "findings.json").read_text())["findings"]
    completed = completed_projection(state, parent_dir, parent, child_dir, child)
    assert completed.returncode == 0, completed.stderr
    live = json.loads(completed.stdout)
    assert live["scanId"] == child["scanId"]
    assert live["scanDir"] == str(child_dir)
    assert live["sourceFindings"] == [
        originals[index] for index in fixture["expected"]["sourceFindingIndexes"]
    ]
    assert live["draft"]["coverage"] == fixture["expected"]["coverage"]
    assert live["draft"]["scanId"] == parent["scanId"]
    for finding, wanted in zip(
        live["draft"]["findings"], fixture["expected"]["findings"], strict=True
    ):
        assert finding["identity"] == wanted["identity"]
        assert finding["provenance"]["sourceFindingIds"] == wanted["sourceFindingIds"]
        assert finding["provenance"]["extensions"] == {"fixture": "preserve-source-provenance"}
        assert finding.get("writeup") == wanted.get("writeup")
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with workbench_api["connect"]() as connection:
        row = workbench_api["require_scan"](connection, child["scanId"])
        project = workbench_api["saved_results"]._stopped_child_draft
        draft = project(workbench_api["_WORKBENCH_DB_CONTEXT"], row, parent_dir)
        assert project(workbench_api["_WORKBENCH_DB_CONTEXT"], row, parent_dir) == draft
    expected = fixture["expected"]
    for actual, wanted, original_index in zip(
        draft["findings"], expected["findings"], expected["sourceFindingIndexes"], strict=True
    ):
        assert actual["identity"]["anchor"] == wanted["identity"]["anchor"]
        assert actual["identity"]["instance"] == f"{child['scanId']}-saved"
        assert actual["locations"] == wanted["locations"]
        assert actual.get("writeup") == wanted.get("writeup")
        assert actual["extensions"] == {"fixture": "preserve-finding-extensions"}
        assert actual["provenance"]["sourceFindingIds"] == wanted["sourceFindingIds"]
        assert actual["provenance"]["sourceFindings"] == [
            {"id": wanted["sourceFindingIds"][0], "finding": originals[original_index]}
        ]
        assert not {"findingId", "occurrenceId", "fingerprints"}.intersection(actual)
    for key, wanted in expected["coverage"].items():
        assert draft["coverage"][key] == wanted
    for destination, source in expected["fileProjections"].items():
        assert (parent_dir / destination).read_bytes() == (child_dir / source).read_bytes()
    for name, contents in fixture["files"].items():
        assert (child_dir / name).read_text() == contents


@pytest.mark.parametrize("rewrite", ["findings", "legacy-binding"])
def test_completed_projection_rejects_rewritten_saved_scan(
    projection_fixture, workbench_api, monkeypatch, rewrite
):
    state, parent_dir, parent, child_dir, child, fixture = projection_fixture
    manifest_path = child_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if rewrite == "findings":
        findings_path = child_dir / "findings.json"
        findings = json.loads(findings_path.read_text())
        index = fixture["expected"]["sourceFindingIndexes"][0]
        findings["findings"][index]["summary"] = "Rewritten completed observation"
        payload = json.dumps(findings).encode()
        findings_path.write_bytes(payload)
        for artifact in manifest["scan"]["artifacts"]:
            if artifact["path"] == "findings.json":
                artifact["sha256"] = hashlib.sha256(payload).hexdigest()
        message = "sealed scan manifest changed after completion"
    else:
        # Historical completed rows can lack a pinned digest; their target binding still applies.
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET seal_manifest_digest = NULL WHERE id = ?", (child["scanId"],)
            )
        manifest["scan"]["target"]["displayName"] = "Different target"
        message = "target displayName must match the workbench target"
    manifest_path.write_text(json.dumps(manifest))
    source_bytes = {
        name: (child_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
    }
    listed = run_workbench(state, "list-scans", "--scan-root", str(child_dir))["scans"]
    assert len(listed) == 1
    assert listed[0]["scanId"] == child["scanId"]
    assert listed[0]["progress"]["status"] == "complete"
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with workbench_api["connect"]() as connection:
        row = workbench_api["require_scan"](connection, child["scanId"])
        with pytest.raises(SystemExit, match=message):
            workbench_api["saved_results"]._stopped_child_draft(
                workbench_api["_WORKBENCH_DB_CONTEXT"], row, parent_dir
            )
    projected = completed_projection(state, parent_dir, parent, child_dir, child)
    assert projected.returncode != 0
    assert message in projected.stderr
    assert not (parent_dir / "findings").exists()
    assert {name: (child_dir / name).read_bytes() for name in source_bytes} == source_bytes


@pytest.mark.parametrize("nested", [False, True])
def test_projection_preserves_long_report_references(tmp_path, nested):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    state = tmp_path / "state"
    parent_dir = tmp_path / "parent"
    parent = register(state, target, parent_dir, mode="deep")
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    slug = "a" * 250
    report_path = (
        "findings/original/secondary/report.md" if nested else f"findings/{slug}/{slug}.md"
    )
    source = child_dir / report_path
    source.parent.mkdir(parents=True)
    source.write_text("# Synthetic report\n[Evidence](poc/trace.txt)\n")
    (source.parent / "poc").mkdir()
    (source.parent / "poc/trace.txt").write_text("Synthetic supporting evidence\n")
    findings_path = child_dir / "findings.json"
    document = json.loads(findings_path.read_text())
    document["findings"][0]["writeup"] = {"reportPath": report_path}
    findings_path.write_text(json.dumps(document))
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    completed = completed_projection(state, parent_dir, parent, child_dir, child)
    assert completed.returncode == 0, completed.stderr
    live = json.loads(completed.stdout)["draft"]["findings"][0]
    projected = parent_dir / live["writeup"]["reportPath"]
    assert projected.name == source.name
    assert projected.read_bytes() == source.read_bytes()
    assert (projected.parent / "poc/trace.txt").read_bytes() == (
        source.parent / "poc/trace.txt"
    ).read_bytes()
    assert (
        completed_projection(state, parent_dir, parent, child_dir, child).stdout == completed.stdout
    )
    checkpoint(
        state,
        parent,
        passes=[
            {"directory": child_dir.relative_to(parent_dir).as_posix(), "scanId": child["scanId"]}
        ],
    )
    run_workbench(state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Stopped.")
    saved = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]["findings"][0]
    assert saved["writeup"] == live["writeup"]
    assert saved["artifactPaths"] == [
        live["writeup"]["reportPath"],
        (projected.parent / "poc/trace.txt").relative_to(parent_dir).as_posix(),
    ]


@pytest.mark.parametrize(
    "field, value, message",
    [
        ("sourceScanId", "wrong-child", "does not match"),
        (
            "expectedParentIdentity",
            {"dev": "0", "ino": "0"},
            "changed after artifact restoration setup",
        ),
    ],
)
def test_completed_projection_keeps_source_and_parent_binding(
    projection_fixture, field, value, message
):
    state, parent_dir, parent, child_dir, child, _ = projection_fixture
    completed = completed_projection(state, parent_dir, parent, child_dir, child, **{field: value})
    assert completed.returncode != 0
    assert message in completed.stderr
    assert not (parent_dir / "findings").exists()


@pytest.mark.parametrize("directory", [False, True])
def test_completed_projection_does_not_copy_or_follow_symlink_evidence(
    projection_fixture, directory
):
    state, parent_dir, parent, child_dir, child, _ = projection_fixture
    outside = parent_dir.parent / "outside-evidence.txt"
    if directory:
        outside.mkdir()
        (outside / "evidence.txt").write_text("Outside directory evidence")
    else:
        outside.write_text("Evidence outside the child must not be projected.")
    (child_dir / "findings/check/unsafe.txt").symlink_to(outside, target_is_directory=directory)
    completed = completed_projection(state, parent_dir, parent, child_dir, child)
    assert completed.returncode == 0, completed.stderr
    assert not (parent_dir / "findings").exists()
    assert (child_dir / "findings/check/unsafe.txt").is_symlink()


@pytest.mark.parametrize("terminal", ["unsealed", "interrupted"])
def test_completed_projection_requires_completed_seal(projection_fixture, terminal):
    state, parent_dir, parent, child_dir, child, _ = projection_fixture
    path = child_dir / "scan-manifest.json"
    manifest = json.loads(path.read_text())
    if terminal == "unsealed":
        manifest["scan"].pop("sealedAt")
        manifest["scan"].pop("artifacts")
    else:
        manifest["scan"]["status"] = "interrupted"
    path.write_text(json.dumps(manifest))
    completed = completed_projection(state, parent_dir, parent, child_dir, child)
    assert completed.returncode != 0
    assert "Only a sealed completed scan" in completed.stderr
    assert not (parent_dir / "findings").exists()


@pytest.mark.parametrize(
    "location, scope, expected",
    [
        ("src/extract.py", "SRC", True),
        ("src/extract.py", "Src/Extract.py", True),
        ("src-other/extract.py", "SRC", False),
        ("./SRC/extract.py", "src", True),
    ],
)
def test_projection_keeps_windows_scope_case_semantics(
    location, scope, expected, monkeypatch, tmp_path
):
    import ntpath

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import project_scan_artifacts as projection

    monkeypatch.setattr(projection, "normcase", ntpath.normcase)
    parent = tmp_path / "parent"
    source = parent / "child"
    source.mkdir(parents=True)
    finding = {"locations": [{"path": location}], "provenance": {"source": "local_plugin"}}
    result = projection.project_scan_artifacts(
        "parent",
        "child",
        source,
        parent,
        {"scan": {"scope": {"includePaths": [scope], "excludePaths": []}}},
        {"findings": [finding]},
        {"completeness": "complete", "surfaces": [], "deferred": [], "explicitExclusions": []},
    )
    assert result["sourceFindings"] == ([finding] if expected else [])
    if expected:
        assert result["draft"]["findings"][0]["provenance"]["sourceFindingIds"] == ["child:0"]


@pytest.mark.parametrize("windows", [False, True])
def test_projection_many_selected_paths_keeps_boundaries_and_source_order(
    windows, monkeypatch, tmp_path
):
    import ntpath
    import posixpath

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import project_scan_artifacts as projection

    monkeypatch.setattr(projection, "normcase", ntpath.normcase if windows else posixpath.normcase)
    parent = tmp_path / "parent"
    source = parent / "child"
    source.mkdir(parents=True)
    findings = []
    expected = []
    for index in range(1000):
        paths = {
            0: [f"src/selected/{index}.py"],
            1: [f"src/selected/{index}.py.extra"],
            2: [f"src/selected-other/{index}.py"],
            3: ["outside/file.py", f"DOCS/nested/{index}.md"],
        }[index % 4]
        finding = {
            "locations": [{"path": path} for path in paths],
            "provenance": {"source": "local_plugin"},
        }
        findings.append(finding)
        if index % 4 == 0 or (windows and index % 4 == 3):
            expected.append(finding)

    def project(scopes):
        return projection.project_scan_artifacts(
            "parent",
            "child",
            source,
            parent,
            {"scan": {"scope": {"includePaths": scopes, "excludePaths": []}}},
            {"findings": findings},
            {"completeness": "complete", "surfaces": [], "deferred": [], "explicitExclusions": []},
        )

    projected = project([f"src/selected/{index}.py" for index in range(1000)] + ["./docs/"])
    assert projected["sourceFindings"] == expected
    for index, (draft, original) in enumerate(
        zip(projected["draft"]["findings"], expected, strict=True)
    ):
        assert draft["locations"] == original["locations"]
        assert draft["provenance"]["sourceFindingIds"] == [f"child:{index}"]
    assert project(["."])["sourceFindings"] == findings


def test_coverage_union_keeps_distinct_rows_with_the_same_id(workbench_api) -> None:
    coverage = {
        "completeness": "partial",
        "surfaces": [{"id": "surface", "notes": "Earlier observation"}],
    }
    addition = {
        "surfaces": [
            {"notes": "Earlier observation", "id": "surface"},
            {"id": "surface", "notes": "Later observation"},
        ],
        "openQuestions": [{"question": "Remaining coverage?"}],
    }
    workbench_api["saved_results"].union_coverage(coverage, addition)
    assert coverage == {
        "completeness": "partial",
        "surfaces": [
            {"id": "surface", "notes": "Earlier observation"},
            {"id": "surface", "notes": "Later observation"},
        ],
        "explicitExclusions": [],
        "deferred": [],
        "openQuestions": [{"question": "Remaining coverage?"}],
    }
