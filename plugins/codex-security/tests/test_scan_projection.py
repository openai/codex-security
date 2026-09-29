from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_workbench_scan_composition import register
from workbench_test_support import run_workbench, write_completed_contract


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
    workbench_api["saved_results"].merge_coverage(coverage, addition)
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


def completed_projection(
    parent_dir, parent, child_dir, child, *, descriptor_limit=None, **overrides
):
    identity = parent_dir.stat()
    request = {
        "parentScanId": parent["scanId"],
        "sourceScanId": child["scanId"],
        "sourceDirectory": str(child_dir),
        "parentDirectory": str(parent_dir),
        "expectedParentIdentity": {"dev": str(identity.st_dev), "ino": str(identity.st_ino)},
        **overrides,
    }
    command = [sys.executable, "-I", "-X", "utf8", "-B"]
    if descriptor_limit is not None:
        command.extend(
            [
                "-c",
                (
                    "import resource, runpy, sys; "
                    f"resource.setrlimit(resource.RLIMIT_NOFILE, ({descriptor_limit}, "
                    "resource.getrlimit(resource.RLIMIT_NOFILE)[1])); "
                    "runpy.run_path(sys.argv.pop(), run_name='__main__')"
                ),
            ]
        )
    command.append(str(Path(__file__).parents[1] / "scripts/project_scan_artifacts.py"))
    return subprocess.run(
        command,
        input=json.dumps(request),
        capture_output=True,
        text=True,
        check=False,
    )


def test_stopped_projection_shared_fixture(projection_fixture, workbench_api, monkeypatch):
    state, parent_dir, parent, child_dir, child, fixture = projection_fixture
    originals = json.loads((child_dir / "findings.json").read_text())["findings"]
    completed = completed_projection(parent_dir, parent, child_dir, child)
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


@pytest.mark.parametrize("length, collision", [(215, False), (215, True), (220, True)])
def test_projection_retains_long_writeups_and_evidence(
    tmp_path, workbench_api, monkeypatch, length, collision
):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    state = tmp_path / "state"
    parent_dir = tmp_path / "parent"
    parent = register(state, target, parent_dir, mode="deep")
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    slug = "a" * length
    base_slug = f"{child['scanId']}-{slug}"
    report_path = f"findings/{slug}/{slug}.md"
    source = child_dir / report_path
    source.parent.mkdir(parents=True)
    source.write_text("# Synthetic long report\n")
    evidence_name = f"{base_slug}.md" if length == 215 and collision else "trace.txt"
    evidence = source.parent / evidence_name
    evidence.write_text("Synthetic supporting evidence\n")
    findings_path = child_dir / "findings.json"
    document = json.loads(findings_path.read_text())
    document["findings"][0]["writeup"] = {"reportPath": report_path}
    if length > 215 and collision:
        # A normal source report reserves the first compacted destination name.
        other_slug = hashlib.sha256(base_slug.encode()).hexdigest()
        other = copy.deepcopy(document["findings"][0])
        other["identity"]["anchor"] = "other-synthetic-report"
        other["writeup"]["reportPath"] = f"findings/{other_slug}/{other_slug}.md"
        document["findings"].append(other)
        other_source = child_dir / other["writeup"]["reportPath"]
        other_source.parent.mkdir()
        other_source.write_text("# Other synthetic report\n")
    findings_path.write_text(json.dumps(document))
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])

    completed = completed_projection(parent_dir, parent, child_dir, child)
    assert completed.returncode == 0, completed.stderr
    live = json.loads(completed.stdout)["draft"]["findings"]
    assert len({finding["writeup"]["reportPath"] for finding in live}) == len(live)
    for finding, original in zip(live, document["findings"], strict=True):
        destination = parent_dir / finding["writeup"]["reportPath"]
        assert len(destination.name) <= 255
        assert (
            destination.read_bytes() == (child_dir / original["writeup"]["reportPath"]).read_bytes()
        )
    projected = parent_dir / live[0]["writeup"]["reportPath"]
    assert (projected.parent / evidence_name).read_bytes() == evidence.read_bytes()
    if not collision:
        assert projected.name == f"{base_slug}.md"
    if length > 215 and collision:
        assert Path(live[1]["writeup"]["reportPath"]).name == f"{child['scanId']}-{other_slug}.md"
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with workbench_api["connect"]() as connection:
        row = workbench_api["require_scan"](connection, child["scanId"])
        project = workbench_api["saved_results"]._stopped_child_draft
        stopped = project(workbench_api["_WORKBENCH_DB_CONTEXT"], row, parent_dir)
        assert project(workbench_api["_WORKBENCH_DB_CONTEXT"], row, parent_dir) == stopped
    assert [finding["writeup"] for finding in stopped["findings"]] == [
        finding["writeup"] for finding in live
    ]
    assert source.read_text() == "# Synthetic long report\n"
    assert evidence.read_text() == "Synthetic supporting evidence\n"


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
    _, parent_dir, parent, child_dir, child, _ = projection_fixture
    completed = completed_projection(parent_dir, parent, child_dir, child, **{field: value})
    assert completed.returncode != 0
    assert message in completed.stderr
    assert not (parent_dir / "findings").exists()


@pytest.mark.parametrize("directory", [False, True])
def test_completed_projection_rejects_symlink_evidence(projection_fixture, directory):
    _, parent_dir, parent, child_dir, child, _ = projection_fixture
    outside = parent_dir.parent / "outside-evidence.txt"
    if directory:
        outside.mkdir()
        (outside / "evidence.txt").write_text("Outside directory evidence")
    else:
        outside.write_text("Evidence outside the child must not be projected.")
    (child_dir / "findings/check/unsafe.txt").symlink_to(outside, target_is_directory=directory)
    completed = completed_projection(parent_dir, parent, child_dir, child)
    assert completed.returncode != 0
    assert "inside the scan directory" in completed.stderr
    assert not list((parent_dir / "findings").glob("*/unsafe.txt"))


@pytest.mark.parametrize(
    "depth, descriptor_limit",
    [
        pytest.param(
            260,
            256,
            marks=pytest.mark.skipif(sys.platform == "win32", reason="POSIX descriptor limit"),
        ),
        pytest.param(
            1050,
            None,
            marks=pytest.mark.skipif(
                sys.platform != "linux", reason="Evidence path exceeds other platforms' limits"
            ),
        ),
    ],
)
def test_completed_projection_copies_deep_evidence(projection_fixture, depth, descriptor_limit):
    _, parent_dir, parent, child_dir, child, fixture = projection_fixture
    source = child_dir / "findings/check"
    destination = parent_dir / f"findings/{child['scanId']}-check-4"
    components = ["d"] * depth
    source_leaf = source.joinpath(*components, "evidence.bin")
    destination_leaf = destination.joinpath(*components, "evidence.bin")
    try:
        directory = source
        for component in components:
            directory /= component
            directory.mkdir()
        source_leaf.write_bytes(b"\x00\xffSynthetic nested evidence")
        completed = completed_projection(
            parent_dir, parent, child_dir, child, descriptor_limit=descriptor_limit
        )
        assert completed.returncode == 0, completed.stderr
        assert destination_leaf.read_bytes() == source_leaf.read_bytes()
        assert len(json.loads(completed.stdout)["draft"]["findings"]) == len(
            fixture["expected"]["sourceFindingIndexes"]
        )
    finally:
        # Do not make test teardown depend on a recursive directory remover either.
        for leaf, root in ((source_leaf, source), (destination_leaf, destination)):
            leaf.unlink(missing_ok=True)
            directory = leaf.parent
            while directory != root:
                if directory.exists():
                    directory.rmdir()
                directory = directory.parent


@pytest.mark.parametrize("terminal", ["unsealed", "interrupted"])
def test_completed_projection_requires_completed_seal(projection_fixture, terminal):
    _, parent_dir, parent, child_dir, child, _ = projection_fixture
    path = child_dir / "scan-manifest.json"
    manifest = json.loads(path.read_text())
    if terminal == "unsealed":
        manifest["scan"].pop("sealedAt")
        manifest["scan"].pop("artifacts")
    else:
        manifest["scan"]["status"] = "interrupted"
    path.write_text(json.dumps(manifest))
    completed = completed_projection(parent_dir, parent, child_dir, child)
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
