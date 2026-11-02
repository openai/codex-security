from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from test_workbench_completion_binding import (
    _seal_draft,
    _start_deep_scan_with_draft_findings,
    register_cli_scan,
)
from workbench_test_support import (
    empty_target_paths,
    mark_deep_coordinator_succeeded,
    run_workbench,
    scan_command,
    write_completed_contract,
)


@pytest.mark.parametrize("recipe_kind", ["standard", "import", "mock", "unbound"])
def test_standard_seals_the_selected_registration_bundle(tmp_path: Path, recipe_kind: str) -> None:
    state, target = empty_target_paths(tmp_path)
    output = tmp_path / "scan"
    output.mkdir(mode=0o700)
    plugin = tmp_path / "plugin"
    (plugin / "skills").mkdir(parents=True)
    (plugin / "references").mkdir()
    reference = plugin / "references" / "scan.md"
    reference.write_bytes(b"Scan instructions\n")
    expected = hashlib.sha256(
        b"references/scan.md\0" + hashlib.sha256(reference.read_bytes()).digest()
    )
    recipe = {
        "repository": str(target),
        "mode": "standard",
        "target": {"kind": "repository", "paths": []},
        "config": {},
    }
    if recipe_kind == "import":
        recipe["import"] = {"format": "sarif", "sourcePath": "report.sarif"}
    if recipe_kind == "mock":
        recipe["mock"] = True
    scan_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(output),
        "--registration-json-stdin",
        environment={
            "CODEX_SECURITY_PLUGIN_ROOT": str(plugin),
            "_CODEX_SECURITY_INSTRUCTION_ROOT": "" if recipe_kind == "unbound" else str(plugin),
        },
        input_text=json.dumps({"recipe": recipe}),
    )["scanId"]
    reference.write_bytes(b"Updated after registration\n")
    write_completed_contract(output, scan_id, target)
    scan_command(state, "complete-scan", scan_id)
    producer = json.loads((output / "scan-manifest.json").read_bytes())["scan"]["producer"]
    if recipe_kind == "standard":
        assert producer["instructionDigests"] == ["sha256:" + expected.hexdigest()]
    else:
        assert "instructionDigests" not in producer


@pytest.mark.parametrize("unknown_worker", [False, True])
def test_deep_seal_collects_only_started_workers(tmp_path: Path, unknown_worker: bool) -> None:
    state, scan_id, output = _start_deep_scan_with_draft_findings(tmp_path)
    parent, first_worker, later_worker = ("sha256:" + digit * 64 for digit in "acb")
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        db.execute("UPDATE scans SET instruction_digest = ? WHERE id = ?", (parent, scan_id))
        for index, (kind, started, digest, seconds) in enumerate(
            [
                ("discovery", True, parent, "00"),
                ("discovery", True, first_worker, "01"),
                ("dedup", True, None if unknown_worker else later_worker, "01.000001"),
                ("discovery", True, first_worker, "01.000002"),
                ("discovery", False, None, "02"),
            ]
        ):
            timestamp = f"2026-01-01T00:00:{seconds}Z"
            db.execute(
                """INSERT INTO deep_scan_workers
                (id, scan_id, kind, status, prompt_path, artifact_dir, created_at,
                 started_at, updated_at, instruction_digest)
                VALUES (?, ?, ?, 'canceled', ?, ?, ?, ?, ?, ?)""",
                (
                    str(index),
                    scan_id,
                    kind,
                    "prompt.md",
                    str(output),
                    timestamp,
                    timestamp if started else None,
                    timestamp,
                    digest,
                ),
            )
    scan_command(state, "complete-scan", scan_id)
    producer = json.loads((output / "scan-manifest.json").read_bytes())["scan"]["producer"]
    if unknown_worker:
        assert "instructionDigests" not in producer
    else:
        assert producer["instructionDigests"] == [parent, first_worker, later_worker]


@pytest.mark.parametrize("measured", [False, True], ids=["absent", "matching"])
@pytest.mark.parametrize("restore_draft", [False, True], ids=["sealed", "restored-draft"])
def test_replaying_a_seal_preserves_its_original_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, measured: bool, restore_draft: bool
) -> None:
    state, target = empty_target_paths(tmp_path)
    output = tmp_path / "scan"
    monkeypatch.setenv("_CODEX_SECURITY_INSTRUCTION_ROOT", str(Path(__file__).resolve().parents[1]))
    scan_id = register_cli_scan(state, target, output)["scanId"]
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        (registered,) = db.execute(
            "SELECT instruction_digest FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    assert registered
    reported = [registered] if measured else None
    write_completed_contract(output, scan_id, target)
    manifest = output / "scan-manifest.json"
    draft = manifest.read_bytes()
    if reported:
        document = json.loads(draft)
        document["scan"]["producer"]["instructionDigests"] = reported
        manifest.write_text(json.dumps(document))
    _seal_draft(output, target)
    original = manifest.read_bytes()
    scan_command(state, "prepare-scan-completion", scan_id)
    assert manifest.read_bytes() == original
    if measured:
        # Exercise replay from the admitted claim even when the registration measurement is lost.
        with sqlite3.connect(state / "workbench.sqlite3") as db:
            db.execute("UPDATE scans SET instruction_digest = NULL WHERE id = ?", (scan_id,))
    if restore_draft:
        manifest.write_bytes(draft)
    scan_command(state, "complete-scan", scan_id)
    completed = manifest.read_bytes()
    if not restore_draft:
        assert completed == original
    assert json.loads(completed)["scan"]["producer"].get("instructionDigests") == reported


@pytest.mark.parametrize("command", ["prepare-scan-completion", "complete-scan"])
def test_rejected_legacy_seal_does_not_pin_an_absent_instruction_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    state, target = empty_target_paths(tmp_path)
    output = tmp_path / "scan"
    monkeypatch.setenv("_CODEX_SECURITY_INSTRUCTION_ROOT", str(Path(__file__).resolve().parents[1]))
    scan_id = register_cli_scan(state, target, output)["scanId"]
    write_completed_contract(output, scan_id, target)
    path = output / "scan-manifest.json"
    draft = path.read_bytes()
    _seal_draft(output, target)
    legacy = json.loads(path.read_bytes())
    assert "instructionDigests" not in legacy["scan"]["producer"]
    minified = json.dumps(legacy, separators=(",", ":")).encode()
    path.write_bytes(minified)
    report = output / "report.md"
    report.write_text("Existing projection")

    rejected = scan_command(state, command, scan_id, check=False)
    assert rejected["returncode"] != 0
    assert "sealed scan manifest changed" in rejected["stderr"]
    assert path.read_bytes() == minified
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        measured, pin, receipt = db.execute(
            "SELECT instruction_digest, prepared_instruction_digests_json, seal_manifest_digest "
            "FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    assert measured and pin is None and receipt is None
    assert report.read_text() == "Existing projection"

    path.write_bytes(draft)
    scan_command(state, "complete-scan", scan_id)
    assert json.loads(path.read_bytes())["scan"]["producer"]["instructionDigests"] == [measured]


def test_completed_seal_receipt_authenticates_legacy_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, target = empty_target_paths(tmp_path)
    output = tmp_path / "scan"
    monkeypatch.setenv("_CODEX_SECURITY_INSTRUCTION_ROOT", str(Path(__file__).resolve().parents[1]))
    scan_id = register_cli_scan(state, target, output)["scanId"]
    write_completed_contract(output, scan_id, target)
    scan_command(state, "complete-scan", scan_id)
    path = output / "scan-manifest.json"
    original = path.read_bytes()
    manifest = json.loads(original)
    assert manifest["scan"]["producer"]["instructionDigests"]
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        db.execute(
            "UPDATE scans SET prepared_instruction_digests_json = NULL, instruction_digest = NULL "
            "WHERE id = ?",
            (scan_id,),
        )
        assert db.execute(
            "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == ("sha256:" + hashlib.sha256(original).hexdigest(),)

    scan_command(state, "complete-scan", scan_id)
    assert path.read_bytes() == original
    manifest["scan"]["producer"]["instructionDigests"] = ["sha256:" + "f" * 64]
    path.write_bytes((json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode())
    rejected = scan_command(state, "complete-scan", scan_id, check=False)
    assert rejected["returncode"] != 0
    assert "sealed scan manifest changed after completion" in rejected["stderr"]


@pytest.mark.parametrize(
    ("command", "claim"),
    [
        ("complete-scan", "forged"),
        ("export-findings", "forged"),
        ("list-findings", "forged"),
        ("complete-scan", "omitted"),
        ("complete-scan", "matching"),
    ],
)
def test_completed_legacy_row_checks_restored_draft_before_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, claim: str
) -> None:
    state, target = empty_target_paths(tmp_path)
    output = tmp_path / "scan"
    monkeypatch.setenv("_CODEX_SECURITY_INSTRUCTION_ROOT", str(Path(__file__).resolve().parents[1]))
    scan_id = register_cli_scan(state, target, output)["scanId"]
    write_completed_contract(output, scan_id, target)
    path = output / "scan-manifest.json"
    draft = json.loads(path.read_bytes())
    findings = output / "findings.json"
    draft_findings = findings.read_bytes()
    coverage = output / "coverage.json"
    draft_coverage = coverage.read_bytes()
    scan_command(state, "complete-scan", scan_id)
    measured = json.loads(path.read_bytes())["scan"]["producer"]["instructionDigests"]
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        db.execute(
            "UPDATE scans SET seal_manifest_digest = NULL, prepared_instruction_digests_json = NULL "
            "WHERE id = ?",
            (scan_id,),
        )
        db.execute(
            "UPDATE finding_occurrences SET details_json = '{}' WHERE scan_id = ?", (scan_id,)
        )
    if claim != "omitted":
        draft["scan"]["producer"]["instructionDigests"] = (
            ["sha256:" + "f" * 64] if claim == "forged" else measured
        )
    path.write_text(json.dumps(draft))
    findings.write_bytes(draft_findings)
    coverage.write_bytes(draft_coverage)
    (output / "report.md").write_text("Existing projection")
    (output / "report.html").write_text("Existing export")
    previous = {
        p: p.read_bytes()
        for p in (path, findings, coverage, output / "report.md", output / "report.html")
    }

    result = scan_command(state, command, scan_id, check=False)
    if claim != "forged":
        assert result["returncode"] == 0, result["stderr"]
        assert json.loads(path.read_bytes())["scan"]["sealedAt"]
        return
    if command == "list-findings":
        assert result["returncode"] == 0  # Finding history tolerates unavailable canonical details.
    else:
        assert result["returncode"] != 0
        assert "instructionDigests" in result["stderr"]
    assert {p: p.read_bytes() for p in previous} == previous
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        assert db.execute(
            "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == (None,)
        assert db.execute(
            "SELECT details_json FROM finding_occurrences WHERE scan_id = ?", (scan_id,)
        ).fetchone() == ("{}",)


@pytest.mark.parametrize("case", ["contradictory", "unmeasured", "stopped"])
def test_rejects_unsupported_instruction_digests_in_a_first_seen_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    state, target = empty_target_paths(tmp_path)
    output = tmp_path / "scan"
    if case == "unmeasured":
        monkeypatch.delenv("_CODEX_SECURITY_INSTRUCTION_ROOT", raising=False)
    else:
        monkeypatch.setenv(
            "_CODEX_SECURITY_INSTRUCTION_ROOT", str(Path(__file__).resolve().parents[1])
        )
    scan_id = register_cli_scan(state, target, output)["scanId"]
    write_completed_contract(output, scan_id, target)
    path = output / "scan-manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["scan"]["producer"]["instructionDigests"] = ["sha256:" + "b" * 64]
    if case == "stopped":
        manifest["scan"].update(status="failed", preservedSources={})
    path.write_text(json.dumps(manifest))
    _seal_draft(output, target)
    sealed = path.read_bytes()

    if case == "stopped":
        report = output / "report.md"
        report.write_text("Existing projection")
        scan_command(state, "fail-scan", scan_id, "--message", "Stopped by host")
        rejected = scan_command(state, "recover-scan-results", scan_id, check=False)
    else:
        command = "complete-scan" if case == "unmeasured" else "prepare-scan-completion"
        rejected = scan_command(state, command, scan_id, check=False)
    assert rejected["returncode"] != 0
    assert "instructionDigests" in rejected["stderr"]
    assert path.read_bytes() == sealed
    if case == "stopped":
        assert report.read_text() == "Existing projection"
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        assert db.execute(
            "SELECT prepared_instruction_digests_json, seal_manifest_digest FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone() == (None, None)


def test_get_scan_exposes_the_threat_model_only_for_a_supported_sealed_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, target = empty_target_paths(tmp_path)
    output = tmp_path / "scan"
    monkeypatch.setenv("_CODEX_SECURITY_INSTRUCTION_ROOT", str(Path(__file__).resolve().parents[1]))
    scan_id = register_cli_scan(state, target, output)["scanId"]
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        (measured,) = db.execute(
            "SELECT instruction_digest FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    write_completed_contract(output, scan_id, target)
    path = output / "scan-manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["scan"]["producer"]["instructionDigests"] = [measured]
    manifest["scan"]["threatModel"] = {"summary": "Queue producers cross a service boundary."}
    path.write_text(json.dumps(manifest))
    _seal_draft(output, target)
    matched = scan_command(state, "get-scan", scan_id)["scan"]
    assert matched["threatModelAvailable"]
    assert Path(matched["threatModelPath"]).is_file()

    sealed = json.loads(path.read_bytes())
    sealed["scan"]["producer"]["instructionDigests"] = ["sha256:" + "f" * 64]
    path.write_bytes((json.dumps(sealed, sort_keys=True, indent=2) + "\n").encode())
    unsupported = scan_command(state, "get-scan", scan_id)["scan"]
    assert not unsupported["threatModelAvailable"]
    assert "threatModelPath" not in unsupported
    assert "threatModelProvenance" not in unsupported
    assert "threatModel" not in unsupported["artifacts"]


def test_resuming_deep_scan_rejects_an_unmeasured_sealed_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_workbench_standard_deep_results import deep_scan_fixture

    monkeypatch.delenv("_CODEX_SECURITY_INSTRUCTION_ROOT", raising=False)
    state, _, target, output, scan_id = deep_scan_fixture(tmp_path, budget=True)
    scan_command(state, "set-scan-thread", scan_id, "--thread-id", "standard-worker-thread")
    mark_deep_coordinator_succeeded(state, scan_id, output)
    write_completed_contract(output, scan_id, target, coverage_mode="deep_repository")
    path = output / "scan-manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["scan"]["producer"]["instructionDigests"] = ["sha256:" + "b" * 64]
    path.write_text(json.dumps(manifest))
    _seal_draft(output, target)
    sealed = path.read_bytes()

    rejected = scan_command(state, "get-cli-scan-resume", scan_id, check=False)
    assert rejected["returncode"] != 0
    assert "instructionDigests" in rejected["stderr"]
    assert path.read_bytes() == sealed


@pytest.mark.parametrize(
    ("edit", "interrupted_command"),
    [
        ("replace", None),
        ("remove", None),
        ("add", None),
        ("replace", "prepare-scan-completion"),
        ("remove", "complete-scan"),
    ],
)
def test_completion_rejects_changed_prepared_instruction_digests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, edit: str, interrupted_command: str | None
) -> None:
    state, target = empty_target_paths(tmp_path)
    output = tmp_path / "scan"
    if edit != "add":
        monkeypatch.setenv(
            "_CODEX_SECURITY_INSTRUCTION_ROOT", str(Path(__file__).resolve().parents[1])
        )
    else:
        monkeypatch.delenv("_CODEX_SECURITY_INSTRUCTION_ROOT", raising=False)
    scan_id = register_cli_scan(state, target, output)["scanId"]
    write_completed_contract(output, scan_id, target)
    if interrupted_command:
        from test_workbench_standard_deep_results import run_workbench_with_fault

        interrupted = run_workbench_with_fault(
            tmp_path / "interrupt_after_seal.py",
            state,
            tmp_path / "codex-home",
            "import os\nworkbench_db.published_manifest_digest = lambda *_: os._exit(75)\n",
            interrupted_command,
            "--scan-id",
            scan_id,
        )
        assert interrupted.returncode == 75, interrupted.stderr
    else:
        scan_command(state, "prepare-scan-completion", scan_id)
    manifest = output / "scan-manifest.json"
    prepared = manifest.read_bytes()
    document = json.loads(prepared)
    producer = document["scan"]["producer"]
    assert ("instructionDigests" in producer) == (edit != "add")
    if edit == "remove":
        del producer["instructionDigests"]
    else:
        producer["instructionDigests"] = ["sha256:" + "f" * 64]
    manifest.write_bytes((json.dumps(document, indent=2, sort_keys=True) + "\n").encode())
    for command in ("complete-scan", "prepare-scan-completion"):
        rejected = scan_command(state, command, scan_id, check=False)
        assert rejected["returncode"] != 0
        assert "producer" in rejected["stderr"]

    manifest.write_bytes(prepared)
    scan_command(state, "complete-scan", scan_id)
    assert manifest.read_bytes() == prepared


@pytest.mark.parametrize(
    ("command", "edit"),
    [("fail-scan", "replace"), ("cancel-scan", "remove"), ("cancel-scan", None)],
)
def test_stop_preserves_the_prepared_instruction_digests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, edit: str | None
) -> None:
    from test_workbench_prompt_only_scan import start_headless_standard_scan

    state, target = empty_target_paths(tmp_path)
    (target / "fixture.py").write_text("value = 1\n")
    monkeypatch.setenv("_CODEX_SECURITY_INSTRUCTION_ROOT", str(Path(__file__).resolve().parents[1]))
    thread = "owner"
    scan = start_headless_standard_scan(state, target, tmp_path / "scans", thread_id=thread)["scan"]
    scan_id, folder = scan["scanId"], Path(scan["scanDir"])
    token = ("--claim-token", scan["handoffClaimToken"])
    write_completed_contract(folder, scan_id, target)
    scan_command(state, "prepare-scan-completion", scan_id, *token)
    path = folder / "scan-manifest.json"
    prepared = path.read_bytes()
    manifest = json.loads(prepared)
    producer = manifest["scan"]["producer"]
    expected = producer["instructionDigests"]
    if edit:
        if edit == "remove":
            del producer["instructionDigests"]
        else:
            producer["instructionDigests"] = ["sha256:" + "d" * 64]
        path.write_bytes((json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode())
        (folder / "report.md").write_text("Existing projection")
        (folder / "report.html").write_text("Existing export")

    args = ("--thread-id", thread) if command == "cancel-scan" else (*token, "--message", "stopped")
    scan_command(state, command, scan_id, *args)
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        status, recorded, warnings = db.execute(
            "SELECT status, seal_manifest_digest, completion_warnings_json FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    assert status == "failed"
    if edit:
        assert recorded is None
        assert "instructionDigests changed after preparation" in warnings
        assert (folder / "report.md").read_text() == "Existing projection"
        assert (folder / "report.html").read_text() == "Existing export"
        path.write_bytes(prepared)
        scan_command(state, "preserve-scan-results", scan_id, "--thread-id", thread, *token)
    else:
        assert recorded == "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    terminal = json.loads(path.read_bytes())["scan"]
    assert terminal["status"] == ("canceled" if command == "cancel-scan" else "failed")
    assert terminal["producer"]["instructionDigests"] == expected
