"""Keep model-file identity and host publication authority across Deep Scan recovery."""

import json
import shutil
import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import (
    begin_deep_scan,
    empty_target_paths,
    mark_deep_coordinator_succeeded,
    run_workbench,
    scan_command,
    windows_file_backend,
    write_completed_contract,
)

MODEL_FILES = ("model_instructions_file", "experimental_compact_prompt_file", "model_catalog_json")


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    ("error_code", "missing_root"), [(2, False), (3, False), (5, False), (3, True)]
)
def test_windows_preview_probe_distinguishes_missing_checkpoint_from_invalid_output(
    tmp_path, workbench_db, monkeypatch, error_code, missing_root
):
    import finalize_scan_contract as finalizer
    import windows_scan_local_files
    from workbench.storage import require_host_deep_scan_output

    directory = tmp_path / "scan"
    directory.mkdir()
    scan = workbench_db.execute(
        "SELECT ? AS scan_dir, 'current' AS id", (str(directory),)
    ).fetchone()
    backend = windows_file_backend()
    native_error = windows_scan_local_files.WindowsScanLocalFileError
    backend.open_read_fd.side_effect = native_error(error_code, "native checkpoint probe")
    if missing_root:
        backend.scan_root_identity.side_effect = native_error(3, "scan directory unavailable")
    monkeypatch.setattr(finalizer.os, "supports_dir_fd", set())
    monkeypatch.setattr(finalizer, "_is_windows", lambda: True)
    monkeypatch.setattr(finalizer, "_windows_scan_local_files", lambda: backend)
    if error_code in (2, 3) and not missing_root:
        require_host_deep_scan_output(workbench_db, scan)
    else:
        with pytest.raises(SystemExit, match="Cannot inspect the saved Deep Scan checkpoint"):
            require_host_deep_scan_output(workbench_db, scan)


def model_inputs(path: Path, key: str) -> dict:
    return {**dict.fromkeys(MODEL_FILES), key: {"path": str(path), "sha256": "a" * 64}}


@pytest.mark.parametrize("key", MODEL_FILES)
def test_only_matching_model_files_select_the_pending_host_result(tmp_path: Path, key: str) -> None:
    state, target = empty_target_paths(tmp_path)
    (target / "source.py").write_text("print('test')\n")
    inputs = model_inputs(tmp_path / "settings", key)
    unchanged = ("--model-file-inputs-json", json.dumps(inputs))

    def begin(owner: str, *extra: str, check: bool = True):
        return begin_deep_scan(
            state,
            owner,
            "--target-path",
            str(target),
            "--scan-root",
            str(tmp_path / "scans"),
            *extra,
            check=check,
            environment={"CODEX_HOME": str(tmp_path / "home")},
        )

    assert begin("owner", "--probe-model-file-inputs") == {"newScanTarget": str(target)}
    assert (
        "Invalid Deep Scan model file"
        in begin("owner", "--model-file-inputs-json", '{"bad":"receipt"}', check=False)["stderr"]
    )
    original = begin("owner", *unchanged)["deepScan"]
    assert original["modelFileInputs"] == inputs
    scan_id, scan_dir = original["scanId"], Path(original["scanDir"])
    assert begin("owner", "--probe-model-file-inputs")["deepScan"]["scanId"] == scan_id
    assert begin("owner", "--model-file-inputs-json", "{}")["deepScan"]["modelFileInputs"] == inputs
    mark_deep_coordinator_succeeded(state, scan_id, scan_dir)
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="source.py", coverage_mode="deep_repository"
    )
    scan_command(state, "complete-scan", scan_id)
    # A pending native result, even for the original owner, requires the current inputs.
    assert begin("owner", "--probe-model-file-inputs") == {"newScanTarget": str(target)}
    assert begin("other", "--join-only", *unchanged)["deepScan"]["scanId"] == scan_id
    for change in (
        None,
        {**inputs[key], "sha256": "b" * 64},
        {**inputs[key], "path": str(tmp_path / "moved")},
    ):
        assert begin(
            "other", "--join-only", "--model-file-inputs-json", json.dumps({**inputs, key: change})
        ) == {"newScanTarget": str(target)}
    assert begin("other", *unchanged)["deepScan"]["scanId"] == scan_id
    fresh = begin("other", "--model-file-inputs-json", json.dumps(dict.fromkeys(MODEL_FILES)))[
        "deepScan"
    ]
    assert fresh["scanId"] != scan_id


def register_deep(tmp_path: Path, scan_inputs: dict, *, alias: bool = False):
    state, target = empty_target_paths(tmp_path)
    (target / "source.py").write_text("print('test')\n")
    directory = tmp_path / "scan"
    directory.mkdir(mode=0o700)
    requested = target
    if alias:
        requested = tmp_path / "original-link"
        requested.symlink_to(target, target_is_directory=True)
    recipe = {
        "mode": "deep",
        "repository": str(requested),
        "config": {},
        "target": {"kind": "paths", "paths": ["source.py"]},
        "scanInputs": scan_inputs,
    }
    registered = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(directory),
        "--registration-json-stdin",
        input_text=json.dumps({"recipe": recipe}),
    )
    scan_id = registered["scanId"]
    scan_command(state, "set-scan-thread", scan_id, "--thread-id", "owner")
    return state, target, directory, scan_id


@pytest.mark.parametrize("version", (2, 3))
def test_unfinished_preview_cannot_start_another_host_run(tmp_path: Path, version: int) -> None:
    state, _, directory, scan_id = register_deep(
        tmp_path, {"modelFileInputs": dict.fromkeys(MODEL_FILES)}
    )
    checkpoint = directory / "artifacts" / "deep-scan" / "checkpoint.json"
    checkpoint.parent.mkdir(parents=True)
    original = json.dumps({"version": version, "passes": [], "mergedScanIds": []}).encode()
    checkpoint.write_bytes(original)
    for response in (
        scan_command(state, "get-cli-scan-resume", scan_id, check=False),
        begin_deep_scan(state, "owner", "--scan-id", scan_id, check=False),
    ):
        assert response["returncode"] != 0
        assert "original SDK version" in response["stderr"]
    assert checkpoint.read_bytes() == original
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        assert db.execute(
            "SELECT count(*) FROM deep_scan_runs WHERE scan_id=?", (scan_id,)
        ).fetchone() == (0,)


@pytest.mark.parametrize("checkout", ["missing", "replacement-link", "loop", "original-alias"])
def test_host_seal_recovers_without_the_original_checkout(tmp_path: Path, checkout: str) -> None:
    inputs = model_inputs(tmp_path / "original", MODEL_FILES[0])
    state, target, directory, scan_id = register_deep(
        tmp_path, {"modelFileInputs": inputs}, alias=checkout == "original-alias"
    )
    started = begin_deep_scan(
        state,
        "owner",
        "--scan-id",
        scan_id,
        "--model-file-inputs-json",
        json.dumps(dict.fromkeys(MODEL_FILES)),
    )
    assert started["deepScan"]["modelFileInputs"] == inputs
    mark_deep_coordinator_succeeded(state, scan_id, directory)
    write_completed_contract(
        directory, scan_id, target, relative_path="source.py", coverage_mode="deep_repository"
    )
    scan_command(state, "prepare-scan-completion", scan_id)
    manifest = (directory / "scan-manifest.json").read_bytes()
    shutil.rmtree(target)
    if checkout == "replacement-link":
        replacement = tmp_path / "replacement"
        replacement.mkdir()
        target.symlink_to(replacement, target_is_directory=True)
    elif checkout == "loop":
        target.symlink_to(target, target_is_directory=True)
    findings = directory / "findings.json"
    saved_findings = findings.read_bytes()
    findings.write_bytes(saved_findings + b" ")
    invalid = scan_command(state, "get-cli-scan-resume", scan_id, check=False)
    assert "Cannot resume sealed scan" in invalid["stderr"]
    findings.write_bytes(saved_findings)
    result = scan_command(state, "get-cli-scan-resume", scan_id)
    assert result["sealedProducerVersion"] == json.loads(manifest)["scan"]["producer"]["version"]
    assert result["recipe"]["scanInputs"]["modelFileInputs"] == inputs
    assert result["targetPath"] == str(target)
    assert result["recipe"]["repository"] == str(
        tmp_path / "original-link" if checkout == "original-alias" else target
    )
    scan_command(state, "complete-scan", scan_id)
    assert (directory / "scan-manifest.json").read_bytes() == manifest


def test_registered_legacy_receipt_retains_only_the_known_input(tmp_path: Path) -> None:
    instructions = model_inputs(tmp_path / "selected.md", "model_instructions_file")[
        "model_instructions_file"
    ]
    state, _, _, scan_id = register_deep(
        tmp_path, {"modelFileInputs": {"model_instructions_file": instructions}}
    )
    state_view = begin_deep_scan(
        state,
        "owner",
        "--scan-id",
        scan_id,
        "--model-file-inputs-json",
        json.dumps(dict.fromkeys(MODEL_FILES)),
    )["deepScan"]
    assert state_view["modelFileInputs"] == {"model_instructions_file": instructions}


@pytest.mark.parametrize(
    ("field", "legacy_key"),
    [
        ("model_instructions_file", "modelInstructionsFileSha256"),
        ("experimental_compact_prompt_file", "compactPromptFileSha256"),
        ("model_catalog_json", "modelCatalogFileSha256"),
    ],
)
@pytest.mark.parametrize("digest", [None, "b" * 64])
def test_rejoin_uses_a_flat_historical_recipe_receipt(
    tmp_path: Path, field: str, legacy_key: str, digest: str | None
) -> None:
    original_inputs = {legacy_key: digest}
    state, _, _, scan_id = register_deep(tmp_path, original_inputs)
    new_claim = json.dumps(model_inputs(tmp_path / "different-setting", field))
    for _ in range(2):
        response = begin_deep_scan(
            state, "owner", "--scan-id", scan_id, "--model-file-inputs-json", new_claim
        )
        assert response["deepScan"]["modelFileInputs"] == {
            field: None if digest is None else {"sha256": digest}
        }
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        (stored,) = db.execute("SELECT recipe_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    assert json.loads(stored)["scanInputs"] == original_inputs


@pytest.mark.parametrize(
    "saved",
    [
        {"modelInstructionsFileSha256": "malformed"},
        {"modelFileInputs": {"model_instructions_file": {"sha256": "c" * 64}}},
    ],
)
def test_invalid_saved_inputs_do_not_become_historical_receipts(
    tmp_path: Path, saved: dict
) -> None:
    state, _, _, scan_id = register_deep(tmp_path, saved)
    rejected = begin_deep_scan(state, "owner", "--scan-id", scan_id, check=False)
    assert rejected["returncode"] != 0
    assert "model file" in rejected["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        assert db.execute(
            "SELECT COUNT(*) FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
        ).fetchone() == (0,)
