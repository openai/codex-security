from __future__ import annotations

import copy
import json
import shutil
import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import recipe, register, run_workbench, write_completed_contract


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("target_state", ["deleted", "moved"])
@pytest.mark.parametrize("aliased", [False, True])
def test_sealed_resume_uses_stored_target_without_execution_inputs(
    tmp_path: Path, native: bool, target_state: str, aliased: bool
) -> None:
    state, target, directory = tmp_path / "state", tmp_path / "target", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("print('synthetic fixture')\n")
    requested_target = target / ".." / "target" if aliased else target
    scan = register(state, requested_target, directory)
    write_completed_contract(directory, scan["scanId"], target, relative_path="app.py")
    run_workbench(state, "prepare-scan-completion", "--scan-id", scan["scanId"])
    token = "00000000-0000-4000-8000-000000000001"
    if native:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET deep_scan_owner_thread_id = ?, handoff_claim_token = ? "
                "WHERE id = ?",
                ("synthetic-owner", token, scan["scanId"]),
            )
    registration = {
        "scanId": scan["scanId"],
        "threadId": "synthetic-owner",
        "claimToken": token,
        "recipe": recipe(requested_target),
    }
    original_recipe = copy.deepcopy(registration["recipe"])
    sealed = {
        name: (directory / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
    }
    if target_state == "deleted":
        shutil.rmtree(target)
    else:
        target.rename(tmp_path / "moved-target")
    if native:
        resumed = run_workbench(
            state,
            "register-cli-scan",
            "--repository",
            str(requested_target),
            "--scan-dir",
            str(directory),
            "--registration-json-stdin",
            input_text=json.dumps(registration),
        )
    else:
        resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
    assert resumed["scanId"] == scan["scanId"]
    assert resumed["recipe"] == original_recipe
    assert (
        resumed["sealedProducerVersion"]
        == json.loads(sealed["scan-manifest.json"])["scan"]["producer"]["version"]
    )
    assert {name: (directory / name).read_bytes() for name in sealed} == sealed
    completed = run_workbench(
        state,
        "complete-scan",
        "--scan-id",
        scan["scanId"],
        *(("--claim-token", token) if native else ()),
    )
    assert completed["scan"]["progress"]["status"] == "complete"
    assert {name: (directory / name).read_bytes() for name in sealed} == sealed


@pytest.mark.parametrize(
    ("scenario", "error"),
    [
        ("unsealed", "not a readable local directory"),
        ("tampered", "Cannot resume sealed scan"),
        ("owner", "another Codex thread"),
        ("claim", "another continuation"),
        ("target", "match its target, directory and mode"),
        ("output", "match its target, directory and mode"),
        ("mode", "match its target, directory and mode"),
        ("scope", "preserve the original scope"),
        ("recipe-repository", "repository must match"),
        ("relative-target", "absolute local directory path"),
        ("saved-repository", "repository must match"),
        ("canceled", "Only a running scan"),
    ],
)
def test_removed_target_does_not_bypass_native_registration_bindings(
    tmp_path: Path, scenario: str, error: str
) -> None:
    state, target, directory = tmp_path / "state", tmp_path / "target", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("print('synthetic fixture')\n")
    scan = register(state, target, directory)
    write_completed_contract(directory, scan["scanId"], target, relative_path="app.py")
    if scenario != "unsealed":
        run_workbench(state, "prepare-scan-completion", "--scan-id", scan["scanId"])
    token = "00000000-0000-4000-8000-000000000001"
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET deep_scan_owner_thread_id = ?, handoff_claim_token = ? WHERE id = ?",
            ("synthetic-owner", token, scan["scanId"]),
        )
        if scenario == "canceled":
            connection.execute(
                "UPDATE scans SET canceled_at = '2026-01-01T00:00:00Z' WHERE id = ?",
                (scan["scanId"],),
            )
        if scenario == "saved-repository":
            connection.execute(
                "UPDATE scans SET recipe_json = ? WHERE id = ?",
                (json.dumps(recipe(tmp_path / "other-target")), scan["scanId"]),
            )
    registration = {
        "scanId": scan["scanId"],
        "threadId": "synthetic-owner",
        "claimToken": token,
        "recipe": recipe(target),
    }
    if scenario == "owner":
        registration["threadId"] = "other-owner"
    if scenario == "claim":
        registration["claimToken"] = "00000000-0000-4000-8000-000000000002"
    if scenario == "mode":
        registration["recipe"]["mode"] = "deep"
    if scenario == "scope":
        registration["recipe"]["target"] = {"kind": "paths", "paths": ["app.py"]}
    if scenario in ("target", "recipe-repository"):
        registration["recipe"]["repository"] = str(tmp_path / "other-target")
    if scenario == "tampered":
        with (directory / "findings.json").open("a") as findings:
            findings.write(" ")
    output = directory
    if scenario == "output":
        output = tmp_path / "other-scan"
        shutil.copytree(directory, output)
    artifacts = {path.name: path.read_bytes() for path in directory.iterdir() if path.is_file()}
    shutil.rmtree(target)
    rejected = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        "target"
        if scenario == "relative-target"
        else str(tmp_path / "other-target" if scenario == "target" else target),
        "--scan-dir",
        str(output),
        "--registration-json-stdin",
        input_text=json.dumps(registration),
        check=False,
    )
    assert rejected["returncode"] != 0
    assert error in rejected["stderr"]
    assert {name: (directory / name).read_bytes() for name in artifacts} == artifacts
