"""Exercise sparse file-review declarations against a Standard scan's registered target."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import uuid
from pathlib import Path

import pytest
from test_workbench_completion_binding import register_cli_scan
from workbench_test_support import (
    get_scan,
    initialize_git_repository,
    load_script,
    read_draft_documents,
    run_workbench,
    scan_command,
    write_completed_contract,
)


@pytest.fixture
def review():
    return load_script("workbench_source_scopes").review_file_digests


def commit_files(repo: Path) -> None:
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "Add review inputs"], cwd=repo, check=True)


def registered_scan(tmp_path: Path, repo: Path, *exclusions: str) -> sqlite3.Row:
    state = tmp_path / "state"
    registration = register_cli_scan(
        state,
        repo,
        tmp_path / "scan",
        scan_target={"kind": "paths", "paths": ["src"]},
        recipe_fields={"excludePaths": list(exclusions)} if exclusions else None,
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(
            "SELECT * FROM scans WHERE id = ?", (registration["scanId"],)
        ).fetchone()


@pytest.mark.cross_platform
def test_reviewed_file_must_match_the_registered_blob_and_scope(tmp_path: Path, review) -> None:
    repo = tmp_path / "repo"
    initialize_git_repository(repo)
    (repo / "src").mkdir()
    source = repo / "src" / "selected.bin"
    payload = b"original\x00bytes"
    source.write_bytes(payload)
    (repo / ".gitignore").write_text("ignored.bin\n")
    (repo / "src" / "ignored.bin").write_bytes(payload)
    (repo / "src" / "selected").mkdir()
    (repo / "src" / "selected" / "tracked.bin").write_bytes(payload)
    commit_files(repo)
    scan = registered_scan(tmp_path, repo, "src/selected")

    selected = "src/selected.bin"
    assert review(scan, []) == {}
    for malformed in (None, False, 0, {}, "", selected, {selected: True}):
        with pytest.raises(SystemExit):
            review(scan, malformed)
    assert review(scan, [selected]) == {selected: hashlib.sha256(payload).hexdigest()}
    for invalid in (
        "README.md",
        "src/ignored.bin",
        "src/selected/tracked.bin",
        "src/missing",
        "src",
        "src/../src/selected.bin",
    ):
        with pytest.raises(SystemExit):
            review(scan, [selected, invalid])
    source.write_bytes(b"replaced\x00bytes")
    with pytest.raises(SystemExit):
        review(scan, [selected])


@pytest.mark.cross_platform
@pytest.mark.parametrize("conversion", ["autocrlf", "attributes"])
def test_receipt_hashes_crlf_checkout_of_lf_blob(tmp_path: Path, conversion: str, review) -> None:
    repo = tmp_path / "repo"
    initialize_git_repository(repo)
    target = repo / "component"
    (target / "src").mkdir(parents=True)
    path = "src/main.py"
    source = target / path
    source.write_bytes(b"pass\n")

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", *args], cwd=target)

    git("config", "core.autocrlf", "true" if conversion == "autocrlf" else "false")
    if conversion == "attributes":
        (target / ".gitattributes").write_text(f"{path} text eol=crlf\n")
    commit_files(target)
    source.unlink()
    git("checkout", "--", path)
    assert git("show", f"HEAD:component/{path}") == b"pass\n"
    assert source.read_bytes() == b"pass\r\n"
    scan = registered_scan(tmp_path, target)

    assert review(scan, [path]) == {path: hashlib.sha256(b"pass\r\n").hexdigest()}
    (target / ".gitattributes").write_text(f"{path} -text\n")
    with pytest.raises(SystemExit, match="registered Git blob"):
        review(scan, [path])


@pytest.mark.cross_platform
@pytest.mark.parametrize("driver", ["clean", "process"])
def test_receipt_does_not_execute_git_filter_commands(tmp_path: Path, driver: str, review) -> None:
    repo = tmp_path / "repo"
    initialize_git_repository(repo)
    (repo / "src").mkdir()
    source = repo / "src" / "main.py"
    source.write_bytes(b"pass\n")
    commit_files(repo)
    scan = registered_scan(tmp_path, repo)
    name = "fixture=value" if os.name == "nt" else os.fsdecode(b"fixture=\xff")
    (repo / ".gitattributes").write_bytes(os.fsencode(f"*.py text filter={name}\n"))
    command = "echo ran > filter-ran && echo pass"
    subprocess.run(["git", "config", f"filter.{name}.{driver}", command], cwd=repo, check=True)
    subprocess.run(["git", "config", f"filter.{name}.required", "true"], cwd=repo, check=True)
    source.write_bytes(b"pass\r\n")
    assert review(scan, ["src/main.py"]) == {"src/main.py": hashlib.sha256(b"pass\r\n").hexdigest()}
    source.write_bytes(b"changed\n")
    with pytest.raises(SystemExit, match="registered Git blob"):
        review(scan, ["src/main.py"])
    assert not (repo / "filter-ran").exists()


@pytest.mark.cross_platform
def test_reviewed_file_must_belong_to_the_saved_directory_snapshot(tmp_path: Path, review) -> None:
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    if os.name == "posix":
        (repo / r"notes\old.txt").write_bytes(b"notes")
    (src / ".ignore").write_text("*.temporary\n")
    for name in ("a", "b", "c"):
        (src / name).write_bytes(name.encode())
    metadata = src / ".svn"
    metadata.mkdir()
    (metadata / "entries").write_bytes(b"a")
    scan = registered_scan(tmp_path, repo, "src/c")

    assert scan["target_revision"] == "unversioned"
    assert review(scan, ["src/a"]) == {"src/a": hashlib.sha256(b"a").hexdigest()}
    with pytest.raises(SystemExit, match="outside the registered scope"):
        review(scan, ["src/a", "src/c"])
    with pytest.raises(SystemExit):
        review(scan, ["src/.svn/entries"])
    (src / "b").rename(src / "d")
    with pytest.raises(SystemExit):
        review(scan, ["src/d"])


def test_reviewed_file_rejects_a_symlink_to_matching_bytes(tmp_path: Path, review) -> None:
    repo = tmp_path / "repo"
    initialize_git_repository(repo)
    (repo / "src").mkdir()
    selected = repo / "src" / "reviewed"
    selected.write_bytes(b"same bytes")
    commit_files(repo)
    scan = registered_scan(tmp_path, repo)
    outside = tmp_path / "outside"
    outside.write_bytes(selected.read_bytes())
    selected.unlink()
    try:
        selected.symlink_to(outside)
    except OSError:
        pytest.skip("creating a symlink is unavailable")
    with pytest.raises(SystemExit):
        review(scan, ["src/reviewed"])


@pytest.mark.cross_platform
def test_exact_reviewed_paths_below_a_subdirectory_target(tmp_path: Path, review) -> None:
    repo = tmp_path / "repo"
    initialize_git_repository(repo)
    target = repo / "component"
    src = target / "src"
    src.mkdir(parents=True)
    (src / "Foo").write_bytes(b"first")
    alias = (src / "fOO").exists()
    if not alias:
        (src / "fOO").write_bytes(b"second")
    # A root-relative lookup would read a different blob from the registered one.
    (repo / "src").mkdir()
    (repo / "src" / "Foo").write_bytes(b"outer")
    commit_files(repo)
    scan = registered_scan(tmp_path, target)

    expected = {"src/Foo": hashlib.sha256(b"first").hexdigest()}
    if alias:
        with pytest.raises(SystemExit, match="not a regular file in the registered Git tree"):
            review(scan, ["src/fOO"])
    else:
        expected["src/fOO"] = hashlib.sha256(b"second").hexdigest()
    assert review(scan, list(expected)) == expected


def review_draft(state: Path, repository: Path, scan_dir: Path, path: str, *, deferred=None):
    registered = register_cli_scan(state, repository, scan_dir)
    scan_id = registered["scanId"]
    template = scan_dir.parent / "contract"
    template.mkdir()
    write_completed_contract(
        template,
        scan_id,
        repository,
        relative_path=path,
        target_kind="git_revision",
        target_revision=registered["targetRevision"],
    )
    documents = read_draft_documents(template)
    findings = documents["findings"]["findings"]
    if deferred is not None:
        findings.clear()
        documents["reviewState"] = documents.pop("coverage")
        documents["reviewState"].update(surfaces=[], deferred=deferred)
    drafts = scan_dir / "drafts"
    drafts.mkdir(exist_ok=True)

    def submit(paths, *, complete=False):
        draft = drafts / f"{uuid.uuid4()}.json"
        documents["manifest"]["scan"]["complete"] = complete
        draft.write_text(json.dumps(documents))
        checkpoint = drafts / f"{uuid.uuid4()}.checkpoint.json"
        review = {"deferred": deferred} if deferred is not None else {}
        if paths is not None:
            review["reviewedFiles"] = paths
        checkpoint.write_text(
            json.dumps(
                {
                    "scanId": scan_id,
                    "complete": complete,
                    "findings": findings,
                    "reviewState": review,
                }
            )
        )
        return scan_command(
            state,
            "write-scan-draft",
            scan_id,
            "--draft-path",
            str(draft),
            "--checkpoint-path",
            str(checkpoint),
        )

    return registered, findings, submit


def accepted_checkpoint(scan_dir: Path):
    head = json.loads((scan_dir / "checkpoint-head.json").read_text())
    return json.loads((scan_dir / "checkpoints" / head["checkpoint"]).read_text())


@pytest.mark.cross_platform
@pytest.mark.parametrize("prepare", [False, True], ids=["direct", "prepared"])
def test_standard_file_review_receipts_allow_partial_completion(tmp_path: Path, prepare: bool):
    state, repository, scan_dir = tmp_path / "state", tmp_path / "repository", tmp_path / "scan"
    initialize_git_repository(repository)
    reviewed = "-reviewed.py"
    unread = ["README.md", "pending.py"]
    for name in (reviewed, "pending.py"):
        (repository / name).write_bytes(b"pass")
    subprocess.run(["git", "add", "--", reviewed, "pending.py"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "Add review inputs"], cwd=repository, check=True)
    deferred = [{"id": "unread", "reason": "Review time expired.", "paths": unread}]
    registered, _, submit = review_draft(state, repository, scan_dir, reviewed, deferred=deferred)
    scan_id = registered["scanId"]
    assert registered["scopeFileCount"] == 3
    contents = (repository / reviewed).read_bytes()
    coverage = get_scan(state, scan_id)["scan"]["progress"]["coverage"]
    assert coverage.get("filesReviewed", 0) == 0

    assert submit([reviewed])["status"] == "draft_written"
    detail = get_scan(state, scan_id)["scan"]
    compact = get_scan(state, scan_id, "--progress-only")["scan"]
    history = run_workbench(state, "list-scans")["scans"][0]
    for entry in (detail, compact, history):
        assert entry["progress"]["coverage"] == {**coverage, "filesReviewed": 1}
    with sqlite3.connect(state / "workbench.sqlite3") as db:

        def receipt():
            return db.execute(
                "SELECT relative_path, content_sha256, closed_at FROM standard_reviewed_files "
                "WHERE scan_id = ?",
                (scan_id,),
            ).fetchall()

        original = receipt()
        assert len(original) == 1
        assert original[0][:2] == (reviewed, hashlib.sha256(contents).hexdigest())
        assert original[0][2]
        assert submit([reviewed, reviewed])["status"] == "draft_written"
        assert receipt() == original
        for invalid in (["pending.py", "absent.py"], {"pending.py": False}):
            assert "Skipped this batch of file review receipts" in submit(invalid)["warnings"][0]
            assert receipt() == original

    assert submit(None, complete=True)["status"] == "draft_written"
    if prepare:
        prepared = scan_command(state, "prepare-scan-completion", scan_id)["scan"]["progress"]
        assert prepared["status"] == "running"
        assert prepared["coverage"] == {**coverage, "filesReviewed": 1}
    result = scan_command(state, "complete-scan", scan_id)["scan"]["progress"]
    assert result["status"] == "complete"
    assert result["coverage"] == {**coverage, "filesReviewed": 1}
    accepted = accepted_checkpoint(scan_dir)
    assert accepted["reviewState"]["deferred"] == deferred


@pytest.mark.cross_platform
def test_stopped_scan_retains_finding_after_rejected_file_receipt(tmp_path: Path):
    state, repository, scan_dir = tmp_path / "state", tmp_path / "repository", tmp_path / "scan"
    initialize_git_repository(repository)
    registered, findings, submit = review_draft(state, repository, scan_dir, "README.md")
    scan_id = registered["scanId"]
    (repository / "README.md").write_text("Changed after review.")

    result = submit(["README.md"])
    assert result["status"] == "draft_written"
    assert "registered Git blob: README.md" in result["warnings"][0]
    scan_command(state, "cancel-scan", scan_id)
    detail = get_scan(state, scan_id)["scan"]
    assert detail["progress"]["coverage"].get("filesReviewed", 0) == 0
    accepted = accepted_checkpoint(scan_dir)
    assert accepted["findings"][0]["title"] == findings[0]["title"]
    assert (
        json.loads((scan_dir / "findings.json").read_text())["findings"][0]["title"]
        == findings[0]["title"]
    )
