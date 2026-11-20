"""Exercise scan directory reuse and protect the active database while archiving or rolling back."""

from __future__ import annotations

import argparse
import json
import ntpath
import os
import sqlite3
import stat
import threading
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest
from workbench_test_support import SCRIPT, fail_scan, load_script, run_workbench


def register_scan(
    state_dir: Path, repository: Path, scan_dir: Path, *arguments: str, check: bool = True
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "standard",
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
            }
        ),
        *arguments,
        check=check,
    )


@pytest.mark.parametrize("output_mode", [0o700, 0o755, 0o775])
def test_archived_output_preserves_old_scan_and_allows_fresh_registration(
    tmp_path: Path,
    output_mode: int,
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=output_mode)
    scan_dir.chmod(output_mode)
    previous = register_scan(state_dir, repository, scan_dir)
    if os.name != "nt":
        assert stat.S_IMODE(scan_dir.stat().st_mode) == output_mode
    fail_scan(state_dir, str(previous["scanId"]), "The previous scan was interrupted.")
    (scan_dir / "previous.txt").write_text("keep the previous scan\n")
    report_path = scan_dir / "report.md"
    report_path.write_text("# Previous scan\n")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO scan_artifacts (scan_id, kind, path, created_at) VALUES (?, ?, ?, ?)",
            (
                str(previous["scanId"]),
                "markdownReport",
                str(report_path),
                "2026-08-13T00:00:00Z",
            ),
        )
    archived_scan_dir = tmp_path / "scan.previous-test"
    scan_dir.rename(archived_scan_dir)
    scan_dir.mkdir(mode=output_mode)
    scan_dir.chmod(output_mode)

    current = register_scan(
        state_dir,
        repository,
        scan_dir,
        "--archive-existing",
        "--archived-scan-dir",
        str(archived_scan_dir),
    )

    assert current["scanId"] != previous["scanId"]
    assert current["scanDir"] == str(scan_dir)
    assert current["archivedScanDir"] == str(archived_scan_dir)
    assert (archived_scan_dir / "report.md").read_text() == "# Previous scan\n"
    assert (archived_scan_dir / "previous.txt").read_text() == "keep the previous scan\n"
    if os.name != "nt":
        assert stat.S_IMODE(scan_dir.stat().st_mode) == output_mode
        assert stat.S_IMODE(archived_scan_dir.stat().st_mode) == output_mode
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT scan_dir, status FROM scans WHERE id = ?",
            (str(previous["scanId"]),),
        ).fetchone() == (str(archived_scan_dir), "failed")
        assert connection.execute(
            "SELECT scan_dir, status FROM scans WHERE id = ?",
            (str(current["scanId"]),),
        ).fetchone() == (str(scan_dir), "running")
        assert connection.execute(
            "SELECT path FROM scan_artifacts WHERE scan_id = ?",
            (str(previous["scanId"]),),
        ).fetchone() == (str(archived_scan_dir / "report.md"),)


@pytest.mark.parametrize("output_mode", [0o700, 0o755, 0o775])
def test_empty_failed_scan_can_be_archived_and_reused(tmp_path: Path, output_mode: int) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=output_mode)
    scan_dir.chmod(output_mode)
    previous = register_scan(state_dir, repository, scan_dir)
    fail_scan(
        state_dir, str(previous["scanId"]), "The previous scan failed before writing artifacts."
    )

    current = register_scan(state_dir, repository, scan_dir, "--archive-existing")

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        previous_directory = connection.execute(
            "SELECT scan_dir FROM scans WHERE id = ?", (str(previous["scanId"]),)
        ).fetchone()
    assert previous_directory is not None
    archived_scan_dir = Path(previous_directory[0])
    assert archived_scan_dir.parent == scan_dir.parent
    assert archived_scan_dir.name.startswith("scan.previous-")
    assert archived_scan_dir.is_dir()
    assert not any(archived_scan_dir.iterdir())
    assert current["scanDir"] == str(scan_dir)
    if os.name != "nt":
        assert stat.S_IMODE(archived_scan_dir.stat().st_mode) == output_mode
        assert stat.S_IMODE(scan_dir.stat().st_mode) == 0o700


def test_archive_requires_previous_directory_when_artifacts_exist(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    previous = register_scan(state_dir, repository, scan_dir)
    fail_scan(state_dir, str(previous["scanId"]), "The previous scan was interrupted.")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO scan_artifacts (scan_id, kind, path, created_at) VALUES (?, ?, ?, ?)",
            (
                str(previous["scanId"]),
                "markdownReport",
                str(scan_dir / "report.md"),
                "2026-08-13T00:00:00Z",
            ),
        )

    rejected = register_scan(state_dir, repository, scan_dir, "--archive-existing", check=False)

    assert rejected["returncode"] != 0
    assert "archived scan directory is required" in str(rejected["stderr"])


@pytest.mark.skipif(os.name != "posix", reason="uses the filesystem's POSIX component limit")
def test_archive_keeps_output_with_a_full_length_filename(tmp_path: Path) -> None:
    limit = os.pathconf(tmp_path, "PC_NAME_MAX")
    if limit < 0:
        pytest.skip("This filesystem does not report a component limit")
    name = "a" * (limit - 1) + "b"
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    scan_dir = tmp_path / name
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    previous = register_scan(state_dir, repository, scan_dir)
    fail_scan(state_dir, str(previous["scanId"]), "Interrupted fixture scan.")
    (scan_dir / "report.md").write_text("original report\n")

    current = register_scan(state_dir, repository, scan_dir, "--archive-existing")
    archived = Path(str(current["archivedScanDir"]))
    assert archived.parent == tmp_path
    assert (archived / "report.md").read_text() == "original report\n"
    assert not (scan_dir / "report.md").exists()
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT scan_dir FROM scans WHERE id = ?", (previous["scanId"],)
        ).fetchone() == (str(archived),)

    other = tmp_path / (name[:-1] + "c")
    other.mkdir(mode=0o700)
    rejected = register_scan(
        state_dir,
        repository,
        other,
        "--archive-existing",
        "--archived-scan-dir",
        str(archived),
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "previous sibling" in str(rejected["stderr"])


def test_archive_does_not_replace_a_running_scan(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    previous = register_scan(state_dir, repository, scan_dir)

    rejected = register_scan(state_dir, repository, scan_dir, "--archive-existing", check=False)

    assert rejected["returncode"] != 0
    assert "Cannot archive the output of a running scan." in str(rejected["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT scan_dir, status FROM scans WHERE id = ?", (str(previous["scanId"]),)
        ).fetchone() == (str(scan_dir), "running")


@pytest.mark.parametrize("archived", [False, True])
def test_nonempty_output_is_rejected_before_parsing_the_recipe(
    tmp_path: Path, archived: bool
) -> None:
    repository, scan_dir = tmp_path / "repository", tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    (scan_dir / "checkpoint.txt").write_text("preserved output")
    arguments = []
    if archived:
        previous_dir = tmp_path / "scan.previous-test"
        previous_dir.mkdir(mode=0o700)
        arguments = ["--archive-existing", "--archived-scan-dir", str(previous_dir)]

    rejected = run_workbench(
        tmp_path / "state",
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        "{}",
        *arguments,
        check=False,
    )

    assert rejected["returncode"] != 0
    assert "must be empty before the scan starts" in str(rejected["stderr"])
    assert (scan_dir / "checkpoint.txt").read_text() == "preserved output"


@pytest.mark.parametrize(
    "state_subdirectory",
    [".", "state", "linked-state", "aliased-state", "aliased-state-child", "linked-parent"],
)
def test_archive_cannot_move_the_active_workbench_database(
    tmp_path: Path, state_subdirectory: str
) -> None:
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    state_dir = scan_dir / state_subdirectory
    previous_dir = tmp_path / "previous"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    previous_dir.mkdir(mode=0o700)
    if state_subdirectory in {
        "linked-state",
        "aliased-state",
        "aliased-state-child",
        "linked-parent",
    }:
        external_state = tmp_path / "external-state"
        external_state.mkdir(mode=0o700)
        state_dir.symlink_to(external_state, target_is_directory=True)
        if state_subdirectory == "linked-parent":
            child = scan_dir / "child"
            child.mkdir(mode=0o700)
            alias = tmp_path / "alias"
            alias.symlink_to(child, target_is_directory=True)
            state_dir = alias / ".." / state_subdirectory
        elif state_subdirectory.startswith("aliased-state"):
            alias = tmp_path / "alias"
            alias.symlink_to(tmp_path, target_is_directory=True)
            state_dir = alias / "scan" / state_subdirectory
            if state_subdirectory == "aliased-state-child":
                state_dir /= "child"
    previous = register_scan(state_dir, repository, previous_dir)
    (previous_dir / "report.md").write_text("saved report")
    (scan_dir / "previous.txt").write_text("keep existing output")

    rejected = register_scan(state_dir, repository, scan_dir, "--archive-existing", check=False)

    assert rejected["returncode"] != 0
    assert "workbench state or active database" in str(rejected["stderr"])
    assert (scan_dir / "previous.txt").read_text() == "keep existing output"
    assert (previous_dir / "report.md").read_text() == "saved report"
    assert not list(tmp_path.glob("scan.previous-*"))
    saved = run_workbench(state_dir, "get-scan", "--scan-id", str(previous["scanId"]))
    assert saved["scan"]["scanId"] == previous["scanId"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1


@pytest.mark.cross_platform
def test_registration_rechecks_empty_output_after_competing_archive_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workbench_api,
    workbench_schema,
) -> None:
    repository, scan_dir = tmp_path / "repository", tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    checkpoint = scan_dir / "checkpoint.txt"
    checkpoint.write_text("preserved bytes")
    database = tmp_path / "workbench.sqlite3"
    arguments = argparse.Namespace(
        repository=str(repository),
        scan_dir=str(scan_dir),
        archive_existing=True,
        archived_scan_dir=None,
        registration_json_stdin=False,
        recipe_json_stdin=False,
        parent_scan_id=None,
        recipe_json=json.dumps(
            {
                "config": {},
                "mode": "standard",
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
            }
        ),
    )
    register = workbench_api["register_cli_scan"]
    waiting = threading.Event()
    outcomes = []

    class WaitingConnection(sqlite3.Connection):
        def execute(self, statement, *args, **kwargs):
            if statement == "BEGIN IMMEDIATE":
                waiting.set()
            return super().execute(statement, *args, **kwargs)

    def compete():
        with sqlite3.connect(database, factory=WaitingConnection) as connection:
            connection.row_factory = sqlite3.Row
            second = argparse.Namespace(**vars(arguments))
            second.archive_existing, second.parent_scan_id = False, None
            try:
                outcomes.append(register(connection, second))
            except SystemExit as error:
                outcomes.append(error)

    creation_owner, creation_method = Path, "mkdir"
    if os.name == "nt":
        import windows_scan_local_files

        creation_owner, creation_method = (
            windows_scan_local_files,
            "create_directory_with_same_dacl",
        )
    create_directory = getattr(creation_owner, creation_method)
    competitor = threading.Thread(target=compete)

    def replacement(path, *args, **kwargs):
        result = create_directory(path, *args, **kwargs)
        if path == scan_dir:
            competitor.start()
            assert waiting.wait(5)
            raise SystemExit("Synthetic failure after archive replacement")
        return result

    with sqlite3.connect(database) as first:
        workbench_schema.backup(first)
        first.row_factory = sqlite3.Row
        with monkeypatch.context() as patch:
            patch.setattr(creation_owner, creation_method, replacement)
            with pytest.raises(SystemExit, match="Synthetic failure after archive replacement"):
                register(first, arguments)
        competitor.join(10)
        assert not competitor.is_alive()
        assert len(outcomes) == 1
        assert isinstance(outcomes[0], SystemExit)
        assert "must be empty" in str(outcomes[0])
        assert first.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0
    assert checkpoint.read_text() == "preserved bytes"
    assert not list(tmp_path.glob("scan.previous-*"))


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    "root, alias",
    [(r"C:\scans", r"\\?\C:\scans"), (r"\\host\share\scans", r"\\?\UNC\host\share\scans")],
)
def test_archive_owner_distinguishes_aliases_and_literal_directories(
    tmp_path, monkeypatch, root, alias
):
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import workbench_scan_start as start
    from workbench import storage

    class Directory(PureWindowsPath):
        def local(self):
            parts = self.parts[1:]
            if not str(self).startswith("\\\\?\\"):
                parts = [part.rstrip(" .") for part in parts]
            parts = ["output" if part == "OUTPUT" else part for part in parts]
            return tmp_path.joinpath(*(part.encode().hex() for part in parts))

        def expanduser(self):
            return self

        def absolute(self):
            return self

        def resolve(self, strict=False):
            return self

        def iterdir(self):
            return self.local().iterdir()

        def samefile(self, other):
            if self.name == "long-state":
                raise OSError(206, "ordinary Windows filename too long")
            return self.local().samefile(other.local())

    monkeypatch.setattr(storage, "Path", Directory)
    monkeypatch.setattr(storage, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(start, "Path", Directory)
    monkeypatch.setattr(start, "os", SimpleNamespace(name="nt", path=ntpath))
    ordinary, extended = Directory(root) / "output", Directory(alias) / "output"
    ordinary.local().mkdir(parents=True)
    extended.with_name("output.").local().mkdir()
    ordinary.with_name("Output").local().mkdir()
    assert start.scan_directory_spellings(extended.with_name("output.")) == (
        extended.with_name("output."),
    )
    assert start.scan_directory_spellings(ordinary.with_name("missing")) == (
        ordinary.with_name("missing"),
        extended.with_name("missing"),
    )
    assert start.scan_directory_spellings(extended.with_name("long-state")) == (
        extended.with_name("long-state"),
        ordinary.with_name("long-state"),
    )
    with sqlite3.connect(":memory:") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("CREATE TABLE scans(id, status, scan_dir UNIQUE)")
        same_tree = extended.with_name("OUTPUT") / "checkout"
        sibling_tree = extended.with_name("Output") / "checkout"
        same_tree.local().mkdir()
        sibling_tree.local().mkdir()
        assert not same_tree.local().samefile(sibling_tree.local())
        for selected, overlaps in ((same_tree, True), (sibling_tree, False)):
            assert start.scan_output_overlaps_target(ordinary, selected) is overlaps
            assert start.scan_output_overlaps_target(selected, ordinary) is overlaps

        with monkeypatch.context() as inaccessible:

            def deny(*paths):
                raise PermissionError("case-variant directory is inaccessible")

            inaccessible.setattr(Directory, "samefile", deny)
            assert start.scan_output_overlaps_target(ordinary, same_tree)

        args = argparse.Namespace(archive_existing=True, archived_scan_dir=None)

        def stop_before_move():
            raise InterruptedError("Reached archive move")

        for state_root, error, message in (
            (same_tree, SystemExit, "workbench state or active database"),
            (sibling_tree, InterruptedError, "Reached archive move"),
        ):
            monkeypatch.setattr(start, "state_dir", lambda *, canonical, root=state_root: root)
            with (
                pytest.raises(error, match=message),
                start.archive_scan(
                    connection,
                    args,
                    ordinary,
                    "now",
                    lambda path: path,
                    before_archive=stop_before_move,
                ),
            ):
                pytest.fail("The fixture stops before moving the archive.")
        for sibling in (ordinary, ordinary.with_name("OUTPUT")):
            archive = extended.with_name("Output") / "run.previous-test"
            active = sibling / "run"
            args = argparse.Namespace(
                archive_existing=True,
                archived_scan_dir=str(archive),
                scan_dir=str(active),
                previous_scan_id=None,
            )
            with (
                pytest.raises(SystemExit, match="previous sibling"),
                start.archive_scan(connection, args, active, "now", lambda path: path),
            ):
                pytest.fail("Archive registration must verify its physical parent.")
            with pytest.raises(SystemExit, match="previous sibling"):
                start.restore_cli_scan_archive(connection, args, lambda path: path)
        ordinary.joinpath("run").local().mkdir()
        assert (
            storage.archive_source_directory(
                ordinary / "run.previous-test", ordinary.with_name("OUTPUT") / "run" / "child"
            )
            is not None
        )
        assert (
            storage.archive_source_directory(
                ordinary / "run.previous-test", ordinary.with_name("Output") / "run" / "child"
            )
            is None
        )
        archive = extended.with_name("OUTPUT.previous-test")
        worker = ordinary / "worker.json"
        assert storage.archived_deep_path(archive, str(worker)) == str(
            ordinary.with_name(archive.name) / worker.name
        )
        separate_worker = ordinary.with_name("Output") / worker.name
        assert storage.archived_deep_path(archive, str(separate_worker)) == str(separate_worker)
        connection.execute("INSERT INTO scans VALUES ('old', 'running', ?)", (str(extended),))
        for path in (
            ordinary,
            extended,
            ordinary.with_name("OUTPUT"),
            extended.with_name("OUTPUT"),
        ):
            assert (
                start._archive_owner(connection, start.scan_directory_spellings(path))["id"]
                == "old"
            )
        with (
            pytest.raises(SystemExit, match="running scan"),
            start.archive_scan(
                connection,
                argparse.Namespace(archived_scan_dir=None, archive_existing=True),
                ordinary.with_name("OUTPUT"),
                "now",
                lambda path: path,
            ),
        ):
            pytest.fail("Registration must reject the running scan before moving its directory.")
        assert (
            start._archive_owner(
                connection, start.scan_directory_spellings(ordinary.with_name("Output"))
            )
            is None
        )
        connection.execute(
            "INSERT INTO scans VALUES ('new', 'running', ?)", (str(ordinary.with_name("OUTPUT")),)
        )
        with pytest.raises(SystemExit, match="claimed by multiple scans"):
            start._archive_owner(connection, start.scan_directory_spellings(ordinary))


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires Win32 archive aliases")
@pytest.mark.parametrize("old_extended", [False, True])
def test_archive_follows_the_owner_across_windows_spellings(
    tmp_path, request, monkeypatch, old_extended, workbench_api
):
    _extended_path = load_script("windows_scan_local_files")._extended_path

    state, repo, output = (tmp_path / name for name in ("state", "repo", "output"))
    repo.mkdir()
    output.mkdir()
    extended = Path(_extended_path(output))
    old, new = (extended, output) if old_extended else (output, extended)
    new = new.with_name(new.name.upper())
    scan_id = str(register_scan(state, repo, old)["scanId"])
    rejected = register_scan(state, repo, new, "--archive-existing", check=False)
    assert "Cannot archive the output of a running scan" in rejected["stderr"]
    fail_scan(state, scan_id, "Archive this scan")

    report = extended / "report.md."

    def cleanup():
        for folder in (output, *tmp_path.glob("output.previous-*")):
            (Path(_extended_path(folder)) / report.name).unlink(missing_ok=True)

    request.addfinalizer(cleanup)
    ordinary_report = output / "report.md"
    ordinary_report.write_text("ordinary sibling")
    report.write_text("original report")
    deep = workbench_api["deep_scan"]
    monkeypatch.setattr(
        deep,
        "_dependencies",
        SimpleNamespace(
            require_canonical_scan_directory=workbench_api["require_canonical_scan_directory"]
        ),
    )
    scan = {"scan_dir": str(old)}
    recorded_report = deep.deep_scan_path(scan, str(report), "Worker result", kind="file")
    assert Path(recorded_report).samefile(report)
    assert Path(
        deep.deep_scan_path(scan, str(ordinary_report), "Worker result", kind="file")
    ).samefile(ordinary_report)
    assert not Path(recorded_report).samefile(ordinary_report)
    database = state / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO scan_artifacts VALUES (?, 'markdownReport', ?, 'before')",
            (scan_id, recorded_report),
        )

    current = register_scan(state, repo, new, "--archive-existing")
    archived = Path(current["archivedScanDir"])
    with sqlite3.connect(database) as connection:
        recorded = connection.execute(
            "SELECT scan_dir FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]
        saved = connection.execute(
            "SELECT path FROM scan_artifacts WHERE scan_id = ?", (scan_id,)
        ).fetchone()[0]
    assert Path(recorded).samefile(archived)
    assert Path(saved).parent.samefile(recorded)
    assert Path(saved).read_text() == "original report"
    assert (
        run_workbench(
            state,
            "restore-cli-scan-archive",
            "--scan-dir",
            str(new),
            "--archived-scan-dir",
            str(archived),
            "--previous-scan-id",
            scan_id,
        )["disposition"]
        == "already-recorded"
    )


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires long Win32 archive paths")
@pytest.mark.parametrize("root_size", [232, 242], ids=["report", "root"])
def test_archive_keeps_extended_access_after_suffix_exceeds_max_path(tmp_path, root_size):
    extended = load_script("windows_scan_local_files")._extended_path
    state, repo = tmp_path / "state", tmp_path / "repo"
    repo.mkdir()
    units = len(str(tmp_path).encode("utf-16-le")) // 2
    output = tmp_path / ("s" * max(1, root_size - units - 1))
    output.mkdir()
    scan_id = register_scan(state, repo, output)["scanId"]
    fail_scan(state, scan_id, "Stopped")
    report = output / "report.md"
    report.write_text("Previous report")
    database = state / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO scan_artifacts VALUES (?, 'markdownReport', ?, 'before')",
            (scan_id, str(report)),
        )

    current = register_scan(state, repo, Path(extended(output)), "--archive-existing")
    archived = Path(current["archivedScanDir"])
    with sqlite3.connect(database) as connection:
        root, artifact = connection.execute(
            "SELECT scan_dir, path FROM scans JOIN scan_artifacts ON scan_id = scans.id "
            "WHERE scans.id = ?",
            (scan_id,),
        ).fetchone()
    assert root == extended(archived)
    assert artifact == str(Path(root) / report.name)
    assert Path(artifact).read_text() == "Previous report"


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires Win32 archive aliases")
def test_archive_does_not_move_state_or_checkout_via_an_extended_output(tmp_path):
    _extended_path = load_script("windows_scan_local_files")._extended_path

    state, repo = tmp_path / "state", tmp_path / "repo"
    repo.mkdir()
    output = repo / "output"
    output.mkdir()
    (output / "previous.txt").write_text("keep the checkout")
    response = register_scan(
        state, repo, Path(_extended_path(output)), "--archive-existing", check=False
    )
    assert "outside and not contain the selected target" in response["stderr"]
    response = register_scan(
        state, repo, Path(_extended_path(state)), "--archive-existing", check=False
    )
    assert "workbench state or active database" in response["stderr"]
    assert (output / "previous.txt").read_text() == "keep the checkout"
    assert not list(tmp_path.glob("state.previous-*"))


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    "root, prefix",
    [(r"C:\scans", r"\\?\C:\scans"), (r"\\host\share\scans", r"\\?\UNC\host\share\scans")],
)
def test_mixed_worker_paths_preserve_file_identity_through_archive(
    tmp_path, monkeypatch, root, prefix
):
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import deep_scan_workbench as deep
    from workbench import storage

    class Directory(PureWindowsPath):
        def local(self):
            parts = self.parts[1:]
            if not str(self).startswith("\\\\?\\"):
                parts = [part.rstrip(" .") for part in parts]
            # Encode each component so the case-sensitive sibling fixture works on every host.
            return tmp_path.joinpath(*(part.encode().hex() for part in parts))

        def expanduser(self):
            return self

        def absolute(self):
            return self

        def resolve(self, strict=False):
            if strict:
                self.local().stat()
            return self

        def is_file(self):
            return self.local().is_file()

        def is_dir(self):
            return self.local().is_dir()

        def exists(self):
            return self.local().exists()

        def samefile(self, other):
            return self.local().samefile(other.local())

    monkeypatch.setattr(storage, "Path", Directory)
    monkeypatch.setattr(storage, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(deep, "Path", Directory)
    monkeypatch.setattr(
        deep,
        "_dependencies",
        SimpleNamespace(require_canonical_scan_directory=lambda root: root.resolve(strict=True)),
    )
    ordinary, extended = Directory(root) / "run", Directory(prefix) / "run"
    ordinary.local().mkdir(parents=True)
    literal = extended / "result.json."
    normal = ordinary / "result.json"
    normal.local().write_text("ordinary")
    literal.local().write_text("verbatim")
    for path in (
        extended.with_name("run."),
        extended.with_name("RUN"),
        Directory(prefix) / "outside",
    ):
        path.local().mkdir()
        candidate = path / "result.json."
        candidate.local().touch()
        with pytest.raises(SystemExit, match="inside the scan directory"):
            deep.deep_scan_path(
                {"scan_dir": str(ordinary)}, str(candidate), "Worker result", kind="file"
            )

    archive = ordinary.with_name("run.previous-test")
    long_name = "s" * (260 - len(str(ordinary.parent)) - 1)
    extended_archive = extended.with_name(long_name)
    assert storage.relocate_scan_artifact(ordinary, extended_archive, str(normal)) == str(
        extended_archive / normal.name
    )
    assert storage.relocate_scan_artifact(
        ordinary, extended_archive, str(ordinary / literal.name)
    ) == str(ordinary.with_name(long_name) / literal.name)
    for recorded_root, supplied in ((ordinary, literal), (extended, normal)):
        scan = {"scan_dir": str(recorded_root)}
        saved = deep.deep_scan_path(scan, str(supplied), "Worker result", kind="file")
        assert Directory(saved).samefile(supplied)
        missing = supplied.with_name("pending." if supplied == literal else "pending")
        assert (
            Directory(deep.deep_scan_output_path(scan, str(missing), "Output")).local()
            == missing.local()
        )
        for archived in (archive, extended.with_name(archive.name)):
            moved = storage.relocate_scan_artifact(recorded_root, archived, saved)
            assert moved == storage.archived_deep_path(archived, saved)
            ordinary.local().rename(archived.local())
            try:
                assert Directory(moved).local().read_text() == (
                    "verbatim" if supplied == literal else "ordinary"
                )
            finally:
                archived.local().rename(ordinary.local())
    assert storage.worker_contract_relative_path(extended / "result.json", ordinary) == Directory(
        "result.json"
    )
    swapped_anchor = extended.anchor.swapcase()
    # Python 3.10 requires the canonical UNC marker to recognize the extended share.
    anchors = {swapped_anchor.replace("\\unc\\", "\\UNC\\", 1)}
    if Directory(swapped_anchor).is_absolute():
        anchors.add(swapped_anchor)
    for anchor in anchors:
        same_namespace = Directory(anchor).joinpath(*extended.parts[1:])
        assert storage.worker_contract_relative_path(literal, same_namespace) == Directory(
            literal.name
        )
    with pytest.raises(ValueError, match="Verbatim-only"):
        storage.worker_contract_relative_path(literal, ordinary)

    for root, alternate in ((ordinary, extended), (extended, ordinary)):
        scan = {"scan_dir": str(root)}
        mixed_result = alternate / normal.name
        saved = deep._worker_artifact_path(scan, str(mixed_result), "Worker result", kind="file")
        assert storage.worker_contract_relative_path(Directory(saved), root) == Directory(
            normal.name
        )
        with pytest.raises(SystemExit, match="Verbatim-only"):
            deep._worker_artifact_path(
                scan, str(alternate / literal.name), "Worker result", kind="file"
            )
        standard = alternate / "scan-manifest.json"
        assert deep._coordinator_manifest_path(scan, str(standard), "Manifest", staged=True) == str(
            root / standard.name
        )
        standard.local().touch()
        try:
            assert deep._coordinator_manifest_path(
                scan, str(standard), "Manifest", staged=False
            ) == str(root / standard.name)
            assert deep._coordinator_manifest_path(
                scan, str(literal), "Manifest", staged=False
            ) == str(literal)
        finally:
            standard.local().unlink()


@pytest.mark.cross_platform
def test_staged_promotion_rejects_a_namespace_alias_before_moving_the_output(tmp_path, monkeypatch):
    deep = load_script("deep_scan_workbench")

    class Filename(PureWindowsPath):
        def local(self):
            parts = self.parts[1:]
            if not str(self).startswith("\\\\?\\"):
                parts = [name.rstrip(" .") for name in parts]
            return tmp_path.joinpath(*(name.encode().hex() for name in parts))

        def exists(self):
            return self.local().exists()

        def samefile(self, other):
            return self.local().samefile(other.local())

    renames = []

    def replace(source, destination):
        renames.append((source, destination))
        os.replace(source.local(), destination.local())

    monkeypatch.setattr(deep, "Path", Filename)
    monkeypatch.setattr(deep, "os", SimpleNamespace(replace=replace))
    ordinary = Filename("C:/scan")
    extended = Filename("//?/C:/scan")
    ordinary.local().mkdir()
    output = ordinary / "result.json"
    output.local().write_text("original")
    for staged, destination in ((extended / output.name, output), (output, extended / output.name)):
        with pytest.raises(SystemExit, match="must not be its published output"):
            deep.promote_staged_file(str(staged), str(destination))
    assert renames == []

    for staged in (extended / "other.json", extended / "nested" / output.name):
        staged.local().parent.mkdir(exist_ok=True)
        os.link(output.local(), staged.local())
        assert staged.samefile(output)
        _, _, backup = deep.promote_staged_file(str(staged), str(output))
        assert backup is not None and backup.samefile(output)
        backup.local().unlink()

    literal = extended / "result.json."
    literal.local().write_text("literal")
    _, _, backup = deep.promote_staged_file(str(literal), str(ordinary / literal.name))
    assert output.local().read_text() == "literal"
    assert backup is not None and backup.local().read_text() == "original"
