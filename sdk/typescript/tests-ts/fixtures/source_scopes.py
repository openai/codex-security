"""Synthetic Git fixtures for finding-source authorization tests."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unicodedata
import uuid
from contextlib import closing, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.pop("GIT_NO_REPLACE_OBJECTS", None)
os.environ.pop("GIT_REPLACE_REF_BASE", None)

sys.path.insert(0, sys.argv[1])
import workbench_source_excerpt as excerpts
import workbench_source_scopes as scopes
from workbench_target import clean_worktree_content_digest


def git(repository: Path, *arguments: str, input_data: bytes | None = None) -> str:
    environment = dict(
        os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1"
    )
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=Example",
            "-c",
            "user.email=example@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-C",
            str(repository),
            *arguments,
        ],
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=True,
    )
    return result.stdout.decode().strip()


def write(repository: Path, name: str, content: str) -> None:
    path = repository / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def commit(repository: Path) -> str:
    git(repository, "add", "--all")
    git(repository, "commit", "--quiet", "-m", "Synthetic fixture")
    return git(repository, "rev-parse", "HEAD")


def scan(repository: Path, revision: str, paths: list[str]) -> dict:
    identity = (revision, clean_worktree_content_digest(), 0, 0)
    return {
        "target_revision": revision,
        "target_snapshot_digest": identity[1],
        "source_scopes_json": json.dumps(
            scopes.capture_source_scopes(repository, identity, paths)
        ),
        "recipe_json": None,
    }


def excerpt(
    record: dict, repository: Path, path: str, selected: list[str]
) -> str | None:
    return excerpts.finding_source_excerpt(
        record, repository, [{"path": path, "startLine": 1}], selected
    )


def register_recipe(
    repository: Path, recipe: dict, environment: dict[str, str] | None = None
) -> tuple[dict, dict]:
    state = repository.parent / "state"
    scan_dir = Path(tempfile.mkdtemp(prefix="cli-scan-", dir=repository.parent))
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(Path(sys.argv[1]) / "workbench_db.py"),
            "register-cli-scan",
            "--repository",
            str(repository),
            "--scan-dir",
            str(scan_dir),
            "--recipe-json",
            json.dumps(recipe),
        ],
        env={
            **os.environ,
            **(environment or {}),
            "CODEX_SECURITY_STATE_DIR": str(state),
        },
        text=True,
        capture_output=True,
        check=True,
    )
    registered = json.loads(result.stdout)
    with closing(sqlite3.connect(state / "workbench.sqlite3")) as connection:
        connection.row_factory = sqlite3.Row
        record = dict(
            connection.execute(
                "SELECT * FROM scans WHERE id = ?", (registered["scanId"],)
            ).fetchone()
        )
    return registered, record


def directory_link(target: Path, link: Path) -> None:
    if os.name == "nt":
        subprocess.run(
            [
                "node",
                "-e",
                "require('node:fs').symlinkSync(process.argv[1], process.argv[2], 'junction')",
                str(target),
                str(link),
            ],
            check=True,
            capture_output=True,
        )
    else:
        link.symlink_to(target, target_is_directory=True)


def replacements(repository: Path) -> dict:
    write(repository, "selected.py", "selected source\n")
    write(repository, "private.py", "private source\n")
    write(repository, "selected/public.py", "selected directory\n")
    write(repository, "private/public.py", "private directory\n")
    revision = commit(repository)
    file_record = scan(repository, revision, ["selected.py"])
    directory_record = scan(repository, revision, ["selected"])
    file_object = git(repository, "rev-parse", "HEAD:selected.py")
    private_object = git(repository, "rev-parse", "HEAD:private.py")
    tree_object = git(repository, "rev-parse", "HEAD:selected")
    private_tree = git(repository, "rev-parse", "HEAD:private")
    git(repository, "replace", file_object, private_object)
    git(repository, "replace", tree_object, private_tree)
    scopes.tree_entries.cache_clear()
    assert (
        excerpt(file_record, repository, "selected.py", ["selected.py"])
        == "1  selected source"
    )
    assert (
        excerpt(directory_record, repository, "selected/public.py", ["selected"])
        == "1  selected directory"
    )
    scopes.tree_entries.cache_clear()
    captured = scan(repository, revision, ["selected.py", "selected"])
    assert json.loads(captured["source_scopes_json"])["scopes"] == []
    return {"savedObjectsUnchanged": True, "newReplacementViewOmitted": True}


def replacement_filters(repository: Path) -> dict:
    write(repository, "tracked.py", "synthetic source\n")
    write(repository, ".gitattributes", "tracked.py filter=scope_probe\n")
    revision = commit(repository)
    first = git(repository, "hash-object", "-w", "--stdin", input_data=b"first\n")
    second = git(repository, "hash-object", "-w", "--stdin", input_data=b"second\n")
    git(repository, "replace", first, second)
    marker = repository.parent / "filter-executed"
    helper = repository.parent / "filter.py"
    helper.write_text(
        "import os,sys\n"
        "from pathlib import Path\n"
        "Path(os.environ['SYNTHETIC_FILTER_MARKER']).write_text(os.environ.get('GIT_CONFIG_VALUE_0',''))\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n"
    )
    git(
        repository,
        "config",
        "filter.scope_probe.clean",
        " ".join(
            shlex.quote(Path(path).as_posix()) for path in (sys.executable, helper)
        ),
    )
    os.utime(repository / "tracked.py", (0, 0))
    recipe = {
        "config": {},
        "mode": "standard",
        "repository": str(repository),
        "target": {"kind": "refs", "paths": [], "base": revision, "head": revision},
    }
    _, record = register_recipe(
        repository,
        recipe,
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": "SYNTHETIC_GIT_CREDENTIAL",
            "SYNTHETIC_FILTER_MARKER": str(marker),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        },
    )
    assert not marker.exists(), "source capture executed a working-tree filter"
    assert json.loads(record["source_scopes_json"])["scopes"] == []
    assert json.loads(record["recipe_json"]) == recipe
    return {"workingTreeFilterNotRun": True, "registrationRecipeUnchanged": True}


def replacement_snapshot(repository: Path) -> dict:
    from workbench_scan_start import scan_target_identity

    write(repository, "src/public.py", "historical source\n")
    write(repository, "src/removed.py", "historical-only source\n")
    historical = commit(repository)
    write(repository, "src/public.py", "scanned source\n")
    (repository / "src/removed.py").unlink()
    replacement = commit(repository)
    git(repository, "reset", "--hard", historical)
    git(repository, "replace", historical, replacement)
    git(repository, "reset", "--hard", historical)
    assert git(repository, "status", "--porcelain") == ""
    assert not (repository / "src/removed.py").exists()
    identity = scan_target_identity(repository, None)
    assert identity[1] == clean_worktree_content_digest()
    authority = scopes.capture_source_scopes(repository, identity, ["src"])
    assert authority["scopes"] == []
    record = {
        "target_revision": identity[0],
        "target_snapshot_digest": identity[1],
        "source_scopes_json": json.dumps(authority),
        "recipe_json": None,
    }
    assert excerpt(record, repository, "src/removed.py", ["src"]) is None
    legacy = {**record, "source_scopes_json": None}
    assert excerpt(legacy, repository, "src/removed.py", ["."]) is None
    git(repository, "replace", "--delete", historical)
    with patch.dict(
        os.environ, {"GIT_REPLACE_REF_BASE": "refs/synthetic-replacements/"}
    ):
        git(repository, "replace", historical, replacement)
        git(repository, "reset", "--hard", historical)
        assert (
            scopes.capture_source_scopes(
                repository, scan_target_identity(repository, None), ["src"]
            )["scopes"]
            == []
        )
        assert excerpt(legacy, repository, "src/removed.py", ["."]) is None
    return {"mismatchedCaptureOmitted": True, "ambiguousLegacyViewOmitted": True}


def indexed_scopes(repository: Path) -> dict:
    selected = [f"source-{index}.py" for index in range(256)]
    for name in selected:
        write(repository, name, "synthetic source\n")
    revision = commit(repository)
    scopes.tree_entries.cache_clear()
    normalize = scopes.normalized_path_component
    calls = 0

    def counted(value: str) -> str:
        nonlocal calls
        calls += 1
        return normalize(value)

    with patch.object(scopes, "normalized_path_component", counted):
        record = scan(repository, revision, selected)
    assert len(json.loads(record["source_scopes_json"])["scopes"]) == len(selected)
    assert calls <= 3 * len(selected), calls
    return {"selected": len(selected), "linearNormalization": True}


def display_locations(repository: Path) -> dict:
    import workbench_db as db
    from filesystem_identity import serialize_filesystem_identity

    selected = [f"selected/location{index}.py" for index in range(9)]
    for index, name in enumerate(selected):
        write(repository, name, f"source {index}\n")
    record = {
        **scan(repository, commit(repository), ["selected"]),
        "id": "synthetic-scan",
        "started_at": "2026-08-01T00:00:00Z",
        "scan_dir": str(repository.parent / "scan"),
        "target_path": str(repository),
        "target_inode": serialize_filesystem_identity(repository.stat().st_ino),
        "scope": "selected",
    }
    locations = [
        {
            "path": name,
            "startLine": 1,
            "endLine": 1,
            "role": "evidence:root_control" if index == 8 else "evidence",
        }
        for index, name in enumerate(selected)
    ]
    occurrence = {
        "id": "synthetic-occurrence",
        "finding_id": "synthetic-finding",
        "details_json": json.dumps({"locations": locations}),
        "confidence": "high",
        "created_at": record["started_at"],
        "remediation": "Synthetic remediation",
        "severity": "low",
        "summary": "Synthetic summary",
        "title": "Synthetic finding",
    }
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, "
        "start_line INTEGER, end_line INTEGER, role TEXT, sort_order INTEGER)"
    )
    connection.executemany(
        "INSERT INTO finding_locations VALUES (?, ?, ?, ?, ?, ?)",
        [
            (occurrence["id"], item["path"], 1, 1, item["role"], index)
            for index, item in enumerate(locations)
        ],
    )
    with (
        patch.object(db, "finding_remediation_result", return_value=None),
        patch.object(db, "finding_triage_result", return_value=None),
        patch.object(db.scan_history, "finding_matches", return_value=([], None, [])),
    ):
        result = db.finding_result(connection, record, occurrence)
    assert [item["path"] for item in result["locations"]] == selected[:8]
    assert result["sourceExcerpt"] == "1  source 0"
    connection.close()
    return {"displayed": 8, "excerptUsesDisplayedLocation": True}


def selected_redirects(repository: Path) -> dict:
    write(repository, ".gitignore", "/selected/link\n")
    write(repository, "selected/public.py", "selected source\n")
    write(repository, "private/secret.py", "private source\n")
    revision = commit(repository)
    directory_link(repository / "private", repository / "selected/link")
    assert git(repository, "status", "--porcelain") == ""

    requested = ["selected/link"]
    recipe = {
        "config": {},
        "mode": "standard",
        "repository": str(repository),
        "target": {"kind": "paths", "paths": requested},
    }
    registered, record = register_recipe(repository, recipe)
    assert registered["contract"]["scope"]["requiredIncludePaths"] == requested
    assert record["target_snapshot_digest"] == clean_worktree_content_digest()
    assert excerpt(record, repository, "private/secret.py", requested) is None
    assert json.loads(record["source_scopes_json"])["scopes"] == []
    assert json.loads(record["recipe_json"]) == recipe

    descendant = ["selected/link/secret.py"]
    record = scan(repository, revision, descendant)
    assert json.loads(record["source_scopes_json"])["scopes"] == []
    assert excerpt(record, repository, "private/secret.py", descendant) is None
    direct = scan(repository, revision, ["private"])
    assert (
        excerpt(direct, repository, "private/secret.py", ["private"])
        == "1  private source"
    )
    return {
        "selectedLinkOmitted": True,
        "linkedAncestorOmitted": True,
        "registrationRecipeUnchanged": True,
        "directSelectionPreserved": True,
    }


def working_tree_excerpt(repository: Path) -> dict:
    write(repository, "source.py", "old committed source\n")
    revision = commit(repository)
    write(repository, "source.py", "new working-tree source\n")
    recipe = {
        "config": {},
        "mode": "standard",
        "repository": str(repository),
        "target": {
            "kind": "working_tree",
            "paths": [],
            "base": revision,
            "head": revision,
        },
    }
    _, record = register_recipe(repository, recipe)
    metadata = json.loads(record["source_scopes_json"])
    historical = {**record, "source_scopes_json": None}
    range_recipe = {
        **recipe,
        "target": {
            "kind": "refs",
            "paths": [],
            "base": revision,
            "head": revision,
        },
    }
    _, range_record = register_recipe(repository, range_recipe)
    return {
        "authorityOmitted": metadata["scopes"] == [],
        "currentExcerptOmitted": excerpt(record, repository, "source.py", ["."])
        is None,
        "legacyExcerptOmitted": excerpt(historical, repository, "source.py", ["."])
        is None,
        "rangeExcerptPreserved": excerpt(
            range_record, repository, "source.py", ["."]
        )
        == "1  old committed source",
    }


def unsafe_locations(repository: Path) -> dict:
    write(repository, "source.py", "selected source\n")
    record = scan(repository, commit(repository), ["."])
    outside = repository.parent / "outside"
    outside.mkdir()
    write(outside, "source.py", "outside source\n")
    directory_link(outside, repository / "escaped")
    with patch.object(
        scopes, "git_worktree_context", side_effect=AssertionError("Git was invoked")
    ):
        for path in (
            "../outside/source.py",
            str(outside / "source.py"),
            "escaped/source.py",
        ):
            assert excerpt(record, repository, path, ["."]) is None
        assert (
            excerpts.finding_source_excerpt(
                record,
                repository,
                [{"path": "source.py", "startLine": "invalid"}],
                ["."],
            )
            is None
        )
    return {
        "unsafePathsRejectedBeforeGit": True,
        "invalidLocationRejectedBeforeGit": True,
    }


def boundaries(repository: Path) -> dict:
    for name, content in {
        "src/public.py": "public source\n",
        "src/support.py": "support source\n",
        "src/nested/child.py": "nested source\n",
        "private/secret.py": "private source\n",
        "selected.py": "selected file\n",
        "other.py": "other file\n",
    }.items():
        write(repository, name, content)
    linked = False
    try:
        (repository / "src/redirected").symlink_to(
            repository / "private", target_is_directory=True
        )
        (repository / "src/escaped").symlink_to(
            repository.parent, target_is_directory=True
        )
        linked = True
    except OSError:
        pass
    revision = commit(repository)
    selected = scan(repository, revision, ["src"])
    single = scan(repository, revision, ["selected.py"])
    multiple = scan(repository, revision, ["src", "selected.py"])
    whole = scan(repository, revision, ["."])
    legacy = {
        "target_revision": revision,
        "target_snapshot_digest": None,
        "recipe_json": None,
    }
    legacy_kinds = {
        **legacy,
        "recipe_json": json.dumps({"_codexSecurityFileScopes": ["selected.py"]}),
    }
    result = {
        "selected": excerpt(selected, repository, "src/public.py", ["src"]),
        "outside": excerpt(selected, repository, "private/secret.py", ["src"]),
        "additional": excerpt(
            multiple, repository, "selected.py", ["src", "selected.py"]
        ),
        "repository": excerpt(whole, repository, "private/secret.py", ["."]),
        "fileDescendant": excerpt(
            single, repository, "selected.py/private.py", ["selected.py"]
        ),
        "traversal": excerpt(selected, repository, "src/../private/secret.py", ["src"]),
        "absolute": excerpt(
            selected, repository, str(repository / "src/public.py"), ["src"]
        ),
        "redirected": excerpt(selected, repository, "src/redirected/secret.py", ["src"])
        if linked
        else None,
        "escaped": excerpt(selected, repository, "src/escaped/secret.py", ["src"])
        if linked
        else None,
        "legacyScoped": excerpt(legacy, repository, "src/public.py", ["src"]),
        "legacyUnmarkedFile": excerpt(
            legacy, repository, "selected.py", ["selected.py"]
        ),
        "legacyUnmarkedFileDescendant": excerpt(
            legacy, repository, "selected.py/private.py", ["selected.py"]
        ),
        "legacyRoot": excerpt(legacy, repository, "private/secret.py", ["."]),
        "legacyKnownDirectory": excerpt(
            legacy_kinds, repository, "src/public.py", ["src"]
        ),
        "legacyKnownFile": excerpt(
            legacy_kinds, repository, "selected.py", ["selected.py"]
        ),
        "legacyFileDescendant": excerpt(
            legacy_kinds, repository, "selected.py/private.py", ["selected.py"]
        ),
        "emptyAuthority": excerpt(
            {
                **selected,
                "source_scopes_json": json.dumps(
                    {"version": 1, "revision": revision, "scopes": []}
                ),
            },
            repository,
            "src/public.py",
            ["src"],
        ),
        "dirty": excerpt(
            {**selected, "target_snapshot_digest": "dirty"},
            repository,
            "src/public.py",
            ["src"],
        ),
        "fallback": excerpts.finding_source_excerpt(
            selected,
            repository,
            [
                {"path": "private/secret.py", "startLine": 1, "role": "root_control"},
                {"path": "src/public.py", "startLine": 1},
            ],
            ["src"],
        ),
        "rootControl": excerpts.finding_source_excerpt(
            selected,
            repository,
            [
                {
                    "path": "src/support.py",
                    "startLine": 1,
                    "role": "evidence:root_control",
                },
                {"path": "src/public.py", "startLine": 1, "role": "root_control"},
            ],
            ["src"],
        ),
    }
    (repository / "selected.py").unlink()
    write(repository, "selected.py/private.py", "replacement private source\n")
    result["replacedFile"] = excerpt(single, repository, "selected.py", ["selected.py"])
    result["replacedFileDescendant"] = excerpt(
        single, repository, "selected.py/private.py", ["selected.py"]
    )
    shutil.rmtree(repository / "src")
    result["removedDirectory"] = excerpt(
        selected, repository, "src/nested/child.py", ["src"]
    )
    calls = []
    original = scopes.git_bytes

    def observed(target: Path, *arguments: str):
        calls.append(
            (
                os.environ.get("GIT_NO_LAZY_FETCH"),
                os.environ.get("GIT_ALLOW_PROTOCOL"),
                os.environ.get("GIT_NO_REPLACE_OBJECTS"),
            )
        )
        return original(target, *arguments)

    with patch.object(scopes, "git_bytes", observed):
        result["offline"] = excerpt(selected, repository, "src/public.py", ["src"])
    assert calls and all(call == ("1", "", "1") for call in calls)
    with patch.object(excerpts, "offline_git_bytes", return_value=None):
        result["missingObject"] = excerpt(
            selected, repository, "src/public.py", ["src"]
        )
    return result


def aliases(repository: Path) -> dict:
    composed = unicodedata.normalize("NFC", "café")
    decomposed = unicodedata.normalize("NFD", composed)
    write(repository, "src/nested/public.py", "historical source\n")
    write(repository, f"{composed}/public.py", "unicode source\n")
    write(repository, "Ä/public.py", "non-ASCII source\n")
    revision = commit(repository)
    git(repository, "config", "core.precomposeunicode", "true")
    cases = [
        ("case", "SRC/NESTED", "src/nested", "historical source"),
        ("unicode", decomposed, composed, "unicode source"),
        ("nonAscii", "ä", "Ä", "non-ASCII source"),
    ]
    result = {}
    for name, requested, canonical, content in cases:
        supported = (repository / requested).exists() and (
            repository / requested
        ).samefile(repository / canonical)
        record = scan(repository, revision, [requested])
        saved = json.loads(record["source_scopes_json"])["scopes"]
        if supported:
            assert len(saved) == 1
            parent = repository / canonical
            moved = repository / f"moved-{name}"
            parent.rename(moved)
            try:
                assert (
                    excerpt(record, repository, f"{canonical}/public.py", [requested])
                    == f"1  {content}"
                )
                assert (
                    excerpt(record, repository, f"{requested}/public.py", [requested])
                    == f"1  {content}"
                )
            finally:
                moved.rename(parent)
        else:
            assert saved == []
        result[name] = supported

    blob = git(
        repository, "hash-object", "-w", "--stdin", input_data=b"colliding source\n"
    )
    git(
        repository,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},SRC/hidden.py",
    )
    tree = git(repository, "write-tree")
    collision_revision = git(
        repository,
        "commit-tree",
        tree,
        "-p",
        revision,
        input_data=b"Synthetic collision\n",
    )
    upper = repository / "SRC"
    distinct = not upper.exists()
    if distinct:
        write(repository, "SRC/hidden.py", "colliding source\n")
    collision = scan(repository, collision_revision, ["src"])
    saved = json.loads(collision["source_scopes_json"])["scopes"]
    assert bool(saved) == distinct
    assert excerpt(collision, repository, "SRC/hidden.py", ["src"]) is None
    legacy_collision = {
        "target_revision": collision_revision,
        "target_snapshot_digest": None,
        "recipe_json": json.dumps({"_codexSecurityFileScopes": []}),
    }
    assert (
        excerpt(legacy_collision, repository, "src/nested/public.py", ["src"]) is None
    )
    if distinct:
        shutil.rmtree(upper)
        missing = scan(repository, collision_revision, ["src"])
        assert json.loads(missing["source_scopes_json"])["scopes"] == []
    result["collisionChecked"] = True
    return result


def descendant_aliases(repository: Path) -> dict:
    pairs = [("foo.py", "FOO.py"), ("nested/public.py", "NESTED/public.py")]
    for lower, _ in pairs:
        write(repository, f"selected/{lower}", "lower source\n")
    revision = commit(repository)
    upper_blob = git(
        repository, "hash-object", "-w", "--stdin", input_data=b"upper source\n"
    )
    for _, upper in pairs:
        git(
            repository, "update-index", "--add", "--cacheinfo",
            f"100644,{upper_blob},selected/{upper}",
        )
    tree = git(repository, "write-tree")
    collision = git(
        repository, "commit-tree", tree, "-p", revision,
        input_data=b"Synthetic descendant collision\n",
    )
    for lower, upper in pairs:
        lower_path = repository / "selected" / lower
        upper_path = repository / "selected" / upper
        if not upper_path.exists():
            write(repository, f"selected/{upper}", "upper source\n")
        aliases = lower_path.samefile(upper_path)
        record = scan(repository, collision, ["selected"])
        assert len(json.loads(record["source_scopes_json"])["scopes"]) == 1
        for saved in (record, {**record, "source_scopes_json": None}):
            for path, content in ((lower, "lower"), (upper, "upper")):
                expected = None if aliases else f"1  {content} source"
                actual = excerpt(saved, repository, f"selected/{path}", ["selected"])
                assert actual == expected, (path, actual, expected)
    shutil.rmtree(repository / "selected")
    for lower, upper in pairs:
        for path in (lower, upper):
            assert excerpt(record, repository, f"selected/{path}", ["selected"]) is None
    return {"fileAndDirectoryCollisionsChecked": True, "missingWitnessesOmitted": True}


def alias_evidence(_: Path) -> dict:
    selected, candidate = Path("/synthetic/SECRET.py"), Path("/synthetic/secret.py")
    result = {}
    for kind in ("ordinary", "hardlink", "symlink", "reparse"):
        names = ["SECRET.py", "secret.py"] if kind == "hardlink" else ["SECRET.py"]
        entries = [SimpleNamespace(name=name) for name in names]

        def metadata(path: Path):
            mode = (
                stat.S_IFLNK
                if kind == "symlink" and path == candidate
                else stat.S_IFREG
            )
            return SimpleNamespace(
                st_mode=mode, st_file_attributes=0x400 if kind == "reparse" else 0
            )

        with (
            patch.object(Path, "lstat", metadata),
            patch.object(Path, "samefile", return_value=True),
            patch.object(
                scopes.os, "scandir", side_effect=lambda _: nullcontext(entries)
            ),
            patch.object(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400, create=True),
        ):
            result[kind] = scopes.filesystem_alias(selected, candidate)
    return result


def worktrees(repository: Path) -> dict:
    write(repository, "nested/src/public.py", "nested target source\n")
    write(repository, "private.py", "outside target source\n")
    revision = commit(repository)
    selected = repository / "nested"
    record = scan(selected, revision, ["src"])
    assert (
        excerpt(record, selected, "src/public.py", ["src"]) == "1  nested target source"
    )
    assert excerpt(record, selected, "../private.py", ["src"]) is None
    linked = repository.parent / "linked-worktree"
    git(repository, "worktree", "add", "--quiet", "--detach", str(linked), revision)
    linked_target = linked / "nested"
    assert (
        excerpt(record, linked_target, "src/public.py", ["src"])
        == "1  nested target source"
    )
    linked_record = scan(linked_target, revision, ["."])
    assert (
        excerpt(linked_record, linked_target, "src/public.py", ["."])
        == "1  nested target source"
    )
    assert excerpt(linked_record, linked_target, "private.py", ["."]) is None
    return {"subdirectoryBound": True, "linkedWorktreeBound": True}


def writer(repository: Path, kind: str) -> dict:
    write(repository, "src/public.py", "public source\n")
    write(repository, "selected.py", "selected file\n")
    revision = commit(repository)
    state = repository.parent / "state"
    scan_root = repository.parent / "scans"
    environment = dict(os.environ, CODEX_SECURITY_STATE_DIR=str(state))
    script = str(Path(sys.argv[1]) / "workbench_db.py")

    def command(*arguments: str, succeeds: bool = True):
        result = subprocess.run(
            [sys.executable, "-I", "-B", script, *arguments],
            env=environment,
            text=True,
            capture_output=True,
        )
        if not succeeds:
            assert result.returncode != 0
            return result.stderr
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    recipe = {
        "config": {},
        "mode": "standard",
        "repository": str(repository),
        "target": {"kind": "paths", "paths": ["src", "selected.py"]},
    }
    if kind == "workspace":
        workspace = str(uuid.uuid4())
        command(
            "create-workspace",
            "--workspace-id",
            workspace,
            "--thread-id",
            "synthetic-workspace",
        )
        command(
            "save-workspace",
            "--workspace-id",
            workspace,
            "--target-path",
            str(repository),
            "--scope",
            "src",
            "--mode",
            "standard",
        )
        command(
            "start-scan", "--workspace-id", workspace, "--scan-root", str(scan_root)
        )
    elif kind in {"prompt", "headless"}:
        arguments = [
            "start-prompt-only-scan"
            if kind == "prompt"
            else "start-headless-standard-scan",
            "--thread-id",
            "synthetic-" + kind,
            "--target-path",
            str(repository),
            "--scope",
            "src",
            "--scan-root",
            str(scan_root),
        ]
        if kind == "prompt":
            arguments.extend(("--mode", "standard"))
        command(*arguments)
    elif kind == "deep":
        command(
            "begin-deep-scan",
            "--thread-id",
            "synthetic-direct-deep",
            "--target-path",
            str(repository),
            "--scan-root",
            str(scan_root),
        )
    elif kind == "cli":
        registered, _ = register_recipe(
            repository, {**recipe, "_codexSecurityFileScopes": ["other.py"]}
        )
        assert (
            command("get-scan-recipe", "--scan-id", registered["scanId"])["recipe"]
            == recipe
        )
    else:
        raise AssertionError("Unknown scan writer: " + kind)

    with closing(sqlite3.connect(state / "workbench.sqlite3")) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM scans").fetchall()
        assert len(rows) == 1
        row = dict(rows[0])
    metadata = json.loads(row["source_scopes_json"])
    assert metadata["revision"] == revision
    expected = (
        {"src", "selected.py"}
        if kind == "cli"
        else {"."}
        if kind == "deep"
        else {"src"}
    )
    assert {scope["path"] for scope in metadata["scopes"]} == expected
    historical = {**row, "source_scopes_json": None}
    assert (
        excerpt(historical, repository, "src/public.py", list(expected))
        == "1  public source"
    )
    if kind == "cli":
        assert (
            excerpt(historical, repository, "selected.py", list(expected))
            == "1  selected file"
        )
    else:
        assert row["recipe_json"] is None
        assert "does not have a saved launch recipe" in command(
            "get-scan-recipe", "--scan-id", row["id"], succeeds=False
        )
    if kind == "deep":
        git(
            repository,
            "commit",
            "--amend",
            "--quiet",
            "-m",
            "Rewritten synthetic fixture",
        )
        git(repository, "reflog", "expire", "--expire=now", "--all")
        git(repository, "gc", "--prune=now")
        try:
            git(repository, "cat-file", "-e", revision)
        except subprocess.CalledProcessError:
            pass
        else:
            raise AssertionError("Original commit was not pruned")
        assert excerpt(row, repository, "selected.py", ["."]) == "1  selected file"
    return {
        "writer": kind,
        "sourceAuthorityRecorded": True,
        "launchRecipeUnchanged": True,
        "legacyExactScopesPreserved": True,
    }


def migration(_: Path) -> dict:
    from workbench_schema import MIGRATIONS, apply_migrations

    timestamp = "2026-08-01T00:00:00Z"
    historical = tuple(item for item in MIGRATIONS if item[0] < 40)
    for conflict in (False, True):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        def apply(migrations: tuple[tuple[int, str, str], ...]) -> None:
            apply_migrations(connection, migrations, lambda: timestamp, lambda _: None)

        apply(historical)
        connection.execute(
            "INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "synthetic-scan",
                "synthetic-workspace",
                "synthetic-target",
                "synthetic-revision",
                ".",
                "standard",
                "synthetic-output",
                "complete",
                "reporting",
                timestamp,
                timestamp,
                timestamp,
            ),
        )
        if conflict:
            connection.execute(
                "INSERT INTO schema_migrations VALUES (40, ?, ?)",
                ("unrelated migration", timestamp),
            )
        connection.commit()
        before = [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM schema_migrations ORDER BY version"
            )
        ]
        try:
            apply(MIGRATIONS)
        except SystemExit as error:
            assert conflict and "unsupported source-scope migration history" in str(
                error
            )
            assert [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM schema_migrations ORDER BY version"
                )
            ] == before
            assert "source_scopes_json" not in {
                row["name"] for row in connection.execute("PRAGMA table_info(scans)")
            }
        else:
            assert not conflict
            assert (
                connection.execute("SELECT source_scopes_json FROM scans").fetchone()[0]
                is None
            )
            assert [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM schema_migrations WHERE version < 40 ORDER BY version"
                )
            ] == before
            assert (
                connection.execute(
                    "SELECT name FROM schema_migrations WHERE version=40"
                ).fetchone()[0]
                == "persist authorized source excerpt scopes"
            )
            apply(MIGRATIONS)
        connection.close()
    return {
        "legacyAuthorityUnset": True,
        "otherMigrationsPreserved": True,
        "conflictRejected": True,
    }


with tempfile.TemporaryDirectory(prefix="codex-security-source-scopes-") as temporary:
    repository = Path(temporary).resolve() / "repository"
    repository.mkdir()
    git(repository, "init", "--quiet")
    scenario = sys.argv[2]
    result = (
        writer(repository, scenario.removeprefix("writer_"))
        if scenario.startswith("writer_")
        else {
            "boundaries": boundaries,
            "replacements": replacements,
            "replacement_filters": replacement_filters,
            "replacement_snapshot": replacement_snapshot,
            "working_tree_excerpt": working_tree_excerpt,
            "indexed_scopes": indexed_scopes,
            "display_locations": display_locations,
            "selected_redirects": selected_redirects,
            "unsafe_locations": unsafe_locations,
            "aliases": aliases,
            "descendant_aliases": descendant_aliases,
            "alias_evidence": alias_evidence,
            "worktrees": worktrees,
            "migration": migration,
        }[scenario](repository)
    )
    print(json.dumps(result))
