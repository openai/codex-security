from __future__ import annotations

import difflib
import errno
import hashlib
import json
import os
import runpy
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, cast

import pytest
from workbench_test_support import initialize_git_repository

WORKBENCH_TARGET = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts" / "workbench_target.py")
)
trusted_git_executable = WORKBENCH_TARGET["trusted_git_executable"]
directory_content_digest = cast(Callable[[Path], str], WORKBENCH_TARGET["directory_content_digest"])
worktree_content_digest = cast(Callable[[Path], str], WORKBENCH_TARGET["worktree_content_digest"])
update_digest_field = cast(
    Callable[[Any, bytes, bytes], None], WORKBENCH_TARGET["update_digest_field"]
)
CASE_ALIAS = pytest.param("case", marks=pytest.mark.native_macos)


@pytest.mark.cross_platform
@pytest.mark.parametrize("windows", [False, True])
def test_git_bridge_preserves_explicit_environment_and_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    import workbench_target

    monkeypatch.setattr(workbench_target, "_WINDOWS", windows)
    monkeypatch.setattr(workbench_target, "trusted_git_executable", lambda _target: "git")
    captured: dict[str, Any] = {}

    def run(command: list[str], **kwargs: Any):
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(workbench_target.subprocess, "run", run)
    bridge = tmp_path / "git-environment.json"
    bridge.write_text(
        json.dumps(
            {
                "GIT_CONFIG_GLOBAL": "bridge-global",
                "GIT_CONFIG_SYSTEM": "bridge-system",
                "GIT_CONFIG_PARAMETERS": "bridge-parameters",
                "GIT_ATTR_SOURCE": "HEAD",
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_REPLACE_REF_BASE": "refs/fixture-replacements/",
                "GIT_DIR": "other-repository",
                "HOME": "other-home",
                "GIT_NO_LAZY_FETCH": "0",
                "GIT_ALLOW_PROTOCOL": "all",
            }
        )
    )
    monkeypatch.setenv(
        "codex_security_git_environment_file" if windows else "CODEX_SECURITY_GIT_ENVIRONMENT_FILE",
        str(bridge),
    )
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    monkeypatch.delenv("GIT_CONFIG_SYSTEM", raising=False)
    monkeypatch.setenv("git_config_global" if windows else "GIT_CONFIG_GLOBAL", "")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "")
    monkeypatch.setenv("GIT_ATTR_SOURCE", "")
    monkeypatch.delenv("GIT_ATTR_NOSYSTEM", raising=False)
    monkeypatch.setenv("GIT_NO_REPLACE_OBJECTS", "")
    monkeypatch.delenv("GIT_REPLACE_REF_BASE", raising=False)
    monkeypatch.setenv("GIT_DIR", "other-repository")
    monkeypatch.setenv("GIT_NO_LAZY_FETCH", "0")
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "all")
    before = dict(os.environ)

    workbench_target.git_command(tmp_path, "status", text=False)

    environment = captured["env"]
    assert environment["GIT_CONFIG_GLOBAL"] == ""
    assert environment["GIT_CONFIG_SYSTEM"] == "bridge-system"
    assert environment["GIT_CONFIG_PARAMETERS"] == ""
    assert environment["GIT_ATTR_SOURCE"] == ""
    assert environment["GIT_ATTR_NOSYSTEM"] == "1"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == ""
    assert environment["GIT_REPLACE_REF_BASE"] == "refs/fixture-replacements/"
    assert "GIT_DIR" not in environment
    assert environment.get("HOME") == before.get("HOME")
    assert environment["GIT_NO_LAZY_FETCH"] == "1"
    assert environment["GIT_ALLOW_PROTOCOL"] == ""
    assert dict(os.environ) == before


@pytest.mark.skipif(os.name == "nt", reason="Raw POSIX paths use surrogate-escaped bytes")
def test_git_bridge_keeps_configuration_file_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    configuration = tmp_path / (
        "configuration-\udcff" if sys.platform == "linux" else "configuration"
    )
    configuration.mkdir()
    (configuration / "global").write_text('[include]\npath = "relative"\n')
    (configuration / "relative").write_text("[core]\nexcludesFile = selected-fixture\n")
    for name in tuple(os.environ):
        if name.startswith("GIT_CONFIG_"):
            monkeypatch.delenv(name)
    bridge = tmp_path / "git-environment.json"
    bridge.write_text(
        json.dumps({"GIT_CONFIG_GLOBAL": str(configuration / "global"), "GIT_CONFIG_NOSYSTEM": "1"})
    )
    monkeypatch.setenv("CODEX_SECURITY_GIT_ENVIRONMENT_FILE", str(bridge))

    result = workbench_target.git_command(target, "config", "--get", "core.excludesFile", text=True)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "selected-fixture\n"


def test_git_environment_ignores_old_inline_bridge() -> None:
    import workbench_target

    assert (
        workbench_target._git_configuration_environment(
            {"CODEX_SECURITY_GIT_ENVIRONMENT": '{"GIT_CONFIG_GLOBAL":"old-inline"}'}
        )
        == {}
    )


@pytest.mark.cross_platform
def test_git_bridge_preserves_replacement_namespace_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    (target / "source.py").write_text("selected text\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "replacement fixture"], cwd=target, check=True)
    original = subprocess.check_output(
        ["git", "rev-parse", "HEAD:source.py"], cwd=target, text=True
    ).strip()
    replacement = (
        subprocess.check_output(
            ["git", "hash-object", "-w", "--stdin"], cwd=target, input=b"\0binary fixture\n"
        )
        .decode()
        .strip()
    )
    prefix = "refs/fixture-replacements/"
    subprocess.run(["git", "update-ref", prefix + original, replacement], cwd=target, check=True)
    bridge = tmp_path / "git-environment.json"
    bridge.write_text(json.dumps({"GIT_REPLACE_REF_BASE": prefix}))
    monkeypatch.setenv("CODEX_SECURITY_GIT_ENVIRONMENT_FILE", str(bridge))
    monkeypatch.delenv("GIT_REPLACE_REF_BASE", raising=False)
    monkeypatch.delenv("GIT_NO_REPLACE_OBJECTS", raising=False)
    diff_target = {"kind": "range", "baseRevision": base, "headRevision": "HEAD"}

    assert workbench_target.diff_scope_file_count(target, diff_target) == 0
    monkeypatch.setenv("GIT_REPLACE_REF_BASE", "refs/other/")
    assert workbench_target.diff_scope_file_count(target, diff_target) == 1


@pytest.mark.cross_platform
@pytest.mark.parametrize("carrier", ["indexed", "parameters"])
def test_git_filters_keep_behavior_settings_without_header_carriers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, carrier: str
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    (target / ".gitattributes").write_text("source.py filter=fixture\n")
    source = target / "source.py"
    source.write_bytes(b"source\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "filter settings fixture"], cwd=target, check=True)
    marker = tmp_path / "filter-environment.json"
    filter_script = tmp_path / "filter.py"
    filter_script.write_text(
        "import json, os, pathlib, sys\n"
        "selected = {name: value for name, value in os.environ.items() if "
        "name.startswith('GIT_CONFIG_') or name.upper().startswith('CODEX_SECURITY_GIT_ENVIRONMENT')}\n"
        f"pathlib.Path({str(marker)!r}).write_text(json.dumps(selected))\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read().lower())\n"
    )
    command = " ".join(
        json.dumps(str(path).replace("\\", "/")) for path in (sys.executable, filter_script)
    )
    subprocess.run(["git", "config", "filter.fixture.clean", command], cwd=target, check=True)
    for name in tuple(os.environ):
        if name.startswith("GIT_CONFIG_"):
            monkeypatch.delenv(name)
    if carrier == "indexed":
        configuration = {
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "fixture.keep",
            "GIT_CONFIG_VALUE_0": "Authorization: retained behavior value",
            "GIT_CONFIG_KEY_1": "HTTP.https://synthetic.invalid/.ExtraHeader",
            "GIT_CONFIG_VALUE_1": "HEADER_ONLY_SYNTHETIC",
            "GIT_CONFIG_KEY_2": "fixture.empty",
            "GIT_CONFIG_VALUE_2": "",
            "GIT_CONFIG_KEY_999999": "http.extraHeader",
            "GIT_CONFIG_VALUE_999999": "UNUSED_HEADER_SYNTHETIC",
        }
    else:
        configuration = {
            "GIT_CONFIG_PARAMETERS": "'fixture.keep=Authorization: retained behavior value' "
            "'http.extraHeader=HEADER_ONLY_SYNTHETIC' 'fixture.empty=' 'fixture.boolean'"
        }
    bridge = tmp_path / "git-environment.json"
    bridge.write_text(json.dumps(configuration))
    monkeypatch.setenv("CODEX_SECURITY_GIT_ENVIRONMENT_FILE", str(bridge))
    monkeypatch.setenv("codex_security_git_environment", "OLD_INLINE_HEADER_SYNTHETIC")
    source.write_bytes(b"SOURCE\n")
    os.utime(source, (1, 1))

    diff_target = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == 0
    captured = json.loads(marker.read_text())
    assert not any(name.upper().startswith("CODEX_SECURITY_GIT_ENVIRONMENT") for name in captured)
    assert "HEADER_ONLY_SYNTHETIC" not in json.dumps(captured)
    assert "UNUSED_HEADER_SYNTHETIC" not in json.dumps(captured)
    assert "Authorization: retained behavior value" in json.dumps(captured)
    if carrier == "indexed":
        assert captured["GIT_CONFIG_COUNT"] == "2"
        assert captured["GIT_CONFIG_KEY_0"] == "fixture.keep"
        assert captured["GIT_CONFIG_KEY_1"] == "fixture.empty"
        assert captured["GIT_CONFIG_VALUE_1"] == ""


def test_git_projection_preserves_parameter_order_and_native_errors(tmp_path: Path) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    executable = workbench_target.trusted_git_executable(target)
    assert executable is not None
    environment = {
        "PATH": os.environ["PATH"],
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    entries = [
        "fixture.order=first",
        "fixture.empty=",
        "fixture.boolean",
        "fixture.lines=one\ntwo\n",
        "fixture.quote=it's a \\literal",
        "http.extraHeader=HEADER_ONLY_SYNTHETIC",
        "HTTP.https://synthetic.invalid/.ExtraHeader=",
        "fixture.order=last",
    ]
    quoted = subprocess.check_output(
        [executable, "rev-parse", "--sq-quote", *entries], cwd=target, env=environment
    )
    original = environment | {
        "GIT_CONFIG_COUNT": "4",
        "GIT_CONFIG_KEY_0": "fixture.order",
        "GIT_CONFIG_VALUE_0": "indexed-first",
        "GIT_CONFIG_KEY_1": "fixture.large.first",
        "GIT_CONFIG_VALUE_1": "x" * (256 if os.name == "nt" else 65536),
        "GIT_CONFIG_KEY_2": "http.extraHeader",
        "GIT_CONFIG_VALUE_2": "INDEXED_HEADER_SYNTHETIC",
        "GIT_CONFIG_KEY_3": "fixture.large.last",
        "GIT_CONFIG_VALUE_3": "y" * (256 if os.name == "nt" else 65536),
        "GIT_CONFIG_PARAMETERS": os.fsdecode(quoted).strip(),
        "GIT_CONFIG": os.devnull,
    }
    args = [executable, "config", "--null", "--list", "--show-scope", "--no-includes"]
    native = subprocess.check_output(
        args, cwd=target, env={k: v for k, v in original.items() if k != "GIT_CONFIG"}
    )

    def fixture_settings(output: bytes) -> list[bytes]:
        rows = output.split(b"\0")
        return [
            row
            for scope, row in zip(rows[::2], rows[1::2])
            if scope == b"command" and row.startswith(b"fixture.")
        ]

    native_settings = fixture_settings(native)
    indexed = b"fixture.order\nindexed-first" in native_settings
    selected = workbench_target.git_inspection_environment(original, executable, target)
    # Older Git ignores COUNT; preserve its native meaning instead of enabling it.
    assert selected["GIT_CONFIG_COUNT"] == ("3" if indexed else original["GIT_CONFIG_COUNT"])
    assert selected["GIT_CONFIG_VALUE_1"] == original["GIT_CONFIG_VALUE_1"]
    assert "INDEXED_HEADER_SYNTHETIC" not in selected.values()
    actual = subprocess.check_output(
        args, cwd=target, env={k: v for k, v in selected.items() if k != "GIT_CONFIG"}
    )
    assert fixture_settings(actual) == native_settings
    assert b"HEADER_ONLY_SYNTHETIC" not in actual
    assert b"INDEXED_HEADER_SYNTHETIC" not in actual
    benign = environment | {"GIT_CONFIG_PARAMETERS": "'fixture.keep=unchanged spelling'"}
    assert workbench_target.git_inspection_environment(benign, executable, target) == benign
    for malformed in [
        {"GIT_CONFIG_PARAMETERS": "'unterminated"},
        {
            "GIT_CONFIG_COUNT": "bogus",
            "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": "synthetic",
        },
        {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader"},
        {"GIT_CONFIG_PARAMETERS": "'http.subsection\nname.extraHeader=synthetic'"},
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.subsection\nname.extraHeader",
            "GIT_CONFIG_VALUE_0": "synthetic",
        },
    ]:
        source = environment | malformed
        native = subprocess.run(args, cwd=target, env=source, capture_output=True)
        try:
            projected = workbench_target.git_inspection_environment(source, executable, target)
        except subprocess.CalledProcessError as error:
            assert error.returncode == native.returncode
            assert error.stderr == native.stderr
        else:
            actual = subprocess.run(args, cwd=target, env=projected, capture_output=True)
            assert actual.returncode == native.returncode
            assert actual.stderr == native.stderr
            if native.returncode == 0:
                assert actual.stdout == native.stdout


@pytest.mark.parametrize("parameter_style", ["legacy", "separate"])
def test_git_projection_preserves_native_parameter_key_boundaries(
    tmp_path: Path, parameter_style: str
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    executable = workbench_target.trusted_git_executable(target)
    assert executable is not None
    environment = {
        "PATH": os.environ["PATH"],
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    raw = "\udcff" if sys.platform == "linux" else "雪"
    value_raw = "\udcfe" if sys.platform == "linux" else "雪"
    subsection = "?a=b" if parameter_style == "separate" else "plain"
    key = f"url.https://example.test/{subsection}.insteadof"
    settings = [
        ("fixture.order", "first"),
        (key, "https://other.test/"),
        (f"url.https://example.test/{subsection}.boolean", None),
        (f"url.https://example.test/{subsection}.empty", ""),
        (
            f"url.https://raw-{raw}.test/{subsection}.insteadof",
            f"it's ! \\literal-{value_raw}\nvalue\n",
        ),
        (key, "https://last.test/"),
        ("http.extraHeader", "HEADER_ONLY_SYNTHETIC"),
        ("fixture.order", "last"),
    ]

    def quote(arguments: list[str]) -> str:
        return os.fsdecode(
            subprocess.check_output(
                [executable, "rev-parse", "--sq-quote", *arguments], cwd=target, env=environment
            )
        ).strip()

    parameters = (
        " ".join(
            quote([name]) + "=" + ("" if value is None else quote([value]))
            for name, value in settings
        )
        if parameter_style == "separate"
        else quote([name if value is None else f"{name}={value}" for name, value in settings])
    )
    large = "x" * (256 if os.name == "nt" else 65536)
    source = environment | {
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "fixture.large.first",
        "GIT_CONFIG_VALUE_0": large,
        "GIT_CONFIG_KEY_1": "fixture.large.last",
        "GIT_CONFIG_VALUE_1": large,
        "GIT_CONFIG_PARAMETERS": parameters,
    }
    args = [executable, "config", "--null", "--list", "--show-origin", "--no-includes"]
    native = subprocess.run(args, cwd=target, env=source, capture_output=True)
    if native.returncode != 0:
        # Older Git rejects separate key/value quoting; keep that native error.
        assert parameter_style == "separate"
        assert b"bogus format in GIT_CONFIG_PARAMETERS" in native.stderr
        with pytest.raises(subprocess.CalledProcessError) as raised:
            workbench_target.git_inspection_environment(source, executable, target)
        assert raised.value.returncode == native.returncode
        assert raised.value.stderr == native.stderr
        return

    projected = workbench_target.git_inspection_environment(source, executable, target)
    actual = subprocess.run(args, cwd=target, env=projected, capture_output=True)
    assert actual.returncode == 0, actual.stderr
    assert b"HEADER_ONLY_SYNTHETIC" not in actual.stdout
    assert projected["GIT_CONFIG_VALUE_0"] == large
    assert projected["GIT_CONFIG_VALUE_1"] == large

    def user_settings(output: bytes) -> list[bytes]:
        fields = output.split(b"\0")
        return [
            record
            for origin, record in zip(fields[::2], fields[1::2])
            if origin == b"command line:" and record.startswith((b"fixture.", b"url."))
        ]

    assert user_settings(actual.stdout) == user_settings(native.stdout)


def test_missing_trusted_git_does_not_run_configuration_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import workbench_target

    monkeypatch.setattr(workbench_target, "trusted_git_executable", lambda _target: None)
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'http.extraHeader=synthetic'")
    monkeypatch.setattr(
        workbench_target.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("untrusted Git ran"),
    )
    assert workbench_target.git_command(tmp_path, "status", text=False).returncode == 127


@pytest.fixture(
    params=[
        pytest.param(False, id="emulated"),
        pytest.param(True, id="native", marks=pytest.mark.native_windows),
    ]
)
def junction_factory(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    import workbench_target

    native = request.param
    if native and os.name != "nt":
        pytest.skip("requires native Windows junctions")
    targets: dict[Path, Path] = {}
    modes: dict[Path, int] = {}
    if not native:
        monkeypatch.setattr(workbench_target, "_WINDOWS", True)
        real_lstat = Path.lstat
        real_readlink = os.readlink

        def metadata(path: Path, *args: Any, **kwargs: Any) -> Any:
            result = real_lstat(path, *args, **kwargs)
            if path in targets:
                fields = {key: getattr(result, key) for key in dir(result) if key.startswith("st_")}
                fields["st_reparse_tag"] = 0xA0000003
                fields["st_mode"] = modes.get(path, result.st_mode)
                return SimpleNamespace(**fields)
            return result

        def readlink(path: Any, *args: Any, **kwargs: Any) -> Any:
            if Path(path) in targets:
                return str(targets[Path(path)])
            return real_readlink(path, *args, **kwargs)

        def copy_junction(source: Path, destination: Path) -> None:
            # Emulate the filesystem result, not the native GET/SET implementation.
            if any(destination.iterdir()):
                raise OSError(errno.ENOTEMPTY, "junction destination is not empty")
            mode = destination.lstat().st_mode
            # Windows readonly directories do not impose POSIX child-write permissions.
            os.chmod(destination, stat.S_IMODE(mode) | stat.S_IWUSR)
            shutil.copytree(source, destination, dirs_exist_ok=True)
            os.chmod(destination, 0o755)
            targets[destination] = targets[source]
            modes[destination] = mode

        monkeypatch.setattr(Path, "lstat", metadata)
        monkeypatch.setattr(os, "readlink", readlink)
        monkeypatch.setattr(workbench_target, "copy_directory_junction", copy_junction)

    def create(link: Path, target: Path) -> None:
        if native:
            if link.exists():
                link.rmdir()
            subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True)
        else:
            shutil.copytree(target, link, dirs_exist_ok=True)
            targets[link] = target

    return create


@pytest.mark.parametrize("binary_base", [False, True])
def test_local_diff_count_uses_base_files_below_directory_links(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    binary_base: bool,
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    nested = target / "src" / "nested"
    nested.mkdir(parents=True)
    (nested / "changed.py").write_bytes(b"\0base\n" if binary_base else b"base\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "base source"], cwd=target, check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    (nested / "changed.py").write_text("changed\n")
    (nested / "added.py").write_text("staged\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(
        ["git", "update-index", "--skip-worktree", "src/nested/changed.py"],
        cwd=target,
        check=True,
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "changed.py").write_bytes(b"outside\n" if binary_base else b"\0outside\n")
    (outside / "added.py").write_text("outside addition\n")
    shutil.rmtree(nested)
    junction_factory(nested, outside)

    changes = workbench_target.git_changed_paths(target, revision, revision, "local-patch")
    assert changes == [(nested / "changed.py", "D")]
    diff_target = {"kind": "working_tree", "baseRevision": revision, "headRevision": revision}
    assert workbench_target.diff_scope_file_count(target, diff_target) == int(not binary_base)


@pytest.mark.parametrize(
    ("change", "skip_worktree"), [("rename", False), ("rename", True), ("recreated", False)]
)
@pytest.mark.parametrize("location", ["inside", "outside"])
@pytest.mark.parametrize("binary_base", [False, True])
def test_local_diff_preserves_deletions_below_directory_links(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    monkeypatch: pytest.MonkeyPatch,
    change: str,
    skip_worktree: bool,
    location: str,
    binary_base: bool,
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    subprocess.run(["git", "config", "diff.renames", "true"], cwd=target, check=True)
    nested = target / "dir"
    nested.mkdir()
    name = ("Old.py" if os.name == "nt" else "Old\tfile.py") if change == "rename" else "dir/new.py"
    (target / name).write_bytes(b"\0historical\n" if binary_base else b"historical text\n")
    destination = target / "inside" if location == "inside" else tmp_path / "outside"
    destination.mkdir()
    linked_source = destination / "new.py"
    linked_source.write_bytes(b"foreign text\n" if binary_base else b"\0foreign\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "historical source"], cwd=target, check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    source_blob = subprocess.check_output(
        ["git", "rev-parse", f"HEAD:{name}"], cwd=target, text=True
    ).strip()
    if change == "rename":
        subprocess.run(["git", "mv", name, "dir/new.py"], cwd=target, check=True)
        if skip_worktree:
            subprocess.run(
                ["git", "update-index", "--skip-worktree", "dir/new.py"], cwd=target, check=True
            )
    else:
        subprocess.run(["git", "rm", "dir/new.py"], cwd=target, check=True)
    if nested.exists():
        shutil.rmtree(nested)
    junction_factory(nested, destination)
    original_open = Path.open

    def open_source(path: Path, *args: Any, **kwargs: Any):
        assert path not in {nested / "new.py", linked_source}, "opened a linked source"
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_source)
    changes = workbench_target._git_changes(target, revision, revision, "local-patch")
    assert [(item.name, item.status, item.base_blob) for item in changes] == [
        (name, "D", source_blob)
    ]
    diff_target = {"kind": "working_tree", "baseRevision": revision, "headRevision": revision}
    assert workbench_target.diff_scope_file_count(target, diff_target) == int(not binary_base)


@pytest.mark.skipif(os.name == "nt", reason="POSIX file symlinks do not require developer mode")
@pytest.mark.parametrize("location", ["inside", "outside"])
@pytest.mark.parametrize("binary_base", [False, True])
def test_local_diff_preserves_rename_source_when_destination_is_a_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, location: str, binary_base: bool
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    subprocess.run(["git", "config", "diff.renames", "true"], cwd=target, check=True)
    source = target / "Old\tfile.py"
    source.write_bytes(b"\0historical\n" if binary_base else b"historical text\n")
    linked_source = target / "inside.py" if location == "inside" else tmp_path / "outside.py"
    linked_source.write_bytes(b"foreign text\n" if binary_base else b"\0foreign\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "historical source"], cwd=target, check=True)
    source_blob = subprocess.check_output(
        ["git", "rev-parse", "HEAD:Old\tfile.py"], cwd=target, text=True
    ).strip()
    subprocess.run(["git", "mv", source.name, "new.py"], cwd=target, check=True)
    subprocess.run(["git", "update-index", "--skip-worktree", "new.py"], cwd=target, check=True)
    destination = target / "new.py"
    destination.unlink()
    destination.symlink_to(linked_source)
    original_open = Path.open

    def open_source(path: Path, *args: Any, **kwargs: Any):
        assert path not in {destination, linked_source}, "opened a linked source"
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_source)
    changes = workbench_target._git_changes(target, "HEAD", "HEAD", "local-patch")
    assert [(item.name, item.status, item.base_blob) for item in changes] == [
        (source.name, "D", source_blob)
    ]
    diff_target = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == int(not binary_base)


@pytest.mark.parametrize("replacement", ["missing", "directory", "junction"])
def test_local_diff_preserves_rename_source_when_destination_is_ineligible(
    tmp_path: Path, junction_factory: Callable[[Path, Path], None], replacement: str
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    subprocess.run(["git", "config", "diff.renames", "true"], cwd=target, check=True)
    (target / "old.py").write_text("historical text\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "historical source"], cwd=target, check=True)
    subprocess.run(["git", "mv", "old.py", "new.py"], cwd=target, check=True)
    subprocess.run(["git", "update-index", "--skip-worktree", "new.py"], cwd=target, check=True)
    destination = target / "new.py"
    destination.unlink()
    if replacement == "directory":
        destination.mkdir()
    elif replacement == "junction":
        outside = tmp_path / "outside"
        outside.mkdir()
        junction_factory(destination, outside)

    assert workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch") == [
        ("old.py", "D")
    ]
    diff_target = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == 1


@pytest.mark.cross_platform
@pytest.mark.parametrize("binary", [False, True])
def test_local_diff_safe_recreated_files_keep_working_tree_selection(
    tmp_path: Path, binary: bool
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    source = target / "source.py"
    source.write_text("historical text\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "historical source"], cwd=target, check=True)
    subprocess.run(["git", "rm", "source.py"], cwd=target, check=True)
    source.write_bytes(b"\0replacement\n" if binary else b"replacement text\n")

    assert workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch") == [
        ("source.py", "A")
    ]
    diff_target = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == int(not binary)


@pytest.mark.cross_platform
def test_local_diff_count_preserves_case_only_renames(tmp_path: Path) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    subprocess.run(["git", "config", "diff.renames", "false"], cwd=target, check=True)
    (target / "source.py").write_text("base\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "base source"], cwd=target, check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    subprocess.run(["git", "mv", "source.py", "Source.py"], cwd=target, check=True)
    (target / "Source.py").write_text("changed\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)

    changes = workbench_target.git_changed_paths(target, revision, revision, "local-patch")
    assert {path.name: status for path, status in changes} == {"source.py": "D", "Source.py": "A"}
    diff_target = {"kind": "working_tree", "baseRevision": revision, "headRevision": revision}
    assert workbench_target.diff_scope_file_count(target, diff_target) == 2


@pytest.mark.cross_platform
@pytest.mark.parametrize("kind", ["range", "working_tree"])
@pytest.mark.parametrize("binary", [False, True])
def test_diff_count_preserves_historical_git_path_spelling(
    tmp_path: Path, kind: str, binary: bool
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    head = initialize_git_repository(target)
    name = r"legacy\source.py"
    blob = subprocess.check_output(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=target,
        input=b"\0historical\n" if binary else b"historical\n",
    ).strip()
    entries = subprocess.check_output(["git", "ls-tree", "-z", head], cwd=target)
    # Construct the historical tree without checking out a name Windows cannot represent.
    tree = subprocess.check_output(
        ["git", "mktree", "-z"],
        cwd=target,
        input=entries + b"100644 blob " + blob + b"\t" + name.encode() + b"\0",
    ).strip()
    base = subprocess.check_output(
        ["git", "commit-tree", tree.decode(), "-p", head, "-m", "historical source"],
        cwd=target,
        text=True,
    ).strip()
    mode = "local-patch" if kind == "working_tree" else "revisions"
    assert workbench_target.git_changed_path_names(target, base, head, mode) == [(name, "D")]
    diff_target = {"kind": kind, "baseRevision": base, "headRevision": head}
    assert workbench_target.diff_scope_file_count(target, diff_target) == int(not binary)


@pytest.mark.cross_platform
@pytest.mark.parametrize("kind", ["range", "working_tree"])
def test_diff_count_classifies_each_selected_blob_once(
    tmp_path: Path, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    subprocess.run(["git", "config", "diff.renames", "false"], cwd=target, check=True)
    contents = {"text": b"shared text\n", "binary": b"\0shared binary\n"}
    for label, data in contents.items():
        for index in range(2):
            (target / f"removed-{label}-{index}").write_bytes(data)
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "base duplicate blobs"], cwd=target, check=True)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    object_ids = {
        subprocess.check_output(
            ["git", "rev-parse", f"HEAD:removed-{label}-0"], cwd=target, text=True
        ).strip()
        for label in contents
    }
    for label, data in contents.items():
        for index in range(2):
            (target / f"removed-{label}-{index}").unlink()
            (target / f"added-{label}-{index}").write_bytes(data)
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    head = base
    if kind == "range":
        subprocess.run(["git", "commit", "-qm", "move duplicate blobs"], cwd=target, check=True)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    sample_blobs = workbench_target.git_blob_samples
    requests: list[list[str]] = []

    def record_samples(repository: Path, names: list[str], **kwargs: Any):
        requests.append(names)
        return sample_blobs(repository, names, **kwargs)

    monkeypatch.setattr(workbench_target, "git_blob_samples", record_samples)
    diff_target = {"kind": kind, "baseRevision": base, "headRevision": head}
    assert workbench_target.diff_scope_file_count(target, diff_target) == 4
    assert len(requests) == 1
    assert len(requests[0]) == 2
    assert set(requests[0]) == object_ids


def test_local_diff_count_skips_paths_outside_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    target.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("outside = True\n")
    monkeypatch.setattr(
        workbench_target,
        "_git_changes",
        lambda *_args: [workbench_target._GitChange(f"../{outside.name}", "A", "", "")],
    )
    diff_target = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == 0


def test_local_diff_count_excludes_metadata_before_git_filters(tmp_path: Path) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    (target / ".gitattributes").write_text("**/.svn/** filter=fixture\n")
    metadata = target / ".svn"
    metadata.mkdir()
    source = metadata / "source.txt"
    source.write_text("before\n")
    subprocess.run(["git", "add", "-f", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "metadata fixture"], cwd=target, check=True)
    subprocess.run(
        ["git", "config", "filter.fixture.clean", "echo %f >> .git/filter-calls; cat"],
        cwd=target,
        check=True,
    )
    source.write_text("after\n")
    calls = target / ".git" / "filter-calls"
    diff_target = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == 0
    assert not calls.exists()
    subprocess.run(["git", "add", "-f", "."], cwd=target, check=True)
    assert calls.exists()


@pytest.mark.cross_platform
@pytest.mark.parametrize("change", ["stat_only", "mode_only", "rename", "binary"])
def test_local_diff_count_preserves_content_changes(tmp_path: Path, change: str) -> None:
    import workbench_target

    if change == "mode_only" and os.name == "nt":
        pytest.skip("Windows does not expose executable-bit changes")
    target = tmp_path / "repository"
    initialize_git_repository(target)
    name = "source.py" if os.name == "nt" else "source\tfile.py"
    source = target / name
    source.write_text("source\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "content fixture"], cwd=target, check=True)
    os.utime(target / "README.md", (1, 1))
    expected = [name]
    if change == "stat_only":
        os.utime(source, (1, 1))
        expected = []
    elif change == "mode_only":
        source.chmod(0o755)
    elif change == "rename":
        destination = "renamed.py" if os.name == "nt" else "renamed\tfile\tname.py"
        subprocess.run(["git", "mv", name, destination], cwd=target, check=True)
        expected = [destination]
    else:
        source.write_bytes(b"\0binary\n")
    changes = workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch")
    assert [name for name, _status in changes] == expected
    diff_target = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == int(
        change in {"mode_only", "rename"}
    )


@pytest.mark.cross_platform
def test_local_diff_classifies_binary_before_git_normalization(tmp_path: Path) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=target, check=True)
    (target / ".gitattributes").write_text("asset.bin filter=fixture\n")
    (target / "asset.bin").write_bytes(b"\0original\n")
    sources = {
        "source.py": b"before\n",
        "utf16le.py": b"\xff\xfe" + "before\n".encode("utf-16-le"),
        "utf16be.py": b"\xfe\xff" + "before\n".encode("utf-16-be"),
    }
    for name, contents in sources.items():
        (target / name).write_bytes(contents)
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "binary classification fixture"], cwd=target, check=True
    )
    subprocess.run(["git", "config", "filter.fixture.clean", "exit 1"], cwd=target, check=True)
    subprocess.run(["git", "config", "filter.fixture.required", "true"], cwd=target, check=True)
    binary = b"b" * (64 * 1024) + b"\0changed\n"
    (target / "asset.bin").write_bytes(binary)
    (target / "source.py").write_bytes(b"after\n")
    (target / "utf16le.py").write_bytes(b"\xff\xfe" + "after\n".encode("utf-16-le"))
    (target / "utf16be.py").write_bytes(b"\xfe\xff" + "after\n".encode("utf-16-be"))

    # Normalizing this excluded binary would fail; a late NUL still excludes it.
    normalized = subprocess.run(
        ["git", "hash-object", "--path=asset.bin", "--stdin"],
        cwd=target,
        input=binary,
        capture_output=True,
    )
    assert normalized.returncode != 0
    assert workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch") == [
        (name, "M") for name in sorted(["asset.bin", *sources])
    ]
    diff_target = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == len(sources)


@pytest.mark.cross_platform
@pytest.mark.parametrize("normalization", ["binary_attribute", "eol", "clean_filter"])
def test_local_diff_ignores_equivalent_normalized_contents(
    tmp_path: Path, normalization: str
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    source = target / "source.py"
    source.write_bytes(b"source\n")
    attributes = {
        "binary_attribute": "source.py -diff\n",
        "eol": "source.py text eol=lf\n",
        "clean_filter": "source.py filter=fixture\n",
    }
    (target / ".gitattributes").write_text(attributes[normalization])
    if normalization == "clean_filter":
        subprocess.run(
            ["git", "config", "filter.fixture.clean", "tr '[:upper:]' '[:lower:]'"],
            cwd=target,
            check=True,
        )
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "normalized fixture"], cwd=target, check=True)
    if normalization == "eol":
        source.write_bytes(b"source\r\n")
    elif normalization == "clean_filter":
        source.write_bytes(b"SOURCE\n")
    os.utime(source, (1, 1))
    index = target / ".git" / "index"
    before = index.read_bytes()
    assert workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch") == []
    diff_target = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == 0
    assert index.read_bytes() == before


@pytest.mark.cross_platform
@pytest.mark.parametrize("normalization", ["text_auto", "autocrlf", "changed_filter"])
def test_local_diff_preserves_index_aware_eol_conversion(
    tmp_path: Path, normalization: str
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=target, check=True)
    source = target / "source.txt"
    source.write_bytes(b"SOURCE\r\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "raw CRLF fixture"], cwd=target, check=True)
    attributes = "**/.svn/** filter=probe\n"
    if normalization == "text_auto":
        attributes += "*.txt text=auto\n"
    elif normalization == "changed_filter":
        attributes += "source.txt filter=fixture\n"
    (target / ".gitattributes").write_text(attributes)
    metadata = target / ".svn"
    metadata.mkdir()
    (metadata / "source.txt").write_text("before\n")
    subprocess.run(["git", "add", "-f", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "conversion fixture"], cwd=target, check=True)
    if normalization == "autocrlf":
        subprocess.run(["git", "config", "core.autocrlf", "true"], cwd=target, check=True)
    elif normalization == "changed_filter":
        subprocess.run(
            ["git", "config", "filter.fixture.clean", "tr '[:upper:]' '[:lower:]'"],
            cwd=target,
            check=True,
        )
    subprocess.run(
        ["git", "config", "filter.probe.clean", "echo %f >> .git/filter-calls; cat"],
        cwd=target,
        check=True,
    )
    (metadata / "source.txt").write_text("after\n")
    os.utime(source, (1, 1))
    before = (target / ".git" / "index").read_bytes()
    expected = [("source.txt", "M")] if normalization == "changed_filter" else []
    assert (
        workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch") == expected
    )
    diff_target = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == len(expected)
    assert (target / ".git" / "index").read_bytes() == before
    assert not (target / ".git" / "filter-calls").exists()


@pytest.mark.cross_platform
def test_local_diff_batches_eligible_normalization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    names = [f"source-{index:03}.txt" for index in range(24)]
    for name in names:
        (target / name).write_text("before\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "batch fixture"], cwd=target, check=True)
    expected = []
    for index, name in enumerate(names):
        if index % 3:
            (target / name).write_text("after\n")
            expected.append((name, "M"))
        os.utime(target / name, (1, 1))
    native_run = subprocess.run
    calls: list[list[str]] = []

    def traced(command: list[str], *args: Any, **kwargs: Any):
        calls.append(command)
        return native_run(command, *args, **kwargs)

    monkeypatch.setattr(workbench_target.subprocess, "run", traced)
    before = (target / ".git" / "index").read_bytes()
    assert (
        workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch") == expected
    )
    assert sum("hash-object" in command for command in calls) == 1
    assert sum("ls-files" in command and "--stage" in command for command in calls) == 1
    assert sum("status" in command for command in calls) == 1
    assert (target / ".git" / "index").read_bytes() == before


@pytest.mark.cross_platform
@pytest.mark.parametrize("operation", ["hash-object", "ls-files", "status"])
@pytest.mark.parametrize("windows_error", [False, True])
def test_local_diff_retries_native_argument_length_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str, windows_error: bool
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    names = [f"source-{index}.txt" for index in range(3)]
    for name in names:
        (target / name).write_text("before\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "argument fixture"], cwd=target, check=True)
    for name in names:
        (target / name).write_text("after\n")
    native_run = subprocess.run
    failures = 0

    def limited(command: list[str], *args: Any, **kwargs: Any):
        nonlocal failures
        if (
            operation in command
            and (operation != "ls-files" or "--stage" in command)
            and len(command[command.index("--") + 1 :]) == len(names)
        ):
            failures += 1
            error = OSError(errno.EINVAL if windows_error else errno.E2BIG, "argument fixture")
            if windows_error:
                error.winerror = 206
            raise error
        return native_run(command, *args, **kwargs)

    monkeypatch.setattr(workbench_target.subprocess, "run", limited)
    before = (target / ".git" / "index").read_bytes()
    assert workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch") == [
        (name, "M") for name in names
    ]
    assert failures == 1
    assert (target / ".git" / "index").read_bytes() == before


@pytest.mark.cross_platform
@pytest.mark.parametrize("failure", ["fatal", "singleton_length", "disappearing_source"])
def test_local_diff_batch_preserves_native_failures_and_readable_peers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    names = ["gone.txt", "peer.txt"]
    for name in names:
        (target / name).write_text("before\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "failure fixture"], cwd=target, check=True)
    for name in names:
        (target / name).write_text("after\n")
    native_run = subprocess.run
    calls = 0
    length_error = OSError(errno.E2BIG, "native argument fixture")

    def failing(command: list[str], *args: Any, **kwargs: Any):
        nonlocal calls
        if "hash-object" in command:
            calls += 1
            if failure == "fatal":
                return subprocess.CompletedProcess(
                    command, 128, stdout=b"", stderr=b"native fatal fixture diagnostic\n"
                )
            if failure == "singleton_length":
                raise length_error
            if calls == 1:
                (target / "gone.txt").unlink()
        return native_run(command, *args, **kwargs)

    monkeypatch.setattr(workbench_target.subprocess, "run", failing)
    if failure == "fatal":
        with pytest.raises(subprocess.CalledProcessError) as error:
            workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch")
        assert error.value.returncode == 128
        assert error.value.stderr == b"native fatal fixture diagnostic\n"
        assert calls == 1
    elif failure == "singleton_length":
        with pytest.raises(OSError) as error:
            workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch")
        assert error.value is length_error
        assert calls == 2
    else:
        assert workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch") == [
            ("peer.txt", "M")
        ]
        assert calls == 2


@pytest.mark.cross_platform
@pytest.mark.parametrize("index_kind", ["symlink", "unmerged"])
@pytest.mark.parametrize("modified", [False, True])
def test_local_diff_normalizes_working_text_with_nonregular_or_unmerged_index(
    tmp_path: Path, index_kind: str, modified: bool
) -> None:
    import workbench_target

    if index_kind == "symlink" and os.name == "nt":
        pytest.skip("Requires a POSIX symlink")
    target = tmp_path / "repository"
    initialize_git_repository(target)
    source = target / "source.txt"
    source.write_text("base\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "index fixture"], cwd=target, check=True)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    if index_kind == "symlink":
        source.unlink()
        source.symlink_to("destination")
        subprocess.run(["git", "add", "source.txt"], cwd=target, check=True)
        source.unlink()
    else:
        branch = subprocess.check_output(
            ["git", "symbolic-ref", "--short", "HEAD"], cwd=target, text=True
        ).strip()
        subprocess.run(["git", "checkout", "-qb", "fixture-side"], cwd=target, check=True)
        source.write_text("side\n")
        subprocess.run(["git", "commit", "-qam", "side fixture"], cwd=target, check=True)
        subprocess.run(["git", "checkout", "-q", branch], cwd=target, check=True)
        source.write_text("main\n")
        subprocess.run(["git", "commit", "-qam", "main fixture"], cwd=target, check=True)
        merge = subprocess.run(
            ["git", "merge", "fixture-side", "--no-edit"], cwd=target, capture_output=True
        )
        assert merge.returncode == 1
    source.write_text("changed\n" if modified else "base\n")
    os.utime(source, (1, 1))
    assert workbench_target.git_changed_path_names(target, base, "HEAD", "local-patch") == (
        [("source.txt", "M")] if modified else []
    )
    diff_target = {"kind": "working_tree", "baseRevision": base, "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == int(modified)


@pytest.mark.cross_platform
def test_local_diff_does_not_require_unselected_older_blob(tmp_path: Path) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    source = target / "source.py"
    source.write_text("before\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "base fixture"], cwd=target, check=True)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    old = subprocess.check_output(
        ["git", "rev-parse", "HEAD:source.py"], cwd=target, text=True
    ).strip()
    source.write_text("after\n")
    subprocess.run(["git", "commit", "-qam", "current fixture"], cwd=target, check=True)
    (target / ".git" / "objects" / old[:2] / old[2:]).unlink()

    assert workbench_target.git_changed_path_names(target, base, "HEAD", "local-patch") == [
        ("source.py", "M")
    ]
    diff_target = {"kind": "working_tree", "baseRevision": base, "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == 1


@pytest.mark.skipif(os.name == "nt", reason="Requires POSIX unreadable files and FIFOs")
@pytest.mark.parametrize("kind", ["unreadable", "fifo"])
def test_local_diff_skips_ineligible_contents_without_aborting(tmp_path: Path, kind: str) -> None:
    import workbench_target

    if kind == "unreadable" and os.getuid() == 0:
        pytest.skip("root can read files without permission bits")
    target = tmp_path / "repository"
    initialize_git_repository(target)
    source = target / "unavailable.py"
    source.write_text("before\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "unavailable fixture"], cwd=target, check=True)
    if kind == "unreadable":
        source.write_text("different sized contents\n")
        source.chmod(0)
    else:
        source.unlink()
        os.mkfifo(source)
    (target / "readable.py").write_text("readable\n")
    try:
        assert workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch") == [
            ("readable.py", "A")
        ]
        diff_target = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
        assert workbench_target.diff_scope_file_count(target, diff_target) == 1
    finally:
        if kind == "unreadable":
            source.chmod(0o600)


def test_local_diff_checks_junctions_before_running_clean_filters(
    tmp_path: Path, junction_factory: Callable[[Path, Path], None]
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    (target / ".gitattributes").write_text("linked/source.py filter=fixture\n")
    linked = target / "linked"
    linked.mkdir()
    (linked / "source.py").write_text("base\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "junction filter fixture"], cwd=target, check=True)
    shutil.rmtree(linked)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "source.py").write_text("foreign different sized contents\n")
    junction_factory(linked, outside)
    subprocess.run(
        ["git", "config", "filter.fixture.clean", "echo %f >> .git/filter-calls; cat"],
        cwd=target,
        check=True,
    )
    assert workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch") == [
        ("linked/source.py", "D")
    ]
    diff_target = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == 1
    calls = target / ".git" / "filter-calls"
    assert not calls.exists()
    result = workbench_target.git_command(
        target,
        "hash-object",
        "--path=linked/source.py",
        "--stdin",
        text=False,
        input_data=b"control\n",
    )
    result.check_returncode()
    assert "linked/source.py" in calls.read_text()


@pytest.mark.parametrize(
    ("git_repository", "git_exclusion"),
    [
        (None, None),
        ("untracked", None),
        ("indexed", None),
        ("untracked", ".gitignore"),
        ("untracked", ".git/info/exclude"),
        ("nested", ".git/info/exclude"),
    ],
    ids=[
        "plain",
        "git-untracked",
        "git-indexed",
        "gitignore",
        "git-info-exclude",
        "nested-info-exclude",
    ],
)
@pytest.mark.parametrize(
    "change",
    [
        "unchanged",
        "unrelated_file",
        "junction_target",
        "same_content_target",
        "target_contents",
        "target_emptied",
        "target_populated",
    ],
)
def test_reviewed_patch_preserves_junction_boundaries(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    change: str,
    git_repository: str | None,
    git_exclusion: str | None,
) -> None:
    import workbench_db

    source = tmp_path / "source"
    source.mkdir()
    if git_repository:
        subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    junction_root = source
    if git_repository == "nested":
        junction_root = source / "nested"
        initialize_git_repository(junction_root)
    if git_exclusion is not None:
        (junction_root / git_exclusion).write_text("dependencies/linked_directory/\n")
    (junction_root / "dependencies").mkdir()
    junction = junction_root / "dependencies" / "linked_directory"
    outside = tmp_path / "outside"
    outside.mkdir()
    if change != "target_populated":
        (outside / "source.txt").write_text("original contents\n")
    junction_factory(junction, outside)
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    patch = b"diff --git a/app.txt b/app.txt\n--- a/app.txt\n+++ b/app.txt\n@@ -1 +1 @@\n-before\n+after\n"
    (scan_dir / "reviewed.patch").write_bytes(patch)
    scan = {
        "target_path": str(source),
        "target_inode": source.stat().st_ino,
        "target_revision": "unversioned",
        "scan_dir": str(scan_dir),
    }
    (source / "app.txt").write_text("before\n")
    if git_repository == "indexed":
        subprocess.run(["git", "add", "."], cwd=source, check=True)
    remediation = {
        "base_revision": "unversioned",
        "base_content_digest": workbench_db.directory_content_digest(source),
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
    }
    (source / "app.txt").write_text("after\n")
    if change in {"junction_target", "same_content_target"}:
        junction_target = tmp_path / "other"
        junction_target.mkdir()
        (junction_target / "source.txt").write_text(
            "original contents\n"
            if change == "same_content_target"
            else "different target contents\n"
        )
        junction_factory(junction, junction_target)
    elif change in {"target_contents", "target_populated"}:
        (junction / "source.txt").write_text("changed outside the snapshot boundary\n")
    elif change == "target_emptied":
        (junction / "source.txt").unlink()
    elif change == "unrelated_file":
        (source / "unrelated.txt").write_text("outside the reviewed patch\n")
    if change == "unrelated_file" or (
        change in {"junction_target", "same_content_target"} and git_exclusion is None
    ):
        with pytest.raises(SystemExit, match="changes outside the reviewed patch"):
            workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")
    else:
        assert workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")


@pytest.mark.parametrize(
    ("git_repository", "readonly_target"),
    [(False, False), (True, False), (False, True)],
    ids=["plain", "git", "readonly-empty-target"],
)
def test_reviewed_patch_preserves_readonly_junction(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    git_repository: bool,
    readonly_target: bool,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    if git_repository:
        subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    if readonly_target:
        os.chmod(outside, stat.S_IREAD | stat.S_IEXEC)
    else:
        (outside / "file.txt").write_text("external contents\n")
    outside_mode = outside.stat().st_mode
    junction = source / "linked"
    junction_factory(junction, outside)
    os.chmod(junction, stat.S_IREAD | stat.S_IEXEC)
    try:
        assert not junction.lstat().st_mode & stat.S_IWRITE
        assert outside.stat().st_mode == outside_mode
        assert_reviewed_change(source, tmp_path, "app.txt", "before\n", "after\n")
        assert outside.stat().st_mode == outside_mode
        if not readonly_target:
            assert (outside / "file.txt").read_text() == "external contents\n"
    finally:
        os.chmod(junction, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)


@pytest.mark.parametrize("scope", [".", "component"])
@pytest.mark.parametrize("populated", [False, True])
def test_versioned_reviewed_patch_preserves_nested_junctions(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    populated: bool,
) -> None:
    import workbench_db

    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    target = repository / scope
    target.mkdir(exist_ok=True)
    (target / "app.txt").write_text("before\n")
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "Add target"], cwd=repository, check=True)
    nested = target / "nested"
    initialize_git_repository(nested)
    outside = tmp_path / "outside"
    outside.mkdir()
    if populated:
        (outside / "external.txt").write_text("outside contents\n")
    junction = nested / "linked"
    junction_factory(junction, outside)
    relative_junction = junction.relative_to(repository)
    original_command = workbench_db.git_command
    original_restore = workbench_db.restore_directory_junctions
    reversed_roots: list[Path] = []
    restored: list[Path] = []

    def command(path, *args, **kwargs):
        if args[0] == "apply":
            copied = kwargs["work_tree"]
            placeholder = copied / relative_junction
            assert placeholder.is_dir()
            assert not getattr(placeholder.lstat(), "st_reparse_tag", 0)
            assert list(placeholder.iterdir()) == []
        result = original_command(path, *args, **kwargs)
        if args[0] == "apply" and result.returncode == 0:
            reversed_roots.append(copied)
        return result

    def restore(source, destination, junctions):
        assert source == repository
        assert reversed_roots == [destination]
        assert relative_junction in junctions
        original_restore(source, destination, junctions)
        restored.append(destination)

    monkeypatch.setattr(workbench_db, "git_command", command)
    monkeypatch.setattr(workbench_db, "restore_directory_junctions", restore)
    assert_reviewed_change(
        target,
        tmp_path,
        "app.txt",
        "before\n",
        "after\n",
        revision=workbench_db.git_revision(target),
    )
    assert len(restored) == 1
    assert sorted(path.name for path in outside.iterdir()) == (
        ["external.txt"] if populated else []
    )
    if populated:
        assert (outside / "external.txt").read_text() == "outside contents\n"


@pytest.mark.parametrize(
    "link_kind",
    [
        pytest.param("absolute", marks=pytest.mark.cross_platform),
        pytest.param("relative", marks=pytest.mark.cross_platform),
        pytest.param(
            "junction",
            marks=[
                pytest.mark.native_windows,
                pytest.mark.skipif(os.name != "nt", reason="requires native Windows junctions"),
            ],
        ),
    ],
)
@pytest.mark.parametrize("nested", [False, True], ids=["direct", "nested"])
@pytest.mark.parametrize("unrelated_change", [False, True], ids=["reviewed", "unrelated"])
def test_reviewed_patch_does_not_copy_through_indexed_directory_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    link_kind: str,
    nested: bool,
    unrelated_change: bool,
) -> None:
    import workbench_db

    repository = tmp_path / "source" / "repository"
    repository.parent.mkdir()
    revision = initialize_git_repository(repository)
    source = repository / "component"
    link = source / ("linked/nested" if nested else "linked")
    link.mkdir(parents=True)
    (link / "file.txt").write_text("indexed child\n")
    (source / "app.txt").write_text("before\n")
    subprocess.run(["git", "add", "component"], cwd=repository, check=True)
    shutil.rmtree(link)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file.txt").write_text("original outside contents\n")
    if link_kind == "junction":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], check=True)
    else:
        link_target = (
            "../" * (4 if nested else 3) + "outside" if link_kind == "relative" else str(outside)
        )
        link.symlink_to(link_target, target_is_directory=True)
    original_link = os.readlink(link)

    staging = tmp_path / "staging"
    sentinel = staging / "outside"
    sentinel.mkdir(parents=True)
    (sentinel / "file.txt").write_text("staged outside sentinel\n")
    # A relative link resolves to this different directory after materialization.
    monkeypatch.setattr(workbench_db.tempfile, "tempdir", str(staging))
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    patch = b"diff --git a/app.txt b/app.txt\n--- a/app.txt\n+++ b/app.txt\n@@ -1 +1 @@\n-before\n+after\n"
    (scan_dir / "reviewed.patch").write_bytes(patch)
    scan = {
        "target_path": str(source),
        "target_inode": source.stat().st_ino,
        "target_revision": revision,
        "scan_dir": str(scan_dir),
    }
    remediation = {
        "base_revision": revision,
        "base_content_digest": workbench_db.worktree_content_digest(source),
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
    }
    (source / "app.txt").write_text("after\n")
    if unrelated_change:
        (source / "unrelated.txt").write_text("outside the reviewed patch\n")
        with pytest.raises(SystemExit, match="changes outside the reviewed patch"):
            workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")
    else:
        assert workbench_db.require_reviewed_patch_applied(
            scan, remediation, "reviewed.patch"
        ) == workbench_db.worktree_content_digest(source)
    assert (outside / "file.txt").read_text() == "original outside contents\n"
    assert (sentinel / "file.txt").read_text() == "staged outside sentinel\n"
    assert (source / "app.txt").read_text() == "after\n"
    assert os.readlink(link) == original_link
    assert list(staging.iterdir()) == [sentinel]


@pytest.mark.parametrize(
    "case",
    [
        "ordering",
        "ignore_add",
        "ignore_remove",
        "git_metadata",
        "git_metadata_crlf",
        "git_metadata_lf",
        "git_objects",
    ],
)
def test_reviewed_patch_restores_junction_git_context(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    case: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    initialize_unborn_git_repository(source)
    newline = None
    if case in {"git_metadata_crlf", "git_metadata_lf"}:
        global_config = tmp_path / "global.gitconfig"
        global_config.write_text("[core]\n\tautocrlf = false\n")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
        monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
        subprocess.run(["git", "config", "core.autocrlf", "true"], cwd=source, check=True)
        newline = "\r\n" if case == "git_metadata_crlf" else "\n"
    (source / "src").mkdir()
    (source / "src" / "app.txt").write_text("stable contents\n")
    (source / "src.py").write_text("adjacent contents\n")
    (source / "Alpha.txt").write_text("mixed case ordering\n")
    (source / ".gitignore").write_text("cache/\n")
    (source / "cache").mkdir()
    (source / "cache" / "output.txt").write_text("ignored output\n")
    outside = tmp_path / "outside"
    if case.startswith("git_metadata") or case == "git_objects":
        junction = source / (".git" if case.startswith("git_metadata") else ".git/objects")
        junction.rename(outside)
    else:
        outside.mkdir()
        (outside / "file.txt").write_text("external contents\n")
        junction = source / "linked"
    junction_factory(junction, outside)
    patched = ".gitignore" if case.startswith("ignore_") else "app.txt"
    before = (
        "# fixture\nlinked/\n"
        if case == "ignore_remove"
        else "# fixture\n"
        if case == "ignore_add"
        else "before\n"
    )
    after = (
        "# fixture\nlinked/\n"
        if case == "ignore_add"
        else "# fixture\n"
        if case == "ignore_remove"
        else "after\n"
    )
    metadata = (outside / "config").read_bytes() if case.startswith("git_metadata") else None
    assert_reviewed_change(source, tmp_path, patched, before, after, newline=newline)
    assert outside.is_dir()
    if metadata is not None:
        assert (outside / "config").read_bytes() == metadata
    if newline is not None:
        assert (source / patched).read_bytes() == after.replace("\n", newline).encode()


@pytest.mark.cross_platform
def test_reviewed_patch_preserves_scoped_unborn_lf_bytes(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    initialize_unborn_git_repository(repository)
    attributes = tmp_path / "attributes"
    attributes.write_text("*.txt text eol=crlf\n")
    subprocess.run(
        ["git", "config", "core.attributesFile", str(attributes)], cwd=repository, check=True
    )
    source = repository / "component"
    source.mkdir()

    assert_reviewed_change(source, tmp_path, "app.txt", "before\n", "after\n", newline="\n")

    assert (source / "app.txt").read_bytes() == b"after\n"


def assert_reviewed_change(
    source: Path,
    tmp_path: Path,
    relative: str,
    before: str,
    after: str,
    *,
    newline: str | None = None,
    revision: str = "unversioned",
) -> None:
    import workbench_db

    patch = (
        f"diff --git a/{relative} b/{relative}\n"
        + "".join(
            difflib.unified_diff(
                before.splitlines(True),
                after.splitlines(True),
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
            )
        )
    ).encode()
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    (scan_dir / "reviewed.patch").write_bytes(patch)
    scan = {
        "target_path": str(source),
        "target_inode": source.stat().st_ino,
        "target_revision": revision,
        "scan_dir": str(scan_dir),
    }
    (source / relative).write_text(before, newline=newline)
    revision, digest = workbench_db.remediation_checkout_snapshot(scan)
    remediation = {
        "base_revision": revision,
        "base_content_digest": digest,
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
    }
    (source / relative).write_text(after, newline=newline)
    assert workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires native Windows path casing")
def test_native_reviewed_patch_preserves_indexed_junction_spelling(tmp_path: Path) -> None:
    source = tmp_path / "source"
    initialize_unborn_git_repository(source)
    subprocess.run(["git", "config", "core.ignorecase", "true"], cwd=source, check=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file.txt").write_text("external contents\n")
    junction = source / "linked"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(outside)], check=True)
    (source / "app.txt").write_text("before\n")
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    junction.rename(source / "Linked")
    assert_reviewed_change(source, tmp_path, "app.txt", "before\n", "after\n")


def test_indexed_junction_case_aliases_keep_snapshot_identity(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import workbench_target

    source = tmp_path / "source"
    initialize_unborn_git_repository(source)
    subprocess.run(["git", "config", "core.ignorecase", "true"], cwd=source, check=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file.txt").write_text("external contents\n")
    junction = source / "linked"
    junction_factory(junction, outside)
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    metadata = junction.lstat()
    renamed = junction.rename(source / "Linked")
    if not getattr(renamed.lstat(), "st_reparse_tag", 0):
        # Supply case aliases for the emulated junction on a case-sensitive volume.
        real_lstat = Path.lstat
        real_readlink = os.readlink
        monkeypatch.setattr(
            Path,
            "lstat",
            lambda path: metadata if path in (junction, renamed) else real_lstat(path),
        )
        monkeypatch.setattr(
            os,
            "readlink",
            lambda path: str(outside) if Path(path) in (junction, renamed) else real_readlink(path),
        )
    before = workbench_target.directory_content_digest(source)

    (renamed / "new.txt").write_text("new external contents\n")
    assert workbench_target.directory_content_digest(source) == before
    (renamed / "file.txt").unlink()
    (renamed / "new.txt").unlink()
    assert workbench_target.directory_content_digest(source) == before


def test_reverse_patch_cannot_write_through_junction(
    tmp_path: Path, junction_factory: Callable[[Path, Path], None]
) -> None:
    import workbench_db

    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("outside contents\n")
    junction = source / "linked"
    junction_factory(junction, outside)
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    patch = b"diff --git a/linked/deleted.txt b/linked/deleted.txt\ndeleted file mode 100644\n--- a/linked/deleted.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-removed\n"
    (scan_dir / "reviewed.patch").write_bytes(patch)
    scan = {
        "target_path": str(source),
        "target_inode": source.stat().st_ino,
        "target_revision": "unversioned",
        "scan_dir": str(scan_dir),
    }
    remediation = {
        "base_revision": "unversioned",
        "base_content_digest": "different base",
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
    }
    with pytest.raises(OSError):
        workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")
    assert sorted(path.name for path in outside.iterdir()) == ["keep.txt"]
    assert (outside / "keep.txt").read_text() == "outside contents\n"


def test_reverse_patch_cannot_redirect_junction_restoration(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import workbench_db

    source = tmp_path / "source"
    (source / "dep").mkdir(parents=True)
    original_target = tmp_path / "original"
    original_target.mkdir()
    (original_target / "keep.txt").write_text("original contents\n")
    junction = source / "dep" / "linked"
    junction_factory(junction, original_target)
    os.chmod(junction, stat.S_IREAD | stat.S_IEXEC)
    outside = tmp_path / "outside"
    external = outside / "linked"
    external.mkdir(parents=True)
    original_mode = external.stat().st_mode
    config = tmp_path / "gitconfig"
    config.write_text("[core]\n\tsymlinks = true\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    patch = f"""diff --git a/app.txt b/app.txt
--- a/app.txt
+++ b/app.txt
@@ -1 +1 @@
-before
+after
diff --git a/dep b/dep
deleted file mode 120000
--- a/dep
+++ /dev/null
@@ -1 +0,0 @@
-{outside.as_posix()}
\\ No newline at end of file
diff --git a/dep/linked b/dep/linked
new file mode 160000
index {"0" * 40}..{"1" * 40}
--- /dev/null
+++ b/dep/linked
@@ -0,0 +1 @@
+Subproject commit {"1" * 40}
""".encode()
    (scan_dir / "reviewed.patch").write_bytes(patch)
    scan = {
        "target_path": str(source),
        "target_inode": source.stat().st_ino,
        "target_revision": "unversioned",
        "scan_dir": str(scan_dir),
    }
    (source / "app.txt").write_text("before\n")
    remediation = {
        "base_revision": "unversioned",
        "base_content_digest": workbench_db.directory_content_digest(source),
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
    }
    (source / "app.txt").write_text("after\n")
    try:
        with pytest.raises(SystemExit, match="checkout path was replaced"):
            workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")
        assert external.lstat().st_mode == original_mode
        assert not getattr(external.lstat(), "st_reparse_tag", 0)
        assert list(external.iterdir()) == []
        assert (original_target / "keep.txt").read_text() == "original contents\n"
    finally:
        os.chmod(junction, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)


def initialize_unborn_git_repository(target: Path) -> None:
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)


@pytest.mark.parametrize("git", [False, True])
def test_directory_snapshots_exclude_svn_metadata(tmp_path: Path, git: bool) -> None:
    target = tmp_path / "target"
    if git:
        initialize_unborn_git_repository(target)
    else:
        target.mkdir()
    source = target / "app.py"
    source.write_text("source\n")
    metadata = [target / ".svn" / "wc.db", target / "nested" / ".svn" / "pristine" / "base"]
    for path in metadata:
        path.parent.mkdir(parents=True)
        path.write_text("metadata\n")
    if git:
        subprocess.run(["git", "add", "--force", "."], cwd=target, check=True)

    original = directory_content_digest(target)
    count_files = WORKBENCH_TARGET["directory_snapshot_regular_file_count"]
    assert count_files(target) == 1
    for path in metadata:
        path.write_text("metadata changed\n")
    assert directory_content_digest(target) == original
    assert count_files(target) == 1
    source.write_text("source changed\n")
    assert directory_content_digest(target) != original


@pytest.mark.parametrize("tracked", [False, True])
@pytest.mark.parametrize("scope", [".", "nested[scope]"])
def test_worktree_snapshots_exclude_svn_metadata(tmp_path: Path, tracked: bool, scope: str) -> None:
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    target = repository / scope
    target.mkdir(exist_ok=True)
    source = target / ".svn-backup" / "app.py"
    source.parent.mkdir()
    source.write_text("source\n")
    metadata = [target / ".svn" / "wc.db", target / "nested" / ".svn" / "entries"]
    for path in metadata:
        path.parent.mkdir(parents=True)
        path.write_text("metadata\n")
    subprocess.run(["git", "add", str(source)], cwd=repository, check=True)
    if tracked:
        subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "Synthetic source and metadata"], cwd=repository, check=True
    )

    original = worktree_content_digest(target)
    for path in metadata:
        path.write_text("updated metadata\n")
    assert worktree_content_digest(target) == original
    source.write_text("updated source\n")
    assert worktree_content_digest(target) != original


@pytest.mark.parametrize("scope", [".svn", "nested/.svn"])
def test_git_directory_snapshots_exclude_svn_junctions(
    tmp_path: Path, junction_factory: Callable[[Path, Path], None], scope: str
) -> None:
    import workbench_target

    target = tmp_path / "target"
    initialize_unborn_git_repository(target)
    source = target / "app.py"
    source.write_text("source\n")
    metadata = target / scope
    metadata.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "state").write_text("metadata\n")
    junction_factory(metadata / "linked", outside)

    assert workbench_target.git_directory_snapshot_paths(target) == [source]


def test_windows_inventory_batches_wide_untracked_trees(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import workbench_target

    target = tmp_path / "target"
    initialize_unborn_git_repository(target)
    monkeypatch.setattr(workbench_target, "_WINDOWS", True)
    run_git = workbench_target.git_command
    calls = 0

    def counted_git(*args: Any, **kwargs: Any):
        nonlocal calls
        calls += 1
        return run_git(*args, **kwargs)

    monkeypatch.setattr(workbench_target, "git_command", counted_git)
    sources = []
    for index in range(16):
        source = target / f"component-{index}" / "src" / "app.py"
        source.parent.mkdir(parents=True)
        source.write_text("print('fixture')\n")
        sources.append(source)
        if index == 0:
            assert workbench_target.git_directory_snapshot_paths(target) == sources
            single_directory_calls = calls
            calls = 0

    assert set(workbench_target.git_directory_snapshot_paths(target)) == set(sources)
    assert calls == single_directory_calls


@pytest.mark.parametrize("change", ["unchanged", "ignored_file", "unrelated_file"])
def test_reviewed_patch_preserves_unborn_git_inventory(tmp_path: Path, change: str) -> None:
    import workbench_db

    source = tmp_path / "source"
    initialize_unborn_git_repository(source)
    (source / "src").mkdir()
    app = source / "src" / "app.txt"
    app.write_text("before\n")
    (source / ".gitignore").write_text("ignored-cache/\n")
    cache = source / "ignored-cache"
    cache.mkdir()
    cached_file = cache / "output.txt"
    cached_file.write_text("ignored build output\n")
    subprocess.run(["git", "add", ".gitignore", "src/app.txt"], cwd=source, check=True)
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    patch = (
        b"diff --git a/src/app.txt b/src/app.txt\n"
        b"--- a/src/app.txt\n+++ b/src/app.txt\n@@ -1 +1 @@\n-before\n+after\n"
    )
    (scan_dir / "reviewed.patch").write_bytes(patch)
    scan = {
        "target_path": str(source),
        "target_inode": source.stat().st_ino,
        "target_revision": "unversioned",
        "scan_dir": str(scan_dir),
    }
    revision, digest = workbench_db.remediation_checkout_snapshot(scan)
    assert revision == "unversioned"
    remediation = {
        "base_revision": revision,
        "base_content_digest": digest,
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
    }
    app.write_text("after\n")
    if change == "ignored_file":
        cached_file.write_text("updated ignored build output\n")
    elif change == "unrelated_file":
        (source / "unrelated.txt").write_text("outside the reviewed patch\n")
    if change == "unrelated_file":
        with pytest.raises(SystemExit, match="changes outside the reviewed patch"):
            workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")
    else:
        assert workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")


def add_submodule_gitlink(repository: Path, revision: str, scope: str) -> None:
    subprocess.run(
        [
            "git",
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{revision},{(Path(scope) / 'submodule').as_posix()}",
        ],
        cwd=repository,
        check=True,
    )


def set_default_subprocess_encoding(monkeypatch: pytest.MonkeyPatch, encoding: str) -> None:
    run = subprocess.run

    def run_with_default_encoding(*args: Any, **kwargs: Any):
        if kwargs.get("text") and kwargs.get("encoding") is None:
            kwargs["encoding"] = encoding
        return run(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", run_with_default_encoding)


def test_stale_git_binding_does_not_spawn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CODEX_SECURITY_GIT", str(tmp_path / "missing-git"))

    def unexpected_spawn(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("stale Git binding reached subprocess.run")

    monkeypatch.setattr(subprocess, "run", unexpected_spawn)
    result = WORKBENCH_TARGET["git_command"](tmp_path, "status", text=True)
    assert result.returncode == 127
    assert result.stdout == ""
    assert result.args[0] == "git"


@pytest.mark.parametrize(
    ("encoding", "bom"),
    [("utf-8", b""), ("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")],
)
@pytest.mark.parametrize("retain_samples", [True, False])
def test_git_blob_samples_match_full_file_classification_with_bounded_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    encoding: str,
    bom: bytes,
    retain_samples: bool,
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    # The UTF-16 surrogate pair crosses the first 64 KiB sample boundary.
    text = bom + ("a" * 32766 + "😀" + "b" * 32768).encode(encoding)
    contents = {
        "text.bin": text + (b"\0" if bom else b""),
        "binary-tail.bin": text + "\0".encode(encoding),
        "binary-head.bin": b"\0" + text * 32,
        "empty.bin": b"",
        "after.txt": b"after\n",
    }
    for name, content in contents.items():
        (target / name).write_bytes(content)
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "source samples"], cwd=target, check=True)

    git_blob_samples = WORKBENCH_TARGET["git_blob_samples"]
    function_globals = git_blob_samples.__globals__
    read_batch_samples = function_globals["_read_git_batch_samples"]
    reads: list[int] = []

    def require_bounded_output(output: Any, names: list[str], *, retain_samples: bool):
        assert not output.seekable()
        read = output.read

        def bounded_read(size: int = -1) -> bytes:
            assert 0 <= size <= 64 * 1024
            reads.append(size)
            return read(size)

        output.read = bounded_read
        return read_batch_samples(output, names, retain_samples=retain_samples)

    monkeypatch.setitem(function_globals, "_read_git_batch_samples", require_bounded_output)
    # Both request and response exceed pipe buffers, before the multi-megabyte binary.
    missing = ["HEAD:missing"] * 10_000
    samples = git_blob_samples(
        target,
        [*missing, *(f"HEAD:{name}" for name in contents)],
        retain_samples=retain_samples,
    )

    assert samples == [
        *([None] * len(missing)),
        (text[: 64 * 1024] if retain_samples else b"", False),
        (b"", True),
        (b"", True),
        (b"", False),
        (b"after\n" if retain_samples else b"", False),
    ]
    assert max(reads) == 64 * 1024


@pytest.mark.parametrize("binary_chunk", [0, 1, None])
def test_local_source_classification_stops_after_binary_chunk(binary_chunk: int | None) -> None:
    import io

    chunks = [b"a" * (64 * 1024) for _ in range(4)]
    if binary_chunk is not None:
        chunks[binary_chunk] = b"\0" + chunks[binary_chunk][1:]
    data = b"".join(chunks)
    source = io.BytesIO(data)

    _, binary = WORKBENCH_TARGET["_read_source_sample"](source, len(data), drain=False)

    assert binary == (binary_chunk is not None)
    assert source.tell() == (len(data) if binary_chunk is None else (binary_chunk + 1) * 64 * 1024)


@pytest.mark.parametrize(
    "output",
    [
        b"missing terminator",
        b"object blob invalid\n",
        b"object blob -1\n",
        b"object blob 4\nabc",
        b"object blob 4\nabcd!",
        b"object blob invalid\n" + b"x" * (4 * 1024 * 1024),
        b"object blob 131072\n" + b"x" * (64 * 1024 + 1),
    ],
    ids=[
        "unterminated-header",
        "invalid-size",
        "negative-size",
        "short-body",
        "invalid-terminator",
        "large-invalid-header",
        "truncated-large-body",
    ],
)
def test_git_blob_samples_reject_incomplete_framing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: bytes
) -> None:
    git_blob_samples = WORKBENCH_TARGET["git_blob_samples"]

    def git_command(*args: Any, **kwargs: Any):
        remaining = memoryview(output)
        try:
            while remaining:
                written = os.write(kwargs["stdout_file"].fileno(), remaining)
                remaining = remaining[written:]
        except BrokenPipeError:
            return subprocess.CompletedProcess(args, 1)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setitem(git_blob_samples.__globals__, "git_command", git_command)

    assert git_blob_samples(tmp_path, ["HEAD:source"]) == [None]


@pytest.mark.parametrize("output", [b"", b"object blob 4\ntext\n"])
def test_git_blob_samples_reject_git_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: bytes
) -> None:
    git_blob_samples = WORKBENCH_TARGET["git_blob_samples"]

    def git_command(*args: Any, **kwargs: Any):
        kwargs["stdout_file"].write(output)
        return subprocess.CompletedProcess(args, 1)

    monkeypatch.setitem(git_blob_samples.__globals__, "git_command", git_command)

    assert git_blob_samples(tmp_path, ["HEAD:source"]) == [None]


def test_diff_count_preserves_git_batch_failure_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import workbench_target

    target = tmp_path / "target"
    initialize_git_repository(target)
    before = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    (target / "a-good.py").write_text("good\n")
    (target / "z-broken.py").write_text("broken\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "changed sources"], cwd=target, check=True)
    command = workbench_target.git_command

    def fail_batch(*args: Any, **kwargs: Any):
        if "cat-file" in args:
            kwargs["stdout_file"].write(b"object blob 5\ngood\n\n")
            return subprocess.CompletedProcess(args, 128, stderr=b"fatal: cannot read fixture blob")
        return command(*args, **kwargs)

    monkeypatch.setattr(workbench_target, "git_command", fail_batch)
    diff_target = {"kind": "range", "baseRevision": before, "headRevision": "HEAD"}
    with pytest.raises(SystemExit, match="fatal: cannot read fixture blob"):
        workbench_target.diff_scope_file_count(target, diff_target)


def test_diff_count_preserves_corrupt_blob_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import workbench_target

    monkeypatch.setenv("LC_ALL", "C")
    target = tmp_path / "target"
    before = initialize_git_repository(target)
    (target / "source.py").write_text("changed\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "changed source"], cwd=target, check=True)
    blob = subprocess.check_output(
        ["git", "rev-parse", "HEAD:source.py"], cwd=target, text=True
    ).strip()
    object_path = target / ".git" / "objects" / blob[:2] / blob[2:]
    object_path.unlink()
    object_path.write_bytes(b"")
    diff_target = {"kind": "range", "baseRevision": before, "headRevision": "HEAD"}
    with pytest.raises(SystemExit, match="(?s)object file.*is empty"):
        workbench_target.diff_scope_file_count(target, diff_target)


@pytest.mark.cross_platform
def test_local_diff_count_keeps_uppercase_metadata_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import workbench_target

    target = tmp_path / "target"
    initialize_git_repository(target)
    source = target / ".SVN" / "source.py"
    source.parent.mkdir()
    source.write_text("before\n")
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "uppercase directory"], cwd=target, check=True)
    source.write_text("after\n")
    monkeypatch.setenv("GIT_ICASE_PATHSPECS", "1")
    diff_target = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    assert workbench_target.diff_scope_file_count(target, diff_target) == 1


def test_git_blob_samples_work_with_git_before_2_38(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    git_blob_samples = WORKBENCH_TARGET["git_blob_samples"]
    git_command = git_blob_samples.__globals__["git_command"]

    def git_before_2_38(*args: Any, **kwargs: Any):
        # Git before 2.38 rejects cat-file -z with a usage error.
        if "-z" in args:
            return subprocess.CompletedProcess(args, 129)
        return git_command(*args, **kwargs)

    monkeypatch.setitem(git_blob_samples.__globals__, "git_command", git_before_2_38)

    assert git_blob_samples(target, ["HEAD:README.md", "HEAD:missing"]) == [
        (b"fixture\n", False),
        None,
    ]


@pytest.mark.parametrize(
    ("log_encoding", "subject"),
    [
        ("UTF-8", "docs: \u65e5\u672c\u8a9e \ud55c\uad6d\uc5b4 \U0001f527"),
        ("ISO-8859-1", "docs: caf\u00e9"),
    ],
)
@pytest.mark.parametrize("encoding", ["cp932", "cp949"])
def test_git_metadata_preserves_unicode_commit_subject(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    encoding: str,
    log_encoding: str,
    subject: str,
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    subprocess.run(["git", "commit", "--allow-empty", "-qm", subject], cwd=target, check=True)
    subprocess.run(
        ["git", "config", "i18n.logOutputEncoding", log_encoding], cwd=target, check=True
    )
    set_default_subprocess_encoding(monkeypatch, encoding)

    assert WORKBENCH_TARGET["git_target_metadata"](target)["commitSubject"] == subject
    assert WORKBENCH_TARGET["git_bytes"](
        target, "show", "-s", "--format=%s", "HEAD"
    ) == f"{subject}\n".encode("utf-8")


@pytest.mark.cross_platform
def test_git_metadata_ignores_signature_output_in_commit_subject(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    headers = subprocess.check_output(["git", "cat-file", "commit", "HEAD"], cwd=target).split(
        b"\n\n", 1
    )[0]
    # A synthetic signature reproduces Git's extra output without a signing tool.
    commit = headers + (
        b"\ngpgsig -----BEGIN SSH SIGNATURE-----\n synthetic\n -----END SSH SIGNATURE-----"
        b"\n\nSigned subject\n"
    )
    revision = (
        subprocess.check_output(
            ["git", "hash-object", "-t", "commit", "-w", "--stdin"], cwd=target, input=commit
        )
        .decode()
        .strip()
    )
    subprocess.run(["git", "update-ref", "HEAD", revision], cwd=target, check=True)
    subprocess.run(["git", "config", "log.showSignature", "true"], cwd=target, check=True)

    assert WORKBENCH_TARGET["git_target_metadata"](target)["commitSubject"] == "Signed subject"


@pytest.mark.parametrize("encoding", ["cp932", "cp949"])
def test_git_output_decodes_repository_paths_as_utf8(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, encoding: str
) -> None:
    target = tmp_path / "Jos\u00e9-\u65e5\u672c\u8a9e-\ud55c\uad6d\uc5b4"
    initialize_git_repository(target)
    set_default_subprocess_encoding(monkeypatch, encoding)

    output = WORKBENCH_TARGET["git_output"](target, "rev-parse", "--show-toplevel")
    assert Path(output) == target


@pytest.mark.parametrize("suffix", ["", " ", "\t", "\r", "\n"])
def test_git_worktree_preserves_path_whitespace(tmp_path: Path, suffix: str) -> None:
    if os.name == "nt" and suffix:
        pytest.skip("Windows does not support these trailing path characters")
    target = tmp_path / f"target{suffix}"
    revision = initialize_git_repository(target)
    nested = target / "src"
    nested.mkdir()

    assert WORKBENCH_TARGET["git_worktree_context"](target) == (target.resolve(), ".")
    assert WORKBENCH_TARGET["git_worktree_context"](nested) == (target.resolve(), "src")
    metadata = WORKBENCH_TARGET["git_target_metadata"](target)
    assert metadata["reviewChangesSupported"] is True
    assert metadata["revision"] == revision
    assert metadata["branch"] == "main"

    original_digest = worktree_content_digest(target)
    (target / "README.md").write_text("changed after commit\n")
    assert worktree_content_digest(target) != original_digest


@pytest.mark.parametrize(
    ("platform", "stdout", "expected"),
    [
        ("linux", b"/repo\r\n", "/repo\r"),
        ("linux", b"/repo\n\n", "/repo\n"),
        ("win32", b"C:/repo\r\n", "C:/repo"),
        ("win32", b"C:/repo\n", "C:/repo"),
    ],
)
def test_git_output_removes_only_the_record_terminator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    stdout: bytes,
    expected: str,
) -> None:
    git_output = WORKBENCH_TARGET["git_output"]
    monkeypatch.setitem(git_output.__globals__, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setitem(
        git_output.__globals__,
        "git_command",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=stdout),
    )

    assert git_output(tmp_path, "rev-parse", "--show-toplevel") == expected


@pytest.mark.cross_platform
@pytest.mark.parametrize("noglob", ["0", "1"])
def test_windows_directory_query_preserves_exclusions_with_inherited_noglob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, noglob: str
) -> None:
    import workbench_target

    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    (repository / ".gitignore").write_text("locally-ignored/\n")
    excludes = tmp_path / "global-excludes"
    excludes.write_text("globally-ignored/\n")
    for directory in ["src", "locally-ignored", "globally-ignored"]:
        source = repository / "pkg" / directory
        source.mkdir(parents=True)
        (source / "app.py").write_text("source fixture\n")
    monkeypatch.setattr(workbench_target, "_WINDOWS", True)
    monkeypatch.setenv("GIT_NOGLOB_PATHSPECS", noglob)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.excludesFile")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(excludes))
    environment = os.environ.copy()

    paths = workbench_target.git_directory_snapshot_paths(repository)

    assert paths is not None
    assert {path.relative_to(repository).as_posix() for path in paths} == {
        ".gitignore",
        "README.md",
        "pkg/src/app.py",
    }
    assert dict(os.environ) == environment


def test_directory_content_digest_uses_git_file_set(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_unborn_git_repository(target)
    (target / ".gitignore").write_text("ignored-cache/\n")
    source = target / "app.py"
    source.write_text("print('fixture')\n")
    original_digest = directory_content_digest(target)

    source.write_text("print('changed')\n")
    assert directory_content_digest(target) != original_digest

    source.write_text("print('fixture')\n")
    (target / ".git" / "runtime-cache").write_text("runtime metadata\n")
    ignored_cache = target / "ignored-cache"
    ignored_cache.mkdir()
    (ignored_cache / "build-output").write_text("ignored runtime data\n")

    assert directory_content_digest(target) == original_digest


@pytest.mark.parametrize("scope", [".", "component"])
def test_directory_snapshot_preserves_target_alias_spelling(tmp_path: Path, scope: str) -> None:
    target = tmp_path / "target"
    initialize_unborn_git_repository(target)
    (target / "component").mkdir()
    (target / "component" / "app.py").write_text("print('fixture')\n")
    (target / "root.py").write_text("print('root')\n")
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    scoped = target / scope
    selected = alias / scope
    expected = [
        selected / path.relative_to(scoped)
        for path in WORKBENCH_TARGET["git_directory_snapshot_paths"](scoped)
    ]

    paths = WORKBENCH_TARGET["git_directory_snapshot_paths"](selected)
    assert [str(path) for path in paths] == [str(path) for path in expected]
    original_digest = directory_content_digest(selected)
    assert original_digest == directory_content_digest(scoped)
    (selected / "changed.py").write_text("print('changed')\n")
    assert directory_content_digest(selected) == directory_content_digest(scoped)
    assert directory_content_digest(selected) != original_digest


@pytest.mark.parametrize("scope", [".", "component"])
@pytest.mark.parametrize("alias_kind", ["symlink", CASE_ALIAS])
def test_submodule_checks_preserve_target_alias_spelling(
    tmp_path: Path, scope: str, alias_kind: str
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    scoped = target / scope
    scoped.mkdir(exist_ok=True)
    submodule = scoped / "submodule"
    revision = initialize_git_repository(submodule)
    add_submodule_gitlink(target, revision, scope)
    alias = tmp_path / ("alias" if alias_kind == "symlink" else "TARGET")
    if alias_kind == "symlink":
        alias.symlink_to(target, target_is_directory=True)
    elif not alias.exists():
        pytest.skip("filesystem does not support case aliases")
    selected = alias / scope
    entries = WORKBENCH_TARGET["git_submodule_entries"](selected)
    assert entries == ((selected / "submodule", revision),)
    WORKBENCH_TARGET["require_clean_submodule_worktrees"](selected)
    (submodule / "README.md").write_text("changed after commit\n")
    with pytest.raises(SystemExit, match="Dirty Git submodules.*submodule"):
        WORKBENCH_TARGET["require_clean_submodule_worktrees"](selected)


@pytest.mark.parametrize("content_digest", [directory_content_digest, worktree_content_digest])
@pytest.mark.parametrize("alias_kind", ["original", "symlink", CASE_ALIAS])
def test_content_digest_expands_nested_git_repositories(
    tmp_path: Path, content_digest: Callable[[Path], str], alias_kind: str
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    nested = target / "nested"
    initialize_git_repository(nested)
    (nested / ".gitignore").write_text("ignored-cache/\n")
    nested_source = nested / "app.py"
    nested_source.write_text("print('fixture')\n")
    ignored_cache = nested / "ignored-cache"
    ignored_cache.mkdir()
    ignored_output = ignored_cache / "build-output"
    ignored_output.write_text("ignored runtime data\n")
    selected = target
    if alias_kind != "original":
        selected = tmp_path / ("alias" if alias_kind == "symlink" else "TARGET")
        if alias_kind == "symlink":
            selected.symlink_to(target, target_is_directory=True)
        elif not selected.exists():
            pytest.skip("filesystem does not support case aliases")
    original_digest = content_digest(selected)

    nested_source.write_text("print('changed')\n")
    assert content_digest(selected) != original_digest

    nested_source.write_text("print('fixture')\n")
    (nested / "README.md").write_text("changed after commit\n")
    assert content_digest(selected) != original_digest

    (nested / "README.md").write_text("fixture\n")
    (nested / ".git" / "runtime-cache").write_text("runtime metadata\n")
    ignored_output.write_text("changed ignored runtime data\n")
    assert content_digest(selected) == original_digest


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX directory permissions")
@pytest.mark.parametrize("inventory", ["plain", "git", "git-junctions"])
def test_directory_inventory_skips_inaccessible_descendants(
    tmp_path: Path, inventory: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    if inventory != "plain":
        initialize_unborn_git_repository(target)
    else:
        target.mkdir()
    if inventory == "git-junctions":
        monkeypatch.setitem(directory_content_digest.__globals__, "_WINDOWS", True)
    source = target / "app.py"
    source.write_text("before\n")
    inaccessible = target / "unreadable"
    inaccessible.mkdir()
    (inaccessible / "private.txt").write_text("inaccessible fixture\n")
    inaccessible.chmod(0)
    try:
        if os.access(inaccessible, os.R_OK | os.X_OK):
            pytest.skip("directory permissions are not enforced for the current user")
        assert WORKBENCH_TARGET["directory_snapshot_regular_file_count"](target) == 1
        before = directory_content_digest(target)
        source.write_text("after\n")
        assert directory_content_digest(target) != before
    finally:
        inaccessible.chmod(0o700)


def test_directory_content_digest_skips_missing_cached_paths(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_unborn_git_repository(target)
    original_digest = directory_content_digest(target)
    cached_source = target / "cached.py"
    cached_source.write_text("print('cached')\n")
    subprocess.run(["git", "add", cached_source.name], cwd=target, check=True)
    cached_source.unlink()

    assert directory_content_digest(target) == original_digest


def test_worktree_content_digest_streams_tracked_binary_patch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    binary = target / "fixture.bin"
    # Incompressible fixture bytes keep the binary patch larger than one hash read.
    fixture_size = 1024 * 1024 + 17
    binary.write_bytes(hashlib.shake_256(b"original binary fixture").digest(fixture_size))
    subprocess.run(["git", "add", binary.name], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "Add binary fixture"], cwd=target, check=True)
    binary.write_bytes(hashlib.shake_256(b"changed binary fixture").digest(fixture_size))

    tracked = subprocess.run(
        [
            "git",
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            "HEAD",
            "--",
            ".",
        ],
        cwd=target,
        check=True,
        capture_output=True,
    ).stdout
    assert b"GIT binary patch" in tracked
    assert len(tracked) > 1024 * 1024
    expected = hashlib.sha256()
    update_digest_field(expected, b"format", b"codex-security-snapshot/v1")
    update_digest_field(expected, b"tracked-diff", tracked)

    function_globals = cast(dict[str, Any], cast(Any, worktree_content_digest).__globals__)
    git_command = cast(
        Callable[..., subprocess.CompletedProcess[Any]], function_globals["git_command"]
    )

    def require_streamed_diff(
        repository: Path, *args: str, **kwargs: object
    ) -> subprocess.CompletedProcess[Any]:
        if "diff" in args:
            assert kwargs.get("stdout_file") is not None
        return git_command(repository, *args, **kwargs)

    monkeypatch.setitem(function_globals, "git_command", require_streamed_diff)

    assert worktree_content_digest(target) == (
        f"codex-security-snapshot/v1:sha256:{expected.hexdigest()}"
    )


def test_windows_git_candidates_reject_batch_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    (repository / ".git").mkdir(parents=True)
    native = tmp_path / "git.com"
    batch = tmp_path / "git.cmd"
    extensionless = tmp_path / "git-native"
    for candidate in (native, batch, extensionless):
        candidate.write_text("synthetic executable fixture\n")
    native_alias = tmp_path / "trusted.exe"
    batch_alias = tmp_path / "untrusted.exe"
    extensionless_alias = tmp_path / "native-alias.exe"
    native_alias.symlink_to(native)
    batch_alias.symlink_to(batch)
    extensionless_alias.symlink_to(extensionless)
    monkeypatch.setitem(
        trusted_git_executable.__globals__, "sys", SimpleNamespace(platform="win32")
    )
    for candidate, expected in (
        (native, native),
        (native_alias, native_alias),
        (batch, None),
        (batch_alias, None),
        (extensionless, None),
        (extensionless_alias, extensionless_alias),
    ):
        monkeypatch.setenv("CODEX_SECURITY_GIT", str(candidate))
        assert trusted_git_executable(repository) == (str(expected) if expected else None)


@pytest.mark.parametrize("windows", [False, True])
def test_git_discovery_continues_past_repository_tools_and_batch_shims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    repository = tmp_path / "repository"
    repository_bin = repository / "bin"
    repository_bin.mkdir(parents=True)
    (repository / ".git").mkdir()
    batch_bin = tmp_path / "batch-bin"
    host_bin = tmp_path / "host-bin"
    batch_bin.mkdir()
    host_bin.mkdir()
    name = "git.exe" if windows else "git"
    host_git = host_bin / name
    for executable in (repository_bin / name, batch_bin / "git.cmd", host_git):
        executable.write_text("synthetic executable fixture\n")
        executable.chmod(0o700)
    monkeypatch.setitem(
        trusted_git_executable.__globals__,
        "sys",
        SimpleNamespace(platform="win32" if windows else "linux"),
    )
    monkeypatch.delenv("CODEX_SECURITY_GIT", raising=False)
    monkeypatch.setenv("PATH", os.pathsep.join(map(str, (repository_bin, batch_bin, host_bin))))
    assert trusted_git_executable(repository) == str(host_git)

    # An explicit unavailable binding must not fall back to a different Git.
    for binding in ("", str(tmp_path / "missing-git")):
        monkeypatch.setenv("CODEX_SECURITY_GIT", binding)
        assert trusted_git_executable(repository) is None
    monkeypatch.setenv("CODEX_SECURITY_GIT", str(repository_bin / name))
    with pytest.raises(SystemExit, match="outside the protected repository"):
        trusted_git_executable(repository)


def test_git_discovery_does_not_invoke_through_repository_directory_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository_bin = repository / "bin"
    repository_bin.mkdir(parents=True)
    (repository / ".git").mkdir()
    host_bin = tmp_path / "host-bin"
    host_bin.mkdir()
    name = "git.exe" if os.name == "nt" else "git"
    host_git = host_bin / name
    host_git.write_text("synthetic host executable\n")
    host_git.chmod(0o700)
    (repository_bin / name).symlink_to(host_git)
    alias = tmp_path / "directory-alias"
    alias.symlink_to(repository_bin, target_is_directory=True)
    monkeypatch.delenv("CODEX_SECURITY_GIT", raising=False)
    monkeypatch.setenv("PATH", os.pathsep.join(map(str, (alias, host_bin))))
    assert trusted_git_executable(repository) == str(host_git)
    monkeypatch.setenv("CODEX_SECURITY_GIT", str(alias / name))
    with pytest.raises(SystemExit, match="outside the protected repository"):
        trusted_git_executable(repository)

    host_alias = repository / "host-alias"
    host_alias.symlink_to(host_bin, target_is_directory=True)
    monkeypatch.setenv("CODEX_SECURITY_GIT", str(host_alias / name))
    with pytest.raises(SystemExit, match="outside the protected repository"):
        trusted_git_executable(repository)


def test_git_discovery_preserves_symlink_parent_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    (repository / ".git").mkdir(parents=True)
    tools = tmp_path / "tools"
    version = tmp_path / "versions" / "v1"
    (tools / "bin").mkdir(parents=True)
    (version / "lib").mkdir(parents=True)
    (version / "bin").mkdir()
    (tools / "current").symlink_to(version / "lib", target_is_directory=True)
    name = "git.exe" if os.name == "nt" else "git"
    host_git = version / "bin" / name
    for executable in (tools / "bin" / name, host_git):
        executable.write_text("synthetic executable fixture\n")
        executable.chmod(0o700)
    path_entry = tools / "current" / ".." / "bin"
    monkeypatch.delenv("CODEX_SECURITY_GIT", raising=False)
    monkeypatch.setenv("PATH", str(path_entry))
    expected = (path_entry / name).resolve(strict=True)
    if os.name != "nt":
        assert expected == host_git
    assert trusted_git_executable(repository) == str(expected)


@pytest.mark.parametrize(
    "name",
    [
        "component with spaces",
        pytest.param(
            "component with spaces ",
            marks=pytest.mark.skipif(os.name == "nt", reason="Windows strips trailing spaces"),
        ),
    ],
)
def test_git_context_retains_scoped_directory_spelling(tmp_path: Path, name: str) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    scoped = target / name
    scoped.mkdir()
    repository, pathspec = WORKBENCH_TARGET["git_worktree_context"](scoped)
    assert repository.samefile(target)
    assert pathspec == scoped.name


@pytest.mark.native_macos
def test_git_target_accepts_filesystem_case_aliases(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    alias = tmp_path / "TARGET"
    if not alias.exists():
        pytest.skip("filesystem does not support case aliases")
    assert WORKBENCH_TARGET["git_target_metadata"](alias)["reviewChangesSupported"]
    repository, pathspec = WORKBENCH_TARGET["git_worktree_context"](alias)
    assert repository.samefile(target)
    assert pathspec == "."
    scoped = target / "component"
    scoped.mkdir()
    repository, pathspec = WORKBENCH_TARGET["git_worktree_context"](alias / "COMPONENT")
    assert repository.samefile(target)
    assert (repository / pathspec).samefile(scoped)


@pytest.mark.skipif(os.name == "nt", reason="Windows does not preserve trailing path whitespace")
@pytest.mark.parametrize("sibling_exists", [False, True])
def test_git_context_preserves_trailing_root_whitespace(
    tmp_path: Path, sibling_exists: bool
) -> None:
    target = tmp_path / "target "
    initialize_git_repository(target)
    if sibling_exists:
        initialize_git_repository(tmp_path / "target")
    assert WORKBENCH_TARGET["git_target_metadata"](target)["reviewChangesSupported"]
    repository, pathspec = WORKBENCH_TARGET["git_worktree_context"](target)
    assert repository.samefile(target)
    assert pathspec == "."
    original_digest = worktree_content_digest(target)
    (target / "synthetic.txt").write_text("selected target content\n")
    assert worktree_content_digest(target) != original_digest
    destination = tmp_path / "copied"
    WORKBENCH_TARGET["copy_git_worktree_files"](target, destination, ())
    assert (destination / "synthetic.txt").read_text() == "selected target content\n"


def test_git_context_rejects_an_unrelated_configured_worktree(tmp_path: Path) -> None:
    target = tmp_path / "target"
    unrelated = tmp_path / "unrelated"
    initialize_git_repository(target)
    unrelated.mkdir()
    subprocess.run(["git", "config", "core.worktree", str(unrelated)], cwd=target, check=True)
    with pytest.raises(SystemExit, match="inside its Git working tree"):
        WORKBENCH_TARGET["git_worktree_context"](target)
    with pytest.raises(SystemExit, match="inside its Git working tree"):
        worktree_content_digest(target)
    destination = tmp_path / "copied"
    with pytest.raises(SystemExit, match="inside its Git working tree"):
        WORKBENCH_TARGET["copy_git_worktree_files"](target, destination, ())
    assert not destination.exists()


@pytest.mark.parametrize("scope", [".", "component"])
@pytest.mark.parametrize("alias_kind", ["original", "symlink", CASE_ALIAS])
def test_copy_retains_alias_rooted_gitlink_exclusions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scope: str, alias_kind: str
) -> None:
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    scoped = repository / scope
    scoped.mkdir(exist_ok=True)
    (scoped / "fixture.py").write_text("synthetic = True\n")
    submodule = scoped / "submodule"
    submodule.mkdir()
    add_submodule_gitlink(repository, revision, scope)
    selected = scoped
    if alias_kind != "original":
        alias = tmp_path / ("selected-alias" if alias_kind == "symlink" else "REPOSITORY")
        if alias_kind == "symlink":
            alias.symlink_to(repository, target_is_directory=True)
        elif not alias.exists():
            pytest.skip("filesystem does not support case aliases")
        selected = alias / scope
    entries = WORKBENCH_TARGET["git_submodule_entries"](selected)
    WORKBENCH_TARGET["require_clean_submodule_worktrees"](selected)
    copy = WORKBENCH_TARGET["copy_git_worktree_files"]
    calls = []

    def checked_copy(
        source: Path, destination: Path, excluded: tuple[Path, ...]
    ) -> tuple[Path, list[Path]]:
        assert not source.samefile(submodule), "An excluded uninitialized gitlink was traversed"
        calls.append(source)
        return copy(source, destination, excluded)

    monkeypatch.setitem(copy.__globals__, "copy_git_worktree_files", checked_copy)
    selected_exclusions = tuple(path for path, _ in entries)
    for index, excluded in enumerate({selected_exclusions, (submodule,)}):
        calls.clear()
        copied, junctions = checked_copy(selected, tmp_path / f"copied-{index}", excluded)
        assert len(calls) == 1
        assert junctions == []
        assert (copied / "fixture.py").read_text() == "synthetic = True\n"
        assert not (copied / "submodule").exists()


@pytest.mark.cross_platform
def test_candidate_sources_disambiguate_revision_from_worktree_filename(tmp_path: Path) -> None:
    target = tmp_path / "repository"
    revision = initialize_git_repository(target)
    (target / revision).write_text("synthetic revision-named file\n")
    subprocess.run(["git", "rm", "-q", "README.md"], cwd=target, check=True)

    sources = WORKBENCH_TARGET["candidate_source_lines"](
        target,
        {"kind": "working_tree", "baseRevision": revision, "headRevision": revision},
        ["README.md"],
        ["README.md"],
    )

    assert sources == {"README.md": {"path": "README.md", "lineCount": 1}}


@pytest.mark.parametrize("replacement", ["directory", "ignored_file", "link"])
@pytest.mark.parametrize("case_insensitive", [False, True])
def test_deleted_candidate_sources_keep_base_blob_when_path_is_recreated(
    tmp_path: Path, replacement: str, case_insensitive: bool
) -> None:
    target = tmp_path / "repository"
    initialize_git_repository(target)
    source = target / "deleted.ts"
    source.write_bytes(b"one\rtwo\r\nthree\nfour")
    subprocess.run(["git", "add", "deleted.ts"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "selected source"], cwd=target, check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    subprocess.run(["git", "rm", "-q", "deleted.ts"], cwd=target, check=True)
    (target / ".git" / "info" / "exclude").write_text("deleted.ts\n")
    if replacement == "directory":
        source.mkdir()
    elif replacement == "ignored_file":
        source.write_text("replacement\n")
    else:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "private.txt").write_text("Synthetic unrelated content.\n")
        if os.name == "nt":
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(source), str(outside)],
                check=True,
                capture_output=True,
            )
        else:
            source.symlink_to(outside, target_is_directory=True)
    assert (
        dict(WORKBENCH_TARGET["git_changed_paths"](target, revision, revision, "local-patch"))[
            source
        ]
        == "D"
    )
    sources = WORKBENCH_TARGET["candidate_source_lines"](
        target,
        {"kind": "working_tree", "baseRevision": revision, "headRevision": revision},
        ["deleted.ts"],
        ["deleted.ts", "DELETED.TS"],
        case_insensitive=case_insensitive,
    )
    expected = {"deleted.ts": {"path": "deleted.ts", "lineCount": 4}}
    if case_insensitive:
        expected["DELETED.TS"] = expected["deleted.ts"]
    assert sources == expected


@pytest.mark.parametrize("case_insensitive", [False, True])
def test_candidate_aliases_use_selected_tree_and_preserve_ambiguity(
    tmp_path: Path, case_insensitive: bool
) -> None:
    target = tmp_path / "repository"
    initialize_git_repository(target)
    support = target / "Support.ts"
    support.write_text("support\nsecond\n")
    subprocess.run(["git", "add", "Support.ts"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "support source"], cwd=target, check=True)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    for name, mode, content in (
        ("Foo.ts", "100644", b"upper\n"),
        ("foo.ts", "100644", b"lower\nsecond\nthird\n"),
        ("folder/file.ts", "100644", b"nested\n"),
        ("link.ts", "120000", b"Support.ts"),
    ):
        blob = (
            subprocess.check_output(
                ["git", "hash-object", "-w", "--stdin"], cwd=target, input=content
            )
            .decode()
            .strip()
        )
        subprocess.run(
            ["git", "update-index", "--add", "--cacheinfo", f"{mode},{blob},{name}"],
            cwd=target,
            check=True,
        )
    subprocess.run(["git", "commit", "-qm", "selected tree"], cwd=target, check=True)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    support.unlink()
    subprocess.run(
        ["git", "update-index", "--force-remove", "Support.ts", "Foo.ts"], cwd=target, check=True
    )
    subprocess.run(["git", "commit", "-qm", "later tree"], cwd=target, check=True)
    (target / "foo.ts").write_text("different current content\n")
    requested = ["Foo.ts", "foo.ts", "FOO.ts", "SUPPORT.TS", "./SUPPORT.TS", "LINK.TS", "FOLDER"]
    sources = WORKBENCH_TARGET["candidate_source_lines"](
        target,
        {"kind": "range", "baseRevision": base, "headRevision": head},
        ["Foo.ts", "foo.ts"],
        requested,
        case_insensitive=case_insensitive,
    )
    assert sources["Foo.ts"] == {"path": "Foo.ts", "lineCount": 1}
    assert sources["foo.ts"] == {"path": "foo.ts", "lineCount": 3}
    assert sources["FOO.ts"] == {"error": "missing"}
    for name in ("SUPPORT.TS", "./SUPPORT.TS"):
        assert sources[name] == (
            {"path": "Support.ts", "lineCount": 2} if case_insensitive else {"error": "missing"}
        )
    for name in ("LINK.TS", "FOLDER"):
        assert sources[name] == {"error": "not_file" if case_insensitive else "missing"}


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    "view",
    [
        "default",
        "uppercase",
        "chain",
        "custom",
        "missing_original",
        "disabled",
        "disabled_empty",
        "core_false",
        "core_inline_false",
        "config_query_scope",
    ],
)
def test_local_diff_preserves_active_blob_replacements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, view: str
) -> None:
    import workbench_target

    for name in (
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_REPLACE_REF_BASE",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG",
        "CODEX_SECURITY_GIT_ENVIRONMENT_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    target = tmp_path / "repository"
    initialize_git_repository(target)
    source = target / "source.py"
    source.write_bytes(b"value = 1\n")
    unchanged = target / "unchanged.py"
    unchanged.write_bytes(b"unchanged = 1\n")

    def git(*args: str, input_data: bytes | None = None) -> bytes:
        return subprocess.check_output(["git", "-C", str(target), *args], input=input_data)

    git("add", ".")
    git("commit", "-qm", "replacement fixture")
    original = git("rev-parse", "HEAD:source.py").strip().decode()
    replacement = git("hash-object", "-w", "--stdin", input_data=b"value = 2\n").strip().decode()
    if view == "custom":
        monkeypatch.setenv("GIT_REPLACE_REF_BASE", "refs/fixture-replacements/")
    if view == "uppercase":
        git("update-ref", f"refs/replace/{original.upper()}", replacement)
    else:
        git("replace", original, replacement)
    if view == "chain":
        last = git("hash-object", "-w", "--stdin", input_data=b"value = 3\n").strip().decode()
        git("replace", replacement, last)
    elif view == "missing_original":
        (target / ".git" / "objects" / original[:2] / original[2:]).unlink()
    elif view in {"disabled", "disabled_empty"}:
        monkeypatch.setenv("GIT_NO_REPLACE_OBJECTS", "1" if view == "disabled" else "")
    elif view == "core_false":
        git("config", "core.useReplaceRefs", "false")
    elif view == "core_inline_false":
        monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.useReplaceRefs=false'")
    elif view == "config_query_scope":
        config = tmp_path / "command-only-config"
        config.write_text("[core]\nuseReplaceRefs = false\n")
        monkeypatch.setenv("GIT_CONFIG", str(config))
    for path in (source, unchanged):
        os.utime(path, (1, 1))
    index = (target / ".git" / "index").read_bytes()
    expected = view not in {"disabled", "disabled_empty", "core_false", "core_inline_false"}
    patch = git(
        "-c", "diff.autoRefreshIndex=false", "diff", "--no-ext-diff", "--no-textconv", "HEAD"
    )
    assert bool(patch) is expected
    assert workbench_target.git_changed_path_names(target, "HEAD", "HEAD", "local-patch") == (
        [("source.py", "M")] if expected else []
    )
    assert workbench_target.diff_scope_file_count(
        target, {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    ) == int(expected)
    assert (target / ".git" / "index").read_bytes() == index


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux stack and argv limits")
def test_git_projection_quotes_native_valid_parameters_with_limited_argv(tmp_path: Path) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    executable = workbench_target.trusted_git_executable(target)
    assert executable is not None
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            """
import os, resource, subprocess, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from workbench_target import git_inspection_environment
executable, target = sys.argv[2], Path(sys.argv[3])
environment = {
    "PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_PARAMETERS": "'x.b' " * 18000 + "'http.extraHeader=synthetic'",
}
resource.setrlimit(resource.RLIMIT_STACK, (512 * 1024, resource.getrlimit(resource.RLIMIT_STACK)[1]))
args = [executable, "-C", str(target), "config", "--null", "--list", "--show-origin", "--no-includes"]
native = subprocess.check_output(args, env=environment)
assert native.split(b"\\0").count(b"x.b") == 18000
projected = git_inspection_environment(environment, executable, target)
actual = subprocess.check_output(args, env=projected)
assert actual.split(b"\\0").count(b"x.b") == 18000
assert b"http.extraheader" not in actual
environment["GIT_CONFIG_PARAMETERS"] = "'x.b' " * 17999 + "'x.b'"
assert git_inspection_environment(environment, executable, target) == environment
""",
            str(Path(workbench_target.__file__).parent),
            executable,
            str(target),
        ],
        check=True,
    )


@pytest.mark.cross_platform
@pytest.mark.parametrize("failure", ["length", "windows_length", "fatal", "other_os", "singleton"])
def test_git_projection_quote_retry_preserves_native_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    executable = workbench_target.trusted_git_executable(target)
    assert executable is not None
    environment = {
        "PATH": os.environ["PATH"],
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_PARAMETERS": "'fixture.first=one' 'fixture.empty=' 'http.extraHeader=synthetic'",
    }
    if failure == "singleton":
        environment["GIT_CONFIG_PARAMETERS"] = "'fixture.first=one' 'http.extraHeader=synthetic'"
    native_run = subprocess.run
    calls: list[int] = []
    error = OSError(errno.EACCES if failure == "other_os" else errno.E2BIG, "native quote fixture")
    if failure == "windows_length":
        error = OSError(errno.EINVAL, "native quote fixture")
        error.winerror = 206

    def limited(command: list[str], *args: Any, **kwargs: Any):
        if "--sq-quote" in command:
            count = len(command) - command.index("--sq-quote") - 1
            calls.append(count)
            if failure == "fatal":
                return subprocess.CompletedProcess(
                    command, 128, stdout=b"", stderr=b"native quote failure\n"
                )
            if failure in {"other_os", "singleton"} or len(calls) == 1:
                raise error
        return native_run(command, *args, **kwargs)

    monkeypatch.setattr(workbench_target.subprocess, "run", limited)
    if failure in {"length", "windows_length"}:
        projected = workbench_target.git_inspection_environment(environment, executable, target)
        quoted = projected["GIT_CONFIG_PARAMETERS"]
        assert quoted.index("'fixture.first=one'") < quoted.index("'fixture.empty='")
        assert "http.extraheader" not in quoted.lower()
        assert calls[0] > 1
        assert sum(calls[1:]) == calls[0]
    elif failure == "fatal":
        with pytest.raises(subprocess.CalledProcessError) as raised:
            workbench_target.git_inspection_environment(environment, executable, target)
        assert raised.value.returncode == 128
        assert raised.value.stderr == b"native quote failure\n"
        assert len(calls) == 1
    else:
        with pytest.raises(OSError) as raised:
            workbench_target.git_inspection_environment(environment, executable, target)
        assert raised.value is error
        if failure == "singleton":
            assert calls[-1] == 1
        else:
            assert len(calls) == 1
