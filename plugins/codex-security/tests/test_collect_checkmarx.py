import json
import os
import re
import runpy
import shutil
import signal
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from types import SimpleNamespace
from xml.etree.ElementTree import Element, ElementTree

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "publish-findings"
    / "scripts"
    / "collect_checkmarx.py"
)
ONE_SCAN = "00000000-0000-4000-8000-000000000001"


@pytest.fixture
def capture_dir(monkeypatch, tmp_path):
    directory = tmp_path / "private exports"
    directory.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.chdir(source)
    monkeypatch.setattr(tempfile, "tempdir", str(directory))
    monkeypatch.setenv("CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS", "1")
    for setting in ("CX_CONFIG_FILE_PATH", "CX_APIKEY", "CX_CLIENT_ID", "CX_CLIENT_SECRET"):
        monkeypatch.delenv(setting, raising=False)
    return directory


def invoke(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), *args])
    try:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    except SystemExit as exit:
        return exit.code
    return 0


def mock_vendor(monkeypatch, run):
    def popen(*args, **kwargs):
        result = run(*args, **kwargs)
        return SimpleNamespace(wait=lambda: result.returncode)

    monkeypatch.setattr(subprocess, "Popen", popen)


def executable(directory, name):
    path = directory / (f"{name}.exe" if os.name == "nt" else name)
    shutil.copy(shutil.which("true", path=os.defpath) or sys.executable, path)
    return str(path)


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires the Windows account profile API")
def test_one_default_profile_uses_the_windows_account_home(monkeypatch, tmp_path):
    import ctypes.wintypes

    # CSIDL_PROFILE asks the Windows shell for the current user's profile folder.
    account = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
    assert ctypes.windll.shell32.SHGetFolderPathW(None, 0x28, None, 0, account) == 0
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert Path.home() == tmp_path
    profiles = runpy.run_path(str(SCRIPT))["one_default_profiles"]()
    assert profiles == {Path(account.value) / ".checkmarx" / "checkmarxcli.yaml"}


@pytest.mark.cross_platform
def test_refuses_profile_routed_through_the_checkout(capture_dir, tmp_path, monkeypatch, capsys):
    source = Path.cwd()
    installed = tmp_path / "installed"
    installed.mkdir()
    (installed / "profile.yaml").touch()
    checkout_link = source / "active"
    selected = tmp_path / "selected"
    for link, target in [(checkout_link, installed), (selected, checkout_link)]:
        if os.name == "nt":
            subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True)
        else:
            link.symlink_to(os.path.relpath(target, link.parent), target_is_directory=True)
    profile = selected / "profile.yaml"
    assert profile.samefile(installed / "profile.yaml")
    # Stand in for a checkout link to an SMB share. Following it, even to query
    # the file type, would start authentication before the vendor process runs.
    following = {selected, profile, checkout_link, checkout_link / "profile.yaml"}
    original_stat = Path.stat
    original_resolve = Path.resolve
    original_readlink = Path.readlink

    def guarded_stat(path, *args, **kwargs):
        assert path not in following or not kwargs.get("follow_symlinks", True)
        return original_stat(path, *args, **kwargs)

    def guarded_resolve(path, *args, **kwargs):
        assert path not in following
        return original_resolve(path, *args, **kwargs)

    def guarded_readlink(path):
        assert path != checkout_link
        return original_readlink(path)

    monkeypatch.setattr(Path, "stat", guarded_stat)
    monkeypatch.setattr(Path, "resolve", guarded_resolve)
    monkeypatch.setattr(Path, "readlink", guarded_readlink)
    collector = runpy.run_path(str(SCRIPT))
    monkeypatch.setenv("PATH", os.pathsep.join([str(checkout_link), str(selected), str(installed)]))
    with pytest.raises(ValueError, match="outside the source checkout"):
        collector["installed_file"](str(profile), source)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CX_CONFIG_FILE_PATH", str(profile))
    cx = executable(tmp_path, "cx")
    assert invoke(monkeypatch, "--source-root", str(source), "one", ONE_SCAN, "--cx", cx) != 0
    assert "CX_CONFIG_FILE_PATH" in capsys.readouterr().err
    assert not list(capture_dir.iterdir())

    monkeypatch.setenv("TMPDIR", str(selected))
    monkeypatch.setattr(tempfile, "tempdir", None)
    monkeypatch.setattr(
        tempfile, "TemporaryFile", lambda **kwargs: pytest.fail("probed a checkout-selected temp")
    )
    with pytest.raises(ValueError, match="temporary directory outside"):
        collector["capture_tempdir"](source)


@pytest.mark.cross_platform
def test_checkout_git_marker_does_not_follow_links(capture_dir, tmp_path, monkeypatch):
    source = Path.cwd()
    marker = source / ".git"
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(marker), str(tmp_path)], check=True)
    else:
        marker.symlink_to(tmp_path, target_is_directory=True)
    original_stat = Path.stat

    def guarded_stat(path, *args, **kwargs):
        if path == marker or marker in path.parents:
            assert path == marker and not kwargs.get("follow_symlinks", True)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", guarded_stat)
    assert runpy.run_path(str(SCRIPT))["source_root"](source) == source


def cxflow_jar(path, version="1.7.14", main="com.checkmarx.flow.CxFlowApplication"):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "META-INF/MANIFEST.MF", f"Manifest-Version: 1.0\r\nStart-Class: {main}\r\n\r\n"
        )
        archive.writestr(
            "META-INF/build-info.properties",
            f"build.group=com.checkmarx\nbuild.version={version}\n",
        )


@pytest.fixture
def cxsast_args(tmp_path):
    jar, config = tmp_path / "cx-flow.jar", tmp_path / "application.yml"
    cxflow_jar(jar)
    config.touch()
    return [
        "cxsast",
        "1234",
        "--team",
        "/CxServer",
        "--project",
        "R&D",
        "--jar",
        str(jar),
        "--config",
        str(config),
        "--java",
        executable(tmp_path, "java"),
    ]


@pytest.mark.parametrize(
    "version, main",
    [
        ("1.6.36", "com.checkmarx.flow.CxFlowApplication"),
        ("unknown", "com.checkmarx.flow.CxFlowApplication"),
        ("1.7.14", "other.Application"),
    ],
)
@pytest.mark.cross_platform
def test_refuses_unknown_or_unsupported_scan_selection(
    version, main, capture_dir, cxsast_args, monkeypatch, capsys
):
    jar = Path(cxsast_args[cxsast_args.index("--jar") + 1])
    cxflow_jar(jar, version=version, main=main)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: pytest.fail("started Java"))
    assert invoke(monkeypatch, *cxsast_args) != 0
    assert "scoped CxSAST XML export" in capsys.readouterr().err
    assert not list(capture_dir.iterdir())


@pytest.mark.parametrize("option", ["--cx", "--java", "--jar", "--config"])
@pytest.mark.cross_platform
def test_refuses_vendor_files_inside_the_scan_source(
    option, capture_dir, cxsast_args, monkeypatch, tmp_path, capsys
):
    source = Path.cwd()
    tools = source / "tools"
    tools.mkdir()
    if option == "--cx":
        request = ["one", ONE_SCAN, "--cx", executable(tmp_path, "cx")]
    else:
        # A checkout may be entered from a subdirectory, with its tool elsewhere in the tree.
        (source / ".git").mkdir()
        (source / ".git" / "HEAD").touch()
        subdir = source / "src"
        subdir.mkdir()
        (subdir / ".git").write_text("gitdir: ../.git/modules/sub")
        monkeypatch.chdir(subdir)
        request = cxsast_args
    # Bootstrap Python from a trusted directory while retaining the selected source.
    selected = Path.cwd()
    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir()
    monkeypatch.chdir(bootstrap)
    request = ["--source-root", str(selected), *request]
    index = request.index(option) + 1
    checkout_file = tools / Path(request[index]).name
    checkout_file.touch()
    request[index] = str(checkout_file)
    assert invoke(monkeypatch, *request) != 0
    assert "outside the source checkout" in capsys.readouterr().err
    if os.name != "nt":
        alias = tmp_path / "configured-file"
        alias.symlink_to(checkout_file)
        request[index] = str(alias)
        assert invoke(monkeypatch, *request) != 0
        assert "outside the source checkout" in capsys.readouterr().err
    assert not list(capture_dir.iterdir())


@pytest.mark.parametrize("suffix", [".cmd", ".BAT"])
@pytest.mark.cross_platform
def test_refuses_windows_batch_launchers(
    suffix, capture_dir, cxsast_args, monkeypatch, tmp_path, capsys
):
    launcher = tmp_path / f"java{suffix}"
    launcher.touch()
    monkeypatch.setattr(sys, "platform", "win32")
    paths = [launcher]
    if os.name != "nt":
        alias = tmp_path / "java.exe"
        alias.symlink_to(launcher)
        paths.append(alias)
    for path in paths:
        cxsast_args[cxsast_args.index("--java") + 1] = str(path)
        assert invoke(monkeypatch, *cxsast_args) != 0
        assert "native Windows executable" in capsys.readouterr().err


@pytest.mark.parametrize("setting", ["CX_CONFIG_FILE_PATH", "TMPDIR"])
@pytest.mark.cross_platform
def test_refuses_vendor_paths_that_resolve_into_source(
    setting, capture_dir, monkeypatch, tmp_path, capsys
):
    source = Path.cwd() / "private"
    if setting == "TMPDIR":
        source.mkdir()
    else:
        source.touch()
    paths = [source]
    if os.name != "nt":
        alias = tmp_path / "external-alias"
        alias.symlink_to(source, target_is_directory=source.is_dir())
        paths.append(alias)
    cx = executable(tmp_path, "cx")
    selected = Path.cwd()
    monkeypatch.chdir(tmp_path)
    for path in paths:
        monkeypatch.setenv(setting, str(path))
        if setting == "TMPDIR":
            monkeypatch.setattr(tempfile, "tempdir", None)  # Read the actual TMPDIR.
        assert invoke(monkeypatch, "--source-root", str(selected), "one", ONE_SCAN, "--cx", cx) != 0
        assert "outside the source checkout" in capsys.readouterr().err
    assert not list(capture_dir.iterdir())
    if source.is_dir():
        assert not list(source.iterdir())


@pytest.mark.skipif(os.name == "nt", reason="exercises Bash startup on Unix")
@pytest.mark.native_macos
def test_shell_launcher_cannot_load_checkout_startup_hook(capture_dir, monkeypatch, tmp_path):
    hook = Path.cwd() / "bash-env"
    marker = tmp_path / "hook-ran"
    hook.write_text('printf x > "$COLLECT_HOOK_MARKER"\n')
    monkeypatch.setenv("BASH_ENV", str(hook))
    monkeypatch.setenv("COLLECT_HOOK_MARKER", str(marker))
    monkeypatch.setenv("TMPDIR", str(capture_dir))
    cx = tmp_path / "vendor cx"
    cx.write_text("#!/usr/bin/env bash\nexit 19\n")
    cx.chmod(0o755)
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(SCRIPT), "one", ONE_SCAN, "--cx", str(cx)],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0 and not marker.exists()
    assert "installed native executable" in result.stderr
    assert not list(capture_dir.iterdir())


@pytest.mark.cross_platform
def test_omitted_source_protects_only_an_enclosing_checkout(capture_dir, monkeypatch, capsys):
    bootstrap = Path.cwd()
    cx = executable(bootstrap, "cx")
    temp = bootstrap / "private temp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))

    def run(args, *, cwd, **kwargs):
        (Path(cwd) / "cx_result.json").write_text(json.dumps({"scanID": ONE_SCAN}))
        return subprocess.CompletedProcess(args, 0)

    mock_vendor(monkeypatch, run)
    request = ["one", ONE_SCAN, "--cx", cx]
    assert invoke(monkeypatch, *request) == 0
    assert Path(capsys.readouterr().out.strip()).is_relative_to(temp)

    (bootstrap / ".git").mkdir()
    (bootstrap / ".git" / "HEAD").touch()
    monkeypatch.chdir(temp)
    assert invoke(monkeypatch, *request) != 0
    assert "outside the source checkout" in capsys.readouterr().err


@pytest.mark.cross_platform
def test_one_collects_exact_scan_to_a_fresh_private_path(
    capture_dir, monkeypatch, tmp_path, capsys
):
    # Preserve the selected name for native multicall launchers that dispatch on argv[0].
    if os.name == "nt":
        cx = executable(tmp_path, "vendor cx")
    else:
        cx = str(tmp_path / "vendor cx")
        Path(cx).symlink_to(executable(tmp_path, "launcher"))
    config = tmp_path / "my cx config"
    config.touch()
    monkeypatch.setenv("CX_CONFIG_FILE_PATH", str(config))
    tools = tmp_path / "external tools"
    tools.mkdir()
    checkout_bin = Path.cwd() / "bin"
    checkout_bin.mkdir()
    monkeypatch.setenv("PATH", os.pathsep.join(["bin", str(checkout_bin), str(tools)]))
    selected = Path.cwd()
    monkeypatch.chdir(tmp_path)
    loaders = {
        "LD_LIBRARY_PATH": str(checkout_bin),
        "LD_PRELOAD": str(checkout_bin / "plugin.so"),
        "DYLD_INSERT_LIBRARIES": str(checkout_bin / "plugin.dylib"),
    }
    for name, value in loaders.items():
        monkeypatch.setenv(name, value)
    requested = ["--source-root", str(selected), "one", ONE_SCAN, "--cx", cx]
    reports = []

    def run(args, *, cwd, **kwargs):
        out = Path(cwd)
        assert out.is_relative_to(capture_dir)
        assert kwargs["env"]["CX_CONFIG_FILE_PATH"] == str(config)
        assert "PATH" not in kwargs["env"]
        if os.name != "nt":
            assert loaders.keys().isdisjoint(kwargs["env"])
        kwargs["stdout"].write("retrieved existing scan\n")
        assert list(map(str, args)) == [
            cx,
            "results",
            "show",
            "--scan-id",
            ONE_SCAN,
            "--report-format",
            "json",
            "--output-path",
            str(out),
            "--output-name",
            "cx_result",
        ]
        report = out / "cx_result.json"
        report.write_text(json.dumps({"scanID": ONE_SCAN, "totalCount": 0, "results": None}))
        (out / "vendor-log.txt").write_text("vendor diagnostic")
        return subprocess.CompletedProcess(args, 0)

    mock_vendor(monkeypatch, run)
    for _ in range(2):
        assert invoke(monkeypatch, *requested) == 0
        output = capsys.readouterr()
        assert "retrieved existing scan" in output.err
        saved = Path(output.out.rstrip("\n"))
        assert saved.is_absolute() and saved.parent.parent == capture_dir
        assert list(saved.parent.iterdir()) == [saved]
        assert json.loads(saved.read_text())["scanID"] == ONE_SCAN
        reports.append(saved)
    assert reports[0].parent != reports[1].parent
    assert {name: os.environ[name] for name in loaders} == loaders


@pytest.mark.parametrize("failure", ["wrong scan", "invalid JSON", "missing file", "nonzero exit"])
@pytest.mark.cross_platform
def test_one_discards_failed_exports(failure, capture_dir, monkeypatch, tmp_path, capsys):
    cx = executable(tmp_path, "cx")

    def run(args, *, cwd, **kwargs):
        if failure == "wrong scan":
            (Path(cwd) / "cx_result.json").write_text(
                json.dumps({"scanID": "different-scan", "totalCount": 0, "results": []})
            )
        if failure in {"invalid JSON", "nonzero exit"}:
            (Path(cwd) / "cx_result.json").write_text('{"partial":')
        if failure == "nonzero exit":
            kwargs["stdout"].write("vendor error while fetching the scan\n")
        return subprocess.CompletedProcess(args, 1 if failure == "nonzero exit" else 0)

    mock_vendor(monkeypatch, run)
    assert invoke(monkeypatch, "one", ONE_SCAN, "--cx", cx) != 0
    output = capsys.readouterr()
    assert not output.out
    if failure == "nonzero exit":
        assert "vendor error while fetching the scan" in output.err
    assert not list(capture_dir.iterdir())


@pytest.mark.parametrize("refusal", ["opt-in disabled", "relative config"])
@pytest.mark.cross_platform
def test_one_refuses_before_vendor_invocation(refusal, capture_dir, monkeypatch, tmp_path, capsys):
    cx = executable(tmp_path, "cx")
    if refusal == "opt-in disabled":
        monkeypatch.delenv("CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS")
        monkeypatch.setattr(
            Path, "is_file", lambda path: pytest.fail(f"Probed {path} before opt-in")
        )
    else:
        monkeypatch.setenv("CX_CONFIG_FILE_PATH", "my-config.yaml")

    def unexpected(*args, **kwargs):
        pytest.fail(f"Collector invoked the vendor CLI with {refusal}")

    monkeypatch.setattr(subprocess, "Popen", unexpected)
    assert invoke(monkeypatch, "one", ONE_SCAN, "--cx", cx) != 0
    output = capsys.readouterr()
    assert not output.out
    if refusal == "relative config":
        assert "CX_CONFIG_FILE_PATH" in output.err and "absolute" in output.err
    assert not list(capture_dir.iterdir())


@pytest.mark.parametrize(
    "result",
    ["selected", "scan", "project", "team", "missing team", "expanded team", "invalid XML"],
)
@pytest.mark.cross_platform
def test_cxsast_collects_selected_scan_with_xml_tracker(
    result, capture_dir, monkeypatch, tmp_path, capsys
):
    install = tmp_path / "Java installation"
    install.mkdir()
    java = executable(install, "java")
    if os.name != "nt":
        launcher = Path(java).rename(install / "launcher")
        Path(java).symlink_to(launcher)
    # A PATH containing tools from the scan target does not select the launcher.
    monkeypatch.setenv("PATH", str(tmp_path))
    executable(tmp_path, "java")
    monkeypatch.setenv("CX_CONFIG_FILE_PATH", "unrelated-one-config.yaml")
    startup_settings = {
        "JDK_ALTERNATE_VM": str(Path.cwd()),
        "JDK_JAVA_OPTIONS": "-Xmx256m",
        "JAVA_TOOL_OPTIONS": f'-javaagent:"{Path.cwd() / "coverage.jar"}"',
        "_JAVA_OPTIONS": f"-DLOGBACK_ROLLINGPOLICY_FILE_NAME_PATTERN={Path.cwd()}/escape.%i.gz",
        "OPENJ9_JAVA_OPTIONS": "-Dfile.encoding=windows-1252",
        "IBM_JAVA_OPTIONS": "-Xmx256m",
        "CHECKMARX_BASE_URL": "https://unselected.invalid",
        "CX_PROBE_IMPORT_ROOT": str(Path.cwd()),
        "LD_PRELOAD": str(Path.cwd() / "library.so"),
        "DYLD_INSERT_LIBRARIES": str(Path.cwd() / "library.dylib"),
        "SPRING_MAIN_SOURCES": "file:/checkout/beans.xml",
        "spring.main.sources": "file:/checkout/beans.xml",
        "SPRING_APPLICATION_JSON": '{"spring.main.sources":"file:/checkout/beans.xml"}',
    }
    for name, value in startup_settings.items():
        monkeypatch.setenv(name, value)
    credentials = {
        "CHECKMARX_USERNAME": "synthetic-user",
        "CHECKMARX_PASSWORD": "synthetic-password",
        "CHECKMARX_CLIENT_SECRET": "synthetic-client-secret",
    }
    for name, value in credentials.items():
        monkeypatch.setenv(name, value)
    jar = tmp_path / "Cx Flow.jar"
    config = tmp_path / "private config,west.yml"
    cxflow_jar(jar)
    config.touch()

    def run(args, *, cwd, **kwargs):
        args = list(map(str, args))
        assert {name.lower() for name in startup_settings}.isdisjoint(
            name.lower() for name in kwargs["env"]
        )
        assert {name: kwargs["env"][name] for name in credentials} == credentials
        assert all(kwargs["env"][name] == str(cwd) for name in ("TMP", "TEMP", "TMPDIR"))
        if os.name == "nt":
            assert kwargs["env"]["SystemRoot"] == os.environ["SystemRoot"]
        assert args[:6] == [
            java,
            f"-Djava.io.tmpdir={cwd}",
            f"-DLOG_PATH={cwd}",
            "-Dfile.encoding=UTF-8",
            "-jar",
            str(jar),
        ]
        assert {
            f"--spring.config.location={config.as_uri()}",
            "--spring.config.additional-location=",
            "--spring.config.import=",
            "--logging.config=classpath:logback-spring.xml",
            f"--logging.file.path={cwd}",
            f"--logging.file.name={Path(cwd, 'cx-flow.log')}",
            f"--logging.logback.rollingpolicy.file-name-pattern={Path(cwd, 'cx-flow.%d{yyyy-MM-dd}.%i.gz')}",
            "--project",
            "--scanId=1234",
            "--cx-team=/CxServer/Masse Team",
            "--cx-project=Example Project",
            "--app=Example Project",
            "--bug-tracker=CxXml",
            "--cx-flow.bug-tracker-impl=CxXml",
            "--cx-flow.enabled-vulnerability-scanners=sast",
            "--cx-flow.preserve-project-name=true",
            "--cx-flow.mail.notification=false",
            "--cx-flow.filter-script=",
            "--checkmarx.preserve-xml=true",
            f"--cx-xml.data-folder={cwd}",
            "--cx-xml.file-name-format=checkmarx-results.xml",
        } <= set(args)
        assert "--scan" not in args
        path = Path(cwd) / "checkmarx-results.xml"
        attributes = {
            "ScanId": "5678" if result == "scan" else "1234",
            "ProjectId": "2",
            "ProjectName": "Other Project" if result == "project" else "Example Project",
        }
        if result != "missing team":
            attributes["TeamFullPathOnReportDate"] = (
                r"cxserver\Other Team" if result == "team" else r"CXSERVER\Masse Team"
            )
            if result == "expanded team":
                attributes["TeamFullPathOnReportDate"] = r"CXSERVER\Maße Team"
        if result == "invalid XML":
            path.write_text("<CxXMLResults")
        else:
            ElementTree(Element("CxXMLResults", attributes)).write(path)
        return subprocess.CompletedProcess(args, 0)

    mock_vendor(monkeypatch, run)
    code = invoke(
        monkeypatch,
        "cxsast",
        "1234",
        "--java",
        java,
        "--jar",
        str(jar),
        "--config",
        str(config),
        "--team",
        "/CxServer/Masse Team/",
        "--project",
        "Example Project",
    )
    assert {name: os.environ[name] for name in startup_settings} == startup_settings
    stdout = capsys.readouterr().out
    if result == "selected":
        assert code == 0
        path = Path(stdout.rstrip("\n"))
        assert path.is_absolute() and path.is_relative_to(capture_dir)
        assert path.name == "checkmarx-results.xml" and path.is_file()
    else:
        assert code != 0
        assert not stdout
        assert not list(capture_dir.iterdir())


@pytest.mark.native_macos
@pytest.mark.skipif(os.name != "posix", reason="exercises the Unix Java launcher")
def test_java_receives_team_and_project_names_in_the_cxsast_environment(tmp_path):
    java = shutil.which("java")
    if not java:
        pytest.skip("requires a Java runtime")
    env = runpy.run_path(str(SCRIPT))["cxsast_environment"](str(tmp_path))
    modules = subprocess.run([java, "--list-modules"], env=env, capture_output=True)
    compiler = re.search(rb"^jdk\.compiler@(\d+)", modules.stdout, re.MULTILINE)
    if not compiler or int(compiler[1]) < 11:
        pytest.skip("the Java source-file probe requires a JDK 11+ compiler module")
    probe = tmp_path / "Names.java"
    probe.write_text(
        """import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Arrays;

class Names {
    public static void main(String[] args) throws Exception {
        Files.write(Paths.get("arguments.txt"), Arrays.asList(args), StandardCharsets.UTF_8);
    }
}
""",
        encoding="ascii",
    )
    names = ["--cx-team=/CxServer/Équipe 東京", "--cx-project=Projet Maße"]
    subprocess.run(
        [java, "-Dfile.encoding=UTF-8", probe, *names], cwd=tmp_path, env=env, check=True
    )
    assert (tmp_path / "arguments.txt").read_text(encoding="utf-8").splitlines() == names


@pytest.mark.cross_platform
def test_excludes_source_by_filesystem_identity(capture_dir, monkeypatch, tmp_path, capsys):
    source = Path.cwd()
    checkout_file = executable(source, "cx")
    alias = source.with_name(source.name.upper())
    if not alias.exists():
        # Model a filesystem preserving alternate case spellings on realpath.
        alias.symlink_to(source, target_is_directory=True)
        resolve = Path.resolve
        monkeypatch.setattr(
            Path,
            "resolve",
            lambda path, *args, **kw: (
                path if path.is_relative_to(alias) else resolve(path, *args, **kw)
            ),
        )
    assert source.samefile(alias)
    assert (
        invoke(
            monkeypatch,
            "--source-root",
            str(source),
            "one",
            ONE_SCAN,
            "--cx",
            str(alias / Path(checkout_file).name),
        )
        != 0
    )
    assert "outside the source checkout" in capsys.readouterr().err


@pytest.mark.parametrize(
    "lookup", ["libc", "passwd", "HOME"] if sys.platform == "linux" else ["libc"]
)
@pytest.mark.skipif(os.name == "nt", reason="exercises Unix account home lookup")
@pytest.mark.native_macos
def test_one_checks_default_profile_from_account_home(
    lookup, capture_dir, monkeypatch, tmp_path, capsys
):
    import pwd

    account = tmp_path / "account"
    account.mkdir()
    (account / ".checkmarx").symlink_to(Path.cwd(), target_is_directory=True)
    (Path.cwd() / "checkmarxcli.yaml").touch()
    other = tmp_path / "alternate-home"
    monkeypatch.setenv("HOME", str(account if lookup == "HOME" else other))
    libc_home = account if lookup == "libc" else other
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(libc_home)))
    if sys.platform == "linux":
        passwd = tmp_path / "passwd"
        entry = b"cx:x:%d:1:Example:%s:/bin/sh\n" % (os.getuid(), os.fsencode(account))
        # Go skips a commented record and a NIS/invalid group entry before its UID lookup.
        inactive = b" #old:x:%d:1:Old:%s:/bin/sh\n" % (os.getuid(), os.fsencode(other))
        inactive += b"+old:x:%d:invalid:Old:%s:/bin/sh\n" % (os.getuid(), os.fsencode(other))
        passwd.write_bytes(inactive + (entry if lookup == "passwd" else b""))
        original_open = Path.open

        def open_file(path, *args, **kwargs):
            return original_open(passwd if str(path) == "/etc/passwd" else path, *args, **kwargs)

        monkeypatch.setattr(Path, "open", open_file)

    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **kw: pytest.fail("unexpected cx invocation")
    )
    assert (
        invoke(
            monkeypatch,
            "--source-root",
            str(Path.cwd()),
            "one",
            ONE_SCAN,
            "--cx",
            executable(tmp_path, "cx"),
        )
        != 0
    )
    assert "CX_CONFIG_FILE_PATH" in capsys.readouterr().err
    assert not list(capture_dir.iterdir())


@pytest.mark.cross_platform
def test_one_accepts_the_same_scan_uuid_in_server_spelling(
    capture_dir, monkeypatch, tmp_path, capsys
):
    scan = "abcdef12-0000-4000-8000-123456789abc"

    def run(args, *, cwd, **kwargs):
        assert args[args.index("--scan-id") + 1] == scan.upper()
        (Path(cwd) / "cx_result.json").write_text(json.dumps({"scanID": scan}))
        return subprocess.CompletedProcess(args, 0)

    mock_vendor(monkeypatch, run)
    assert invoke(monkeypatch, "one", scan.upper(), "--cx", executable(tmp_path, "cx")) == 0
    saved = Path(capsys.readouterr().out.strip())
    assert json.loads(saved.read_text())["scanID"] == scan


@pytest.mark.parametrize("scan_id", ["?limit=1", ONE_SCAN.replace("-", ""), ONE_SCAN + "\n"])
@pytest.mark.cross_platform
def test_one_rejects_invalid_uuid_before_vendor_lookup(
    scan_id, capture_dir, monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **kw: pytest.fail("unexpected cx invocation")
    )
    assert invoke(monkeypatch, "one", scan_id, "--cx", executable(tmp_path, "cx")) != 0
    assert "scan UUID" in capsys.readouterr().err
    assert not list(capture_dir.iterdir())


@pytest.mark.parametrize(
    ("option", "name"),
    [
        ("--team", ""),
        ("--team", " / \\ \t/"),
        ("--project", "\t "),
    ],
)
@pytest.mark.cross_platform
def test_cxsast_rejects_unselected_scope_before_vendor_lookup(
    option, name, cxsast_args, capture_dir, monkeypatch, capsys
):
    cxsast_args[cxsast_args.index(option) + 1] = name
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **kw: pytest.fail("unexpected CxFlow invocation")
    )
    assert invoke(monkeypatch, *cxsast_args) != 0
    assert "CxSAST team path and project" in capsys.readouterr().err
    assert not list(capture_dir.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="exercises POSIX termination signals")
@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP"])
@pytest.mark.native_macos
def test_cancellation_reaps_vendor_and_removes_partial_report(
    name, capture_dir, monkeypatch, tmp_path
):
    # Run a native child that signals the active collector after creating its partial report.
    native_popen = subprocess.Popen
    child = None
    signum = getattr(signal, name)

    def start_child(_command, **kwargs):
        nonlocal child
        child = native_popen(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                (
                    "import os, signal, time; from pathlib import Path; "
                    "Path('cx_result.json').write_text('partial'); "
                    f"os.kill(os.getppid(), signal.{name}); time.sleep(30)"
                ),
            ],
            **kwargs,
        )
        return child

    monkeypatch.setattr(subprocess, "Popen", start_child)
    previous = signal.signal(signum, lambda *_: None)
    try:
        assert (
            invoke(monkeypatch, "one", ONE_SCAN, "--cx", executable(tmp_path, "cx")) == 128 + signum
        )
        assert child is not None and child.returncode == -signal.SIGKILL
        assert not list(capture_dir.iterdir())
    finally:
        signal.signal(signum, previous)
        if child is not None:
            child.kill()
            child.wait()


@pytest.mark.skipif(os.name != "posix", reason="exercises POSIX termination signals")
@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP", "SIGINT"])
@pytest.mark.native_macos
def test_cancellation_before_popen_returns_reaps_vendor(
    name, capture_dir, monkeypatch, tmp_path, capfd
):
    popen = subprocess.Popen
    child = None
    signum = getattr(signal, name)

    def launch(command, **kwargs):
        nonlocal child
        child = popen([sys.executable, "-I", "-S", "-c", "import time; time.sleep(30)"], **kwargs)
        signal.raise_signal(signum)
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    previous = signal.signal(signum, lambda *_: None)
    try:
        assert (
            invoke(monkeypatch, "one", ONE_SCAN, "--cx", executable(tmp_path, "cx")) == 128 + signum
        )
        assert child is not None and child.returncode == -signal.SIGKILL
        assert not capfd.readouterr().out
        assert not list(capture_dir.iterdir())
    finally:
        signal.signal(signum, previous)
        if child is not None:
            child.kill()
            child.wait()


@pytest.mark.cross_platform
def test_preserves_an_ignored_interrupt(capture_dir, monkeypatch, tmp_path):
    def run(args, *, cwd, **kwargs):
        assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
        (Path(cwd) / "cx_result.json").write_text(json.dumps({"scanID": ONE_SCAN}))
        return subprocess.CompletedProcess(args, 0)

    mock_vendor(monkeypatch, run)
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        assert invoke(monkeypatch, "one", ONE_SCAN, "--cx", executable(tmp_path, "cx")) == 0
        assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
    finally:
        signal.signal(signal.SIGINT, previous)


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory ACLs")
def test_capture_private_before_vendor_writes_on_legacy_windows_python(
    capture_dir, monkeypatch, tmp_path, capsys
):
    icacls = Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"
    subprocess.run([icacls, capture_dir, "/grant", "*S-1-1-0:(OI)(CI)R"], check=True)

    def dacl(path):
        saved = tmp_path / "acl.txt"
        subprocess.run([icacls, path, "/save", saved, "/q"], check=True)
        value = saved.read_text(encoding="utf-16-le").rstrip().splitlines()[-1]
        assert value.startswith("D:")
        return value

    shared = capture_dir / "control.txt"
    shared.touch()
    assert ";;;WD)" in dacl(shared)
    # Windows 3.10.11 does not apply a security descriptor for mkdir(0700).
    mkdir = os.mkdir
    monkeypatch.setattr(os, "mkdir", lambda path, mode=0o777: mkdir(path))
    profile = tmp_path / "trusted.yaml"
    profile.touch()
    monkeypatch.setenv("CX_CONFIG_FILE_PATH", str(profile))

    def run(_command, *, cwd, **_kwargs):
        work = Path(cwd)
        root_acl = dacl(work.parent)
        assert root_acl.startswith("D:P") and ";;;WD)" not in root_acl
        assert ";;;WD)" not in dacl(work)
        report = work / "cx_result.json"
        report.write_text(json.dumps({"scanID": ONE_SCAN}))
        assert ";;;WD)" not in dacl(report)
        return 0

    collector = runpy.run_path(str(SCRIPT))
    args = SimpleNamespace(product="one", scan_id=ONE_SCAN, cx="unused")
    collector["collect"](args, None, run)
    assert ";;;WD)" not in dacl(Path(capsys.readouterr().out.strip()))


@pytest.mark.cross_platform
@pytest.mark.parametrize("login", ["named-profile", "default-profile", "env-oauth", "env-key"])
def test_one_keeps_credentials_with_the_selected_login(capture_dir, tmp_path, monkeypatch, login):
    module = runpy.run_path(str(SCRIPT))
    selected = tmp_path / "signed in.yaml"
    selected.write_text("cx_client_id: saved-account\n")
    oauth = {
        "CX_CLIENT_ID": "test-account",
        "CX_CLIENT_SECRET": "synthetic-secret",
        "CX_BASE_URI": "https://api.example.invalid",
        "CX_TENANT": "example",
        "CX_BASE_AUTH_URI": "https://identity.example.invalid",
    }
    for name, value in oauth.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("CX_HTTP_PROXY", "http://proxy.example.invalid")
    monkeypatch.setenv("http_proxy", "http://proxy.example.invalid")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example.invalid")
    monkeypatch.setenv("CX_KEYRING_MODE", "required")
    if login == "named-profile":
        monkeypatch.setenv("CX_CONFIG_FILE_PATH", str(selected))
    if login == "default-profile":
        monkeypatch.delenv("CX_CLIENT_ID")
    if login in {"named-profile", "env-key"}:
        monkeypatch.setenv("CX_APIKEY", "synthetic-key")

    def run(_args, *, cwd, env, **_kwargs):
        assert {"HTTP_PROXY", "http_proxy", "CX_HTTP_PROXY"}.isdisjoint(env)
        if login in {"named-profile", "default-profile"}:
            assert oauth.keys().isdisjoint(env) and "CX_APIKEY" not in env
            assert env.get("CX_CONFIG_FILE_PATH") == (
                str(selected) if login == "named-profile" else None
            )
            assert env["CX_KEYRING_MODE"] == "required"
        else:
            profile = Path(env["CX_CONFIG_FILE_PATH"])
            assert profile.parent == Path(cwd) and profile.read_text() == "{}\n"
            assert env["CX_KEYRING_MODE"] == "disabled"
            if login == "env-key":
                assert env["CX_APIKEY"] == "synthetic-key" and oauth.keys().isdisjoint(env)
            else:
                assert {name: env[name] for name in oauth} == oauth and "CX_APIKEY" not in env
        Path(cwd, "cx_result.json").write_text(json.dumps({"scanID": ONE_SCAN}))
        return 0

    args = SimpleNamespace(product="one", cx=tmp_path / "cx", scan_id=ONE_SCAN)
    module["collect"](args, Path.cwd(), run)
    assert list(capture_dir.glob("*/*")) == list(capture_dir.glob("*/cx_result.json"))
