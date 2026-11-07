"""Exercise selected Checkmarx One and CxSAST report collection with isolated vendor tools."""

import io
import json
import os
import re
import runpy
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1] / "skills/publish-findings/scripts/collect_checkmarx.py"
)
collector = SimpleNamespace(**runpy.run_path(str(SCRIPT)))
ONE_SCAN = "abcdef12-0000-4000-8000-123456789abc"
CXSAST_XML = (
    '<CxXMLResults ScanId="1234" ProjectId="2" ProjectName="Example Project"'
    r' TeamFullPathOnReportDate="CXSERVER\Masse Team"/>'
)


@pytest.fixture
def capture_dir(monkeypatch, tmp_path):
    directory = tmp_path / "private exports"
    directory.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.chdir(source)
    monkeypatch.setattr(tempfile, "tempdir", str(directory))
    for setting in ("CX_CONFIG_FILE_PATH", "CX_APIKEY", "CX_CLIENT_ID", "CX_CLIENT_SECRET"):
        monkeypatch.delenv(setting, raising=False)
    return directory


def invoke(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), *args])
    try:
        return collector.main()
    except SystemExit as exit:
        return exit.code


def mock_vendor(monkeypatch, run):
    def popen(*args, **kwargs):
        status = run(*args, **kwargs)
        return SimpleNamespace(wait=lambda: status)

    monkeypatch.setattr(subprocess, "Popen", popen)


def executable(directory, name):
    path = directory / (f"{name}.exe" if os.name == "nt" else name)
    shutil.copy(shutil.which("true", path=os.defpath) or sys.executable, path)
    return str(path)


@pytest.fixture
def one_args(tmp_path):
    return ["one", ONE_SCAN, "--cx", executable(tmp_path, "cx")]


def write_one(work, scan=ONE_SCAN):
    report = Path(work, "cx_result.json")
    report.write_text(json.dumps({"scanID": scan}))
    return report


@pytest.fixture
def reject(monkeypatch, capture_dir, capsys):
    def unexpected(command, **_kwargs):
        pytest.fail(f"Invoked vendor before validating the request: {command}")

    def check(args, message):
        with monkeypatch.context() as patch:
            patch.setattr(subprocess, "Popen", unexpected)
            assert invoke(patch, *args) != 0
        output = capsys.readouterr()
        assert message in output.err and not output.out
        assert not list(capture_dir.iterdir())

    return check


def directory_link(link, target):
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True)
    else:
        link.symlink_to(os.path.relpath(target, link.parent), target_is_directory=True)


@pytest.mark.cross_platform
def test_refuses_profile_routed_through_the_checkout(one_args, tmp_path, monkeypatch, reject):
    source = Path.cwd()
    installed = tmp_path / "installed"
    installed.mkdir()
    (installed / "profile.yaml").touch()
    checkout_link = source / "active"
    selected = tmp_path / "selected"
    directory_link(checkout_link, installed)
    directory_link(selected, checkout_link)
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
    with pytest.raises(ValueError, match="outside the source checkout"):
        collector.installed_file(str(profile), source)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CX_CONFIG_FILE_PATH", str(profile))
    reject(["--source-root", str(source), *one_args], "CX_CONFIG_FILE_PATH")

    monkeypatch.setenv("TMPDIR", str(selected))
    monkeypatch.setattr(tempfile, "tempdir", None)
    monkeypatch.setattr(
        tempfile, "mkdtemp", lambda **kwargs: pytest.fail("created a checkout-selected temp")
    )
    with pytest.raises(ValueError, match="temporary directory outside"):
        collector.create_capture(source)


@pytest.mark.cross_platform
def test_checkout_git_marker_does_not_follow_links(capture_dir, tmp_path, monkeypatch):
    source = Path.cwd()
    marker = source / ".git"
    directory_link(marker, tmp_path)
    original_stat = Path.stat

    def guarded_stat(path, *args, **kwargs):
        if path == marker or marker in path.parents:
            assert path == marker and not kwargs.get("follow_symlinks", True)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", guarded_stat)
    assert collector.source_root(source) == source


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
    jar, config = tmp_path / "Cx Flow.jar", tmp_path / "private config,west.yml"
    cxflow_jar(jar)
    config.touch()
    return [
        "cxsast",
        "1234",
        "--team",
        "/CxServer/Masse Team/",
        "--project",
        "Example Project",
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
def test_refuses_unknown_or_unsupported_scan_selection(version, main, cxsast_args, reject):
    jar = Path(cxsast_args[cxsast_args.index("--jar") + 1])
    cxflow_jar(jar, version=version, main=main)
    reject(cxsast_args, "scoped CxSAST XML export")


def direct_and_symlink(target, alias):
    yield target
    if os.name != "nt":
        alias.symlink_to(target, target_is_directory=target.is_dir())
        yield alias


@pytest.mark.parametrize("option", ["--cx", "--java", "--jar", "--config"])
@pytest.mark.cross_platform
def test_refuses_vendor_files_inside_the_scan_source(
    option, one_args, cxsast_args, monkeypatch, tmp_path, reject
):
    source = Path.cwd()
    selected = source
    args = one_args if option == "--cx" else cxsast_args
    if option != "--cx":
        # Select a nested checkout while the tool lives in its enclosing repository.
        (source / ".git").mkdir()
        (source / ".git/HEAD").touch()
        selected = source / "src"
        selected.mkdir()
        (selected / ".git").write_text("gitdir: ../.git/modules/sub")
    monkeypatch.chdir(tmp_path)
    index = args.index(option) + 1
    target = source / Path(args[index]).name
    target.touch()
    for path in direct_and_symlink(target, tmp_path / "configured-file"):
        args[index] = str(path)
        reject(["--source-root", str(selected), *args], "outside the source checkout")


@pytest.mark.parametrize("suffix", [".cmd", ".BAT"])
@pytest.mark.cross_platform
def test_refuses_windows_batch_launchers(suffix, cxsast_args, monkeypatch, tmp_path, reject):
    launcher = tmp_path / f"java{suffix}"
    launcher.touch()
    monkeypatch.setattr(sys, "platform", "win32")
    for path in direct_and_symlink(launcher, tmp_path / "alias.exe"):
        cxsast_args[cxsast_args.index("--java") + 1] = str(path)
        reject(cxsast_args, "native Windows executable")


@pytest.mark.parametrize("setting", ["CX_CONFIG_FILE_PATH", "TMPDIR"])
@pytest.mark.cross_platform
def test_refuses_vendor_paths_that_resolve_into_source(
    setting, one_args, monkeypatch, tmp_path, reject
):
    selected = Path.cwd()
    target = selected / "private"
    if setting == "TMPDIR":
        target.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", None)
    else:
        target.touch()
    monkeypatch.chdir(tmp_path)
    for path in direct_and_symlink(target, tmp_path / "external-alias"):
        monkeypatch.setenv(setting, str(path))
        reject(["--source-root", str(selected), *one_args], "outside the source checkout")
    if target.is_dir():
        assert not list(target.iterdir())


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
        write_one(cwd)

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
    # Pin the symlink name for native multicall binaries that dispatch on argv[0].
    cx = executable(tmp_path, "launcher")
    if os.name != "nt":
        alias = tmp_path / "vendor cx"
        alias.symlink_to(cx)
        cx = str(alias)
    config = tmp_path / "my cx config"
    config.touch()
    monkeypatch.setenv("CX_CONFIG_FILE_PATH", str(config))
    loaders = ["LD_LIBRARY_PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"]
    checkout_bin = str(Path.cwd() / "bin")
    for name in ["PATH", *loaders]:
        monkeypatch.setenv(name, checkout_bin)
    request = ["--source-root", str(Path.cwd()), "one", ONE_SCAN.upper(), "--cx", cx]
    monkeypatch.chdir(tmp_path)

    def run(args, *, cwd, env, stdout, **kwargs):
        assert Path(cwd).is_relative_to(capture_dir)
        assert env["CX_CONFIG_FILE_PATH"] == str(config)
        assert {"PATH", *loaders}.isdisjoint(env)
        assert tuple(args[:3]) == (cx, "results", "show")
        assert dict(zip(args[3::2], args[4::2], strict=True)) == {
            "--config-file-path": str(config),
            "--scan-id": ONE_SCAN.upper(),
            "--report-format": "json",
            "--output-path": cwd,
            "--output-name": "cx_result",
        }
        stdout.write("retrieved existing scan\n")
        write_one(cwd)  # Servers can return a different case for the same UUID.
        Path(cwd, "vendor-log.txt").write_text("vendor diagnostic")

    mock_vendor(monkeypatch, run)
    reports = []
    for _ in range(2):
        assert invoke(monkeypatch, *request) == 0
        output = capsys.readouterr()
        assert "retrieved existing scan" in output.err
        saved = Path(output.out.rstrip("\n"))
        assert saved.is_absolute() and saved.parent.parent == capture_dir
        assert list(saved.parent.iterdir()) == [saved]
        assert json.loads(saved.read_text())["scanID"] == ONE_SCAN
        if os.name == "posix":
            assert saved.stat().st_mode & 0o777 == 0o600
            assert saved.parent.stat().st_mode & 0o777 == 0o700
        reports.append(saved.parent)
    assert reports[0] != reports[1]
    assert all(os.environ[name] == checkout_bin for name in loaders)


@pytest.mark.parametrize("failure", ["wrong scan", "invalid JSON", "missing file", "nonzero exit"])
@pytest.mark.cross_platform
def test_one_discards_failed_exports(failure, capture_dir, one_args, monkeypatch, capsys):
    def run(args, *, cwd, **kwargs):
        if failure == "wrong scan":
            write_one(cwd, "00000000-0000-4000-8000-000000000002")
        if failure in {"invalid JSON", "nonzero exit"}:
            (Path(cwd) / "cx_result.json").write_text('{"partial":')
        if failure == "nonzero exit":
            kwargs["stdout"].write("vendor error while fetching the scan\n")
        return 1 if failure == "nonzero exit" else 0

    mock_vendor(monkeypatch, run)
    assert invoke(monkeypatch, *one_args) != 0
    output = capsys.readouterr()
    assert not output.out
    if failure == "nonzero exit":
        assert "vendor error while fetching the scan" in output.err
    assert not list(capture_dir.iterdir())


@pytest.mark.cross_platform
def test_one_refuses_relative_config_before_vendor_invocation(one_args, monkeypatch, reject):
    monkeypatch.setenv("CX_CONFIG_FILE_PATH", "my-config.yaml")
    reject(one_args, "CX_CONFIG_FILE_PATH to a trusted absolute path")


@pytest.mark.parametrize("use_env_credentials", [False, True])
@pytest.mark.cross_platform
def test_cxsast_collects_selected_scan_with_xml_tracker(
    cxsast_args, use_env_credentials, capture_dir, monkeypatch, capsys
):
    credentials = {
        "CHECKMARX_USERNAME": "synthetic-user",
        "CHECKMARX_PASSWORD": "synthetic-password",
        "CHECKMARX_CLIENT_SECRET": "synthetic-client-secret",
    }
    # Competing JVM, Spring and vendor settings must not redirect the chosen profile.
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-javaagent:/checkout/agent.jar")
    monkeypatch.setenv("SPRING_MAIN_SOURCES", "file:/checkout/beans.xml")
    monkeypatch.setenv("CHECKMARX_BASE_URL", "https://unselected.invalid")
    for name, value in credentials.items():
        monkeypatch.setenv(name, value)
    if use_env_credentials:
        cxsast_args.append("--use-env-credentials")

    def run(args, *, cwd, env, **kwargs):
        allowed = {name: str(cwd) for name in ("TMP", "TEMP", "TMPDIR")}
        if os.name == "nt":
            allowed["SystemRoot"] = os.environ["SystemRoot"]
        else:
            allowed["LC_CTYPE"] = "UTF-8" if sys.platform == "darwin" else "C.UTF-8"
        if use_env_credentials:
            allowed.update(credentials)
        assert env == allowed
        config = Path(cxsast_args[cxsast_args.index("--config") + 1])
        assert args[0] == cxsast_args[cxsast_args.index("--java") + 1]
        assert args[args.index("-jar") + 1] == cxsast_args[cxsast_args.index("--jar") + 1]
        assert {
            f"-Djava.io.tmpdir={cwd}",
            f"-DLOG_PATH={cwd}",
            "-Dfile.encoding=UTF-8",
            f"--spring.config.location={config.as_uri()}",
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
            "--checkmarx.cx-branch=false",
            "--checkmarx.preserve-xml=true",
            f"--cx-xml.data-folder={cwd}",
            "--cx-xml.file-name-format=checkmarx-results.xml",
        } <= set(args)
        assert "--scan" not in args
        Path(cwd, "checkmarx-results.xml").write_text(CXSAST_XML)

    mock_vendor(monkeypatch, run)
    assert invoke(monkeypatch, *cxsast_args) == 0
    saved = Path(capsys.readouterr().out.strip())
    assert saved.is_relative_to(capture_dir) and saved.read_text() == CXSAST_XML


@pytest.mark.parametrize(
    "before, after",
    [
        ("1234", "5678"),
        ("Example Project", "Other Project"),
        ("Masse Team", "Other Team"),
        ("Masse Team", "Maße Team"),
        (' TeamFullPathOnReportDate="CXSERVER\\Masse Team"', ""),
        ("/>", ""),
    ],
    ids=["scan", "project", "team", "expanded-team", "missing-team", "invalid-xml"],
)
@pytest.mark.cross_platform
def test_cxsast_discards_invalid_or_mismatched_xml(
    cxsast_args, before, after, capture_dir, monkeypatch, capsys
):
    def run(args, *, cwd, **kwargs):
        Path(cwd, "checkmarx-results.xml").write_text(
            CXSAST_XML.replace(before, after), encoding="utf-8"
        )

    mock_vendor(monkeypatch, run)
    assert invoke(monkeypatch, *cxsast_args) != 0
    assert not capsys.readouterr().out
    assert not list(capture_dir.iterdir())


@pytest.mark.native_macos
@pytest.mark.skipif(os.name != "posix", reason="exercises the Unix Java launcher")
def test_java_receives_team_and_project_names_in_the_cxsast_environment(tmp_path):
    java = shutil.which("java")
    if not java:
        pytest.skip("requires a Java runtime")
    env = collector.cxsast_environment(str(tmp_path))
    modules = subprocess.run([java, "--list-modules"], env=env, capture_output=True)
    compiler = re.search(rb"^jdk\.compiler@(\d+)", modules.stdout, re.MULTILINE)
    if not compiler or int(compiler[1]) < 11:
        pytest.skip("the Java source-file probe requires a JDK 11+ compiler module")
    probe = tmp_path / "Names.java"
    probe.write_text(
        """import java.nio.file.*;
import java.util.Arrays;

class Names {
    public static void main(String[] args) throws Exception {
        Files.write(Path.of("arguments.txt"), Arrays.asList(args));
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
def test_excludes_source_by_filesystem_identity(monkeypatch, reject):
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
    args = ["one", ONE_SCAN, "--cx", str(alias / Path(checkout_file).name)]
    reject(["--source-root", str(source), *args], "outside the source checkout")


@pytest.mark.parametrize("scan_id", ["?limit=1", ONE_SCAN.replace("-", ""), ONE_SCAN + "\n"])
@pytest.mark.cross_platform
def test_one_rejects_invalid_uuid_before_vendor_lookup(scan_id, one_args, reject):
    one_args[1] = scan_id
    reject(one_args, "scan UUID")


@pytest.mark.parametrize(
    ("option", "name"),
    [
        ("--team", ""),
        ("--team", " / \\ \t/"),
        ("--project", "\t "),
    ],
)
@pytest.mark.cross_platform
def test_cxsast_rejects_unselected_scope_before_vendor_lookup(option, name, cxsast_args, reject):
    cxsast_args[cxsast_args.index(option) + 1] = name
    reject(cxsast_args, "CxSAST team path and project")


@pytest.mark.skipif(os.name != "posix", reason="exercises POSIX termination signals")
@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP", "SIGINT"])
@pytest.mark.parametrize("when", ["during launch", "while waiting", "after vendor exit"])
@pytest.mark.native_macos
def test_cancellation_reaps_vendor_and_helper(
    when, name, one_args, capture_dir, monkeypatch, capfd
):
    popen = subprocess.Popen
    child = None
    signum = getattr(signal, name)
    vendor = """
import os, signal, subprocess, sys, time
from pathlib import Path

subprocess.Popen([sys.executable, "-I", "-S", "-c", "import sys; sys.stdin.read()"])
Path("cx_result.json").write_text("partial")
"""
    if when == "while waiting":
        vendor += f"os.kill(os.getppid(), signal.{name})\n"
    if when != "after vendor exit":
        vendor += "time.sleep(30)"

    def start_child(_command, **kwargs):
        nonlocal child
        kwargs.update(stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        child = popen([sys.executable, "-I", "-S", "-c", vendor], **kwargs)
        if when == "after vendor exit":
            assert child.wait(timeout=10) == 0
        if when != "while waiting":
            signal.raise_signal(signum)
        return child

    monkeypatch.setattr(subprocess, "Popen", start_child)
    previous = signal.signal(signum, lambda *_: None)
    try:
        assert invoke(monkeypatch, *one_args) == 128 + signum
        assert child.returncode == (0 if when == "after vendor exit" else -signal.SIGKILL)
        # The helper inherits stdout. EOF proves it exited along with the vendor.
        assert select.select([child.stdout], [], [], 5)[0] and child.stdout.read(1) == b""
        assert not capfd.readouterr().out and not list(capture_dir.iterdir())
    finally:
        signal.signal(signum, previous)
        if child is not None:
            child.stdin.close()  # Release the helper even if cancellation failed.
            child.kill()
            child.wait()
            child.stdout.close()


@pytest.mark.cross_platform
def test_preserves_an_ignored_interrupt(capture_dir, one_args, monkeypatch):
    def run(args, *, cwd, **kwargs):
        assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
        write_one(cwd)

    mock_vendor(monkeypatch, run)
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        assert invoke(monkeypatch, *one_args) == 0
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
        assert ";;;WD)" not in dacl(write_one(work))

    args = SimpleNamespace(product="one", scan_id=ONE_SCAN, cx="unused")
    collector.collect(args, None, run)
    assert ";;;WD)" not in dacl(Path(capsys.readouterr().out.strip()))


@pytest.mark.cross_platform
@pytest.mark.parametrize("login", ["named-profile", "default-profile", "env-oauth", "env-key"])
def test_one_keeps_credentials_with_the_selected_login(
    one_args, capture_dir, tmp_path, monkeypatch, login
):
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
    for proxy in ["CX_HTTP_PROXY", "http_proxy", "HTTP_PROXY"]:
        monkeypatch.setenv(proxy, "http://proxy.example.invalid")
    monkeypatch.setenv("CX_KEYRING_MODE", "required")
    if login == "named-profile":
        monkeypatch.setenv("CX_CONFIG_FILE_PATH", str(selected))
    if login == "default-profile":
        monkeypatch.delenv("CX_CLIENT_ID")
    if login in {"named-profile", "env-key"}:
        monkeypatch.setenv("CX_APIKEY", "synthetic-key")

    def run(command, *, cwd, env, **_kwargs):
        assert command[command.index("--config-file-path") + 1] == env["CX_CONFIG_FILE_PATH"]
        assert {"HTTP_PROXY", "http_proxy", "CX_HTTP_PROXY"}.isdisjoint(env)
        if login in {"named-profile", "default-profile"}:
            assert oauth.keys().isdisjoint(env) and "CX_APIKEY" not in env
            assert env.get("CX_CONFIG_FILE_PATH") == (
                str(selected)
                if login == "named-profile"
                else str(Path.home() / ".checkmarx" / "checkmarxcli.yaml")
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
        write_one(cwd)

    mock_vendor(monkeypatch, run)
    assert invoke(monkeypatch, *one_args) == 0


@pytest.mark.cross_platform
@pytest.mark.parametrize("reader_open", [True, False])
def test_report_path_handoff_uses_utf8_on_a_redirected_pipe(
    capture_dir, monkeypatch, one_args, reader_open
):
    temp = capture_dir / "東京"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    monkeypatch.setenv("CX_CONFIG_FILE_PATH", str(capture_dir / "profile.yaml"))

    def export(_command, *, cwd, **_kwargs):
        write_one(cwd)

    mock_vendor(monkeypatch, export)

    read_fd, write_fd = os.pipe()
    with os.fdopen(read_fd, "rb") as reader, os.fdopen(write_fd, "wb", buffering=0) as writer:
        with io.TextIOWrapper(writer, encoding="cp1252") as stdout, monkeypatch.context() as patch:
            patch.setattr(sys, "stdout", stdout)
            if not reader_open:
                reader.close()
            assert invoke(patch, *one_args) == (0 if reader_open else 1)
        if reader_open:
            saved = next(temp.glob("checkmarx-report-*/cx_result.json"))
            assert reader.read() == f"{saved}\n".encode("utf-8")
        else:
            assert not list(temp.iterdir())
