import json
import os
import runpy
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.etree.ElementTree import Element, ElementTree

import pytest

pytestmark = pytest.mark.cross_platform
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
    monkeypatch.delenv("CX_CONFIG_FILE_PATH", raising=False)
    return directory


def invoke(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), *args])
    try:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    except SystemExit as exit:
        return exit.code
    return 0


def executable(directory, name):
    path = directory / (f"{name}.exe" if os.name == "nt" else name)
    shutil.copy(shutil.which("true", path=os.defpath) or sys.executable, path)
    return str(path)


@pytest.fixture
def cxsast_args(tmp_path):
    jar, config = tmp_path / "cx-flow.jar", tmp_path / "application.yml"
    jar.touch()
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


@pytest.mark.parametrize("option", ["--cx", "--java", "--jar", "--config"])
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
        [sys.executable, "-I", str(SCRIPT), "one", ONE_SCAN, "--cx", str(cx)],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0 and not marker.exists()
    assert "installed native executable" in result.stderr
    assert not list(capture_dir.iterdir())


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
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-Xmx256m")
    tools = tmp_path / "external tools"
    tools.mkdir()
    checkout_bin = Path.cwd() / "bin"
    checkout_bin.mkdir()
    monkeypatch.setenv("PATH", os.pathsep.join(["bin", str(checkout_bin), str(tools)]))
    selected = Path.cwd()
    monkeypatch.chdir(tmp_path)
    requested = ["--source-root", str(selected), "one", ONE_SCAN, "--cx", cx]
    reports = []

    def run(args, *, cwd, **kwargs):
        out = Path(cwd)
        assert out.is_relative_to(capture_dir)
        assert kwargs["env"]["CX_CONFIG_FILE_PATH"] == str(config)
        assert kwargs["env"]["JAVA_TOOL_OPTIONS"] == "-Xmx256m"
        assert kwargs["env"]["PATH"] == str(tools.resolve())
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

    monkeypatch.setattr(subprocess, "run", run)
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


@pytest.mark.parametrize("failure", ["wrong scan", "invalid JSON", "missing file", "nonzero exit"])
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

    monkeypatch.setattr(subprocess, "run", run)
    assert invoke(monkeypatch, "one", ONE_SCAN, "--cx", cx) != 0
    output = capsys.readouterr()
    assert not output.out
    if failure == "nonzero exit":
        assert "vendor error while fetching the scan" in output.err
    assert not list(capture_dir.iterdir())


@pytest.mark.parametrize("refusal", ["opt-in disabled", "relative config"])
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

    monkeypatch.setattr(subprocess, "run", unexpected)
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
    jvm_options = {
        "JDK_JAVA_OPTIONS": "-Xmx256m",
        "JAVA_TOOL_OPTIONS": f'-javaagent:"{Path.cwd() / "coverage.jar"}"',
        "_JAVA_OPTIONS": f"-DLOGBACK_ROLLINGPOLICY_FILE_NAME_PATTERN={Path.cwd()}/escape.%i.gz",
        "OPENJ9_JAVA_OPTIONS": "-Dfile.encoding=windows-1252",
        "IBM_JAVA_OPTIONS": "-Xmx256m",
    }
    for name, value in jvm_options.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("CX_PROFILE_SECRET", "synthetic-profile-value")
    jar = tmp_path / "Cx Flow.jar"
    config = tmp_path / "private config,west.yml"
    jar.touch()
    config.touch()

    def run(args, *, cwd, **kwargs):
        args = list(map(str, args))
        assert jvm_options.keys().isdisjoint(kwargs["env"])
        assert kwargs["env"]["CX_PROFILE_SECRET"] == "synthetic-profile-value"
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

    monkeypatch.setattr(subprocess, "run", run)
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
    assert {name: os.environ[name] for name in jvm_options} == jvm_options
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
    assert invoke(monkeypatch, "one", ONE_SCAN, "--cx", str(alias / Path(checkout_file).name)) != 0
    assert "outside the source checkout" in capsys.readouterr().err


@pytest.mark.parametrize(
    "lookup", ["libc", "passwd", "HOME"] if sys.platform == "linux" else ["libc"]
)
@pytest.mark.skipif(os.name == "nt", reason="exercises Unix account home lookup")
def test_one_checks_default_profile_from_account_home(
    lookup, capture_dir, monkeypatch, tmp_path, capsys
):
    import pwd
    from types import SimpleNamespace

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
        passwd.write_bytes(entry if lookup == "passwd" else b"")
        original_open = Path.open

        def open_file(path, *args, **kwargs):
            return original_open(passwd if str(path) == "/etc/passwd" else path, *args, **kwargs)

        monkeypatch.setattr(Path, "open", open_file)

    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("unexpected cx invocation"))
    assert invoke(monkeypatch, "one", ONE_SCAN, "--cx", executable(tmp_path, "cx")) != 0
    assert "CX_CONFIG_FILE_PATH" in capsys.readouterr().err
    assert not list(capture_dir.iterdir())


def test_one_accepts_the_same_scan_uuid_in_server_spelling(
    capture_dir, monkeypatch, tmp_path, capsys
):
    scan = "abcdef12-0000-4000-8000-123456789abc"

    def run(args, *, cwd, **kwargs):
        assert args[args.index("--scan-id") + 1] == scan.upper()
        (Path(cwd) / "cx_result.json").write_text(json.dumps({"scanID": scan}))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", run)
    assert invoke(monkeypatch, "one", scan.upper(), "--cx", executable(tmp_path, "cx")) == 0
    saved = Path(capsys.readouterr().out.strip())
    assert json.loads(saved.read_text())["scanID"] == scan


@pytest.mark.parametrize("scan_id", ["?limit=1", ONE_SCAN.replace("-", ""), ONE_SCAN + "\n"])
def test_one_rejects_invalid_uuid_before_vendor_lookup(
    scan_id, capture_dir, monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("unexpected cx invocation"))
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
def test_cxsast_rejects_unselected_scope_before_vendor_lookup(
    option, name, cxsast_args, capture_dir, monkeypatch, capsys
):
    cxsast_args[cxsast_args.index(option) + 1] = name
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: pytest.fail("unexpected CxFlow invocation")
    )
    assert invoke(monkeypatch, *cxsast_args) != 0
    assert "CxSAST team path and project" in capsys.readouterr().err
    assert not list(capture_dir.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="exercises POSIX SIGTERM")
def test_sigterm_reaps_vendor_and_removes_partial_report(capture_dir, monkeypatch, tmp_path):
    # Bash as the native test client reads its first argument ("results") from PATH.
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("requires Bash to simulate an active native vendor process")
    (tmp_path / "results").write_text(
        "echo partial >cx_result.json\n"
        'echo $$ >"$VENDOR_PID_FILE"\n'
        'kill -TERM "$PPID"\n'
        "exec sleep 30\n"
    )
    pid_file = tmp_path / "vendor.pid"
    monkeypatch.setenv("VENDOR_PID_FILE", str(pid_file))
    monkeypatch.setenv("TMPDIR", str(capture_dir))
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path), os.environ["PATH"]]))
    result = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "one", ONE_SCAN, "--cx", bash],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    pid = int(pid_file.read_text())
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pass
    else:
        os.kill(pid, signal.SIGKILL)
        pytest.fail("vendor survived collector cancellation")
    assert result.returncode == 128 + signal.SIGTERM
    assert not result.stdout
    assert not list(capture_dir.iterdir())
