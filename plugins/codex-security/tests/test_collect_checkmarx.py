import json
import os
import runpy
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
    path.touch()
    path.chmod(0o755)
    return str(path)


@pytest.mark.parametrize("product", ["one", "cxsast"])
def test_refuses_launchers_inside_the_scan_source(
    product, capture_dir, monkeypatch, tmp_path, capsys
):
    source = Path.cwd()
    tools = source / "tools"
    tools.mkdir()
    if product == "one":
        request = ["one", ONE_SCAN, "--cx", executable(tools, "cx")]
    else:
        # A checkout may be entered from a subdirectory, with its tool elsewhere in the tree.
        (source / ".git").mkdir()
        (source / ".git" / "HEAD").touch()
        subdir = source / "src"
        subdir.mkdir()
        monkeypatch.chdir(subdir)
        request = ["cxsast", "1234", "--java", executable(tools, "java")]
    assert invoke(monkeypatch, *request) != 0
    assert "outside the source checkout" in capsys.readouterr().err
    if os.name != "nt":
        alias = tmp_path / "configured-launcher"
        alias.symlink_to(request[-1])
        request[-1] = str(alias)
        assert invoke(monkeypatch, *request) != 0
        assert "outside the source checkout" in capsys.readouterr().err
    assert not list(capture_dir.iterdir())


def test_one_collects_exact_scan_to_a_fresh_private_path(
    capture_dir, monkeypatch, tmp_path, capsys
):
    # Preserve the selected name for multicall launchers that dispatch on argv[0].
    if os.name == "nt":
        cx = executable(tmp_path, "vendor cx")
    else:
        cx = str(tmp_path / "vendor cx")
        Path(cx).symlink_to(executable(tmp_path, "launcher"))
    config = tmp_path / "my cx config"
    config.touch()
    monkeypatch.setenv("CX_CONFIG_FILE_PATH", str(config))
    requested = ["one", ONE_SCAN, "--cx", cx]
    reports = []

    def run(args, *, cwd, **kwargs):
        out = Path(cwd)
        assert out.is_relative_to(capture_dir)
        assert kwargs.get("env", os.environ)["CX_CONFIG_FILE_PATH"] == str(config)
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
    "result", ["selected", "scan", "project", "team", "missing team", "invalid XML"]
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
    jar = tmp_path / "Cx Flow.jar"
    config = tmp_path / "private config.yml"
    jar.touch()
    config.touch()

    def run(args, *, cwd, **kwargs):
        args = list(map(str, args))
        assert args[:6] == [
            java,
            f"-Djava.io.tmpdir={cwd}",
            f"-DLOG_PATH={cwd}",
            "-Dfile.encoding=UTF-8",
            "-jar",
            str(jar),
        ]
        assert {
            f"--spring.config.location={config}",
            "--project",
            "--scanId=1234",
            "--cx-team=/CxServer/Example Team",
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
                r"cxserver\Other Team" if result == "team" else r"CXSERVER\Example Team"
            )
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
        "/CxServer/Example Team/",
        "--project",
        "Example Project",
    )
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
