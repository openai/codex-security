from contextlib import nullcontext
from pathlib import Path
from runpy import run_path
from xml.etree.ElementTree import ParseError

import pytest

CHECK = Path(__file__).with_name("require_native_python_report.py")
PASSING = "<testsuite><testcase/></testsuite>"


@pytest.mark.parametrize(
    ("report", "outcome"),
    [
        (None, pytest.raises(FileNotFoundError, match="python.xml")),
        ("", pytest.raises(ParseError)),
        ("<testsuite/>", pytest.raises(SystemExit, match="No native platform tests ran")),
        (
            "<testsuite><testcase/><testcase><skipped/></testcase></testsuite>",
            pytest.raises(SystemExit, match="Native platform tests must run without skips"),
        ),
        (PASSING, nullcontext()),
    ],
)
def test_native_python_report(tmp_path, monkeypatch, report, outcome):
    monkeypatch.chdir(tmp_path)
    reports = Path("reports")
    reports.mkdir()
    (reports / "python-stale.xml").write_text(PASSING)
    if report is not None:
        (reports / "python.xml").write_text(report)
    with outcome:
        run_path(str(CHECK), run_name="__main__")
