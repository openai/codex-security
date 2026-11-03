"""Collect a selected existing scan using the user's installed Checkmarx tools."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.parsers import expat


def installed_file(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or not path.is_file():
        raise argparse.ArgumentTypeError("expected an absolute path to an existing file")
    return path


def installed_launcher(value: str) -> Path:
    selected = installed_file(value)
    source = Path.cwd().resolve()
    for parent in (source, *source.parents):
        if (parent / ".git").is_file() or (parent / ".git" / "HEAD").is_file():
            source = parent
            break
    # Inspect the resolved target, but invoke the selected name for multicall shims.
    launcher = selected.parent.resolve() / selected.name
    if any(path.is_relative_to(source) for path in (selected, launcher, launcher.resolve())):
        raise argparse.ArgumentTypeError("use an installed launcher outside the source checkout")
    return launcher


def verify_one(report: Path, scan_id: str) -> None:
    with report.open(encoding="utf-8-sig") as stream:
        data = json.load(stream)
    if not isinstance(data, dict) or data.get("scanID") != scan_id:
        raise ValueError("The Checkmarx One report does not match the requested scan ID.")


def team_path(value: str) -> str:
    return value.replace("\\", "/").strip("/").casefold()


def verify_cxsast(report: Path, scan_id: str, project: str, team: str) -> None:
    parser = expat.ParserCreate()

    def check_root(name, attributes):
        if name != "CxXMLResults" or not attributes.get("ProjectId"):
            raise ValueError("Expected a CxSAST XML scan report.")
        if attributes.get("ScanId") != scan_id or attributes.get("ProjectName") != project:
            raise ValueError("The CxSAST report does not match the requested scan and project.")
        actual_team = attributes.get("TeamFullPathOnReportDate")
        if not actual_team or team_path(actual_team) != team_path(team):
            raise ValueError("The CxSAST report does not match the requested team.")
        parser.StartElementHandler = None

    parser.StartElementHandler = check_root
    with report.open("rb") as stream:
        parser.ParseFile(stream)


def collect(args: argparse.Namespace) -> Path:
    output = Path(tempfile.mkdtemp(prefix="checkmarx-report-")).resolve()
    try:
        with tempfile.TemporaryDirectory(dir=output) as work:
            if args.product == "one":
                config = os.environ.get("CX_CONFIG_FILE_PATH")
                if config and not Path(config).is_absolute():
                    raise ValueError(
                        "Set CX_CONFIG_FILE_PATH to a trusted absolute path. "
                        "The collector runs Checkmarx One from a private directory."
                    )
                report = Path(work, "cx_result.json")
                command = [
                    str(args.cx),
                    "results",
                    "show",
                    "--scan-id",
                    args.scan_id,
                    "--report-format",
                    "json",
                    "--output-path",
                    work,
                    "--output-name",
                    "cx_result",
                ]
            else:
                team = args.team.rstrip("/\\")
                report = Path(work, "checkmarx-results.xml")
                command = [
                    str(args.java),
                    f"-Djava.io.tmpdir={work}",
                    f"-DLOG_PATH={work}",
                    "-Dfile.encoding=UTF-8",
                    "-jar",
                    str(args.jar),
                    f"--spring.config.location={args.config}",
                    "--project",
                    f"--scanId={args.scan_id}",
                    f"--cx-team={team}",
                    f"--cx-project={args.project}",
                    f"--app={args.project}",
                    "--bug-tracker=CxXml",
                    "--cx-flow.bug-tracker-impl=CxXml",
                    "--cx-flow.enabled-vulnerability-scanners=sast",
                    "--cx-flow.preserve-project-name=true",
                    "--cx-flow.mail.notification=false",
                    "--cx-flow.filter-script=",
                    "--disable-break-build",
                    "--checkmarx.preserve-xml=true",
                    f"--cx-xml.data-folder={work}",
                    "--cx-xml.file-name-format=checkmarx-results.xml",
                ]
            # Reserve stdout for the report path and pass vendor diagnostics to stderr.
            result = subprocess.run(command, cwd=work, stdin=subprocess.DEVNULL, stdout=sys.stderr)
            if result.returncode:
                raise ValueError(f"The Checkmarx tool exited with status {result.returncode}.")
            if report.is_symlink() or not report.is_file():
                raise ValueError("The Checkmarx tool did not produce the requested report.")
            if args.product == "one":
                verify_one(report, args.scan_id)
            else:
                verify_cxsast(report, str(args.scan_id), args.project, args.team)
            report.chmod(0o600)
            saved = report.replace(output / report.name)
        return saved
    except BaseException:
        shutil.rmtree(output)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    products = parser.add_subparsers(dest="product", required=True)
    one = products.add_parser("one", help="export an existing Checkmarx One scan")
    one.add_argument("scan_id")
    one.add_argument("--cx", required=True, type=installed_launcher)
    cxsast = products.add_parser("cxsast", help="retrieve an existing CxSAST scan with CxFlow")
    cxsast.add_argument("scan_id", type=int)
    cxsast.add_argument("--java", required=True, type=installed_launcher)
    cxsast.add_argument("--jar", required=True, type=installed_file)
    cxsast.add_argument("--config", required=True, type=installed_file)
    cxsast.add_argument("--team", required=True)
    cxsast.add_argument("--project", required=True)
    args = parser.parse_args()
    if os.environ.get("CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS") != "1":
        parser.error("Set CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1 to enable external imports.")
    if args.product == "cxsast" and args.scan_id <= 0:
        parser.error("Select an existing positive CxSAST scan ID.")
    try:
        print(collect(args))
    except (ValueError, OSError, expat.ExpatError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
