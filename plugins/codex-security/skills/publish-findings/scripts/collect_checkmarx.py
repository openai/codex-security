"""Collect a selected existing scan using the user's installed Checkmarx tools."""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.parsers import expat


def source_root(target: Path | None) -> Path | None:
    if target is not None and (not target.is_absolute() or not target.is_dir()):
        raise ValueError("Select an existing absolute source directory.")
    source = (target or Path.cwd()).resolve()
    root = source if target is not None else None
    for parent in (source, *source.parents):
        if (parent / ".git").is_file() or (parent / ".git" / "HEAD").is_file():
            root = parent
    return root


def in_source(path: Path, source: Path | None) -> bool:
    if source is None:
        return False
    invocation = path.parent.resolve() / path.name
    for candidate in (path, invocation, path.resolve()):
        for ancestor in (candidate, *candidate.parents):
            if ancestor.exists() and ancestor.samefile(source):
                return True
    return False


def installed_file(value: str, source: Path | None) -> Path:
    path = Path(value)
    if not path.is_absolute() or not path.is_file():
        raise ValueError("expected an absolute path to an existing file")
    if in_source(path, source):
        raise ValueError("use an installed file outside the source checkout")
    # Invoke the selected name for native multicall binaries.
    return path.parent.resolve() / path.name


def installed_launcher(value: str, source: Path | None) -> Path:
    path = installed_file(value, source)
    if sys.platform == "win32" and (
        path.suffix.lower() not in {".exe", ".com"}
        or path.resolve().suffix.lower() in {".bat", ".cmd"}
    ):
        raise ValueError("use a native Windows executable (.exe or .com)")
    with path.open("rb") as image:
        magic = image.read(4)
        if sys.platform == "win32":
            # The DOS header points to the PE signature.
            image.seek(0x3C)
            pe_offset = int.from_bytes(image.read(4), "little")
            image.seek(pe_offset)
            native = magic.startswith(b"MZ") and image.read(4) == b"PE\0\0"
        elif sys.platform == "darwin":
            # 32/64-bit thin and universal Mach-O, in either byte order.
            native = any(
                int.from_bytes(magic, order) in {0xFEEDFACE, 0xFEEDFACF, 0xCAFEBABE, 0xCAFEBABF}
                for order in ("big", "little")
            )
        else:
            native = magic == b"\x7fELF"
    if not native:
        raise ValueError("use the installed native executable for cx or java")
    return path


def vendor_environment(source: Path | None) -> dict[str, str]:
    # Let the native loader use installed libraries when starting a vendor process.
    env = {
        name: value
        for name, value in os.environ.items()
        if os.name == "nt" or not name.startswith(("LD_", "DYLD_"))
    }
    entries = []
    for entry in os.get_exec_path(env):
        if os.name == "nt" and entry.startswith('"') and entry.endswith('"'):
            entry = entry[1:-1]
        path = Path(entry)
        if path.is_absolute() and path.is_dir() and not in_source(path, source):
            entries.append(str(path.resolve()))
    env["PATH"] = os.pathsep.join(entries)
    return env


def one_default_profiles() -> set[Path]:
    # Both cx configuration and its keyring resolver use Go's os/user.Current.
    if os.name == "nt":
        import ctypes.wintypes

        get_profile = ctypes.windll.userenv.GetUserProfileDirectoryW
        token = ctypes.wintypes.HANDLE(-4)  # GetCurrentProcessToken() pseudo-handle
        size = ctypes.wintypes.DWORD()
        get_profile(token, None, ctypes.byref(size))
        directory = ctypes.create_unicode_buffer(size.value)
        if not get_profile(token, directory, ctypes.byref(size)):
            raise ctypes.WinError()
        homes = {Path(directory.value)}
    else:
        import pwd

        try:
            homes = {Path(pwd.getpwuid(os.getuid()).pw_dir)}
        except KeyError:
            homes = {Path.home()}
        if sys.platform == "linux":
            # Released cx uses pure Go's local passwd lookup. A libc-enabled build may
            # instead resolve a directory-service account. Leave the choice to cx.
            uid = str(os.getuid()).encode()
            local_home = None
            try:
                with Path("/etc/passwd").open("rb") as passwd:
                    for row in passwd:
                        fields = row.rstrip().split(b":")
                        if len(fields) >= 6 and fields[2] == uid:
                            local_home = Path(os.fsdecode(fields[5]))
                            break
            except OSError:
                # Without a readable passwd file, Go's static lookup falls back to HOME.
                pass
            homes.add(local_home if local_home is not None else Path.home())
    return {home / ".checkmarx" / "checkmarxcli.yaml" for home in homes}


def verify_one(report: Path, scan_id: str) -> None:
    with report.open(encoding="utf-8-sig") as stream:
        data = json.load(stream)
    reported = data.get("scanID") if isinstance(data, dict) else None
    if (
        not isinstance(reported, str)
        or not reported.isascii()
        or reported.lower() != scan_id.lower()
    ):
        raise ValueError("The Checkmarx One report does not match the requested scan ID.")


def team_path(value: str) -> str:
    path = value.replace("\\", "/").strip("/")
    return "".join(char.lower() if char.isascii() else char for char in path)


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


def collect(args: argparse.Namespace, source: Path | None) -> None:
    temp = Path(tempfile.gettempdir())
    if in_source(temp, source):
        raise ValueError(
            "Select a temporary directory outside the source checkout (TMPDIR or TEMP)."
        )
    env = vendor_environment(source)
    output = Path(tempfile.mkdtemp(prefix="checkmarx-report-", dir=temp)).resolve()
    try:
        with tempfile.TemporaryDirectory(dir=output) as work:
            if args.product == "one":
                configured = env.get("CX_CONFIG_FILE_PATH")
                profiles = {Path(configured)} if configured else one_default_profiles()
                if any(not path.is_absolute() or in_source(path, source) for path in profiles):
                    raise ValueError(
                        "Set CX_CONFIG_FILE_PATH to a trusted absolute path outside the source checkout. "
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
                # Start CxFlow without JVM agents or logging overrides from the build shell.
                for name in (
                    "JDK_ALTERNATE_VM",
                    "JDK_JAVA_OPTIONS",
                    "JAVA_TOOL_OPTIONS",
                    "_JAVA_OPTIONS",
                    "OPENJ9_JAVA_OPTIONS",
                    "IBM_JAVA_OPTIONS",
                ):
                    env.pop(name, None)
                team = args.team.rstrip("/\\")
                report = Path(work, "checkmarx-results.xml")
                command = [
                    str(args.java),
                    f"-Djava.io.tmpdir={work}",
                    f"-DLOG_PATH={work}",
                    "-Dfile.encoding=UTF-8",
                    "-jar",
                    str(args.jar),
                    f"--spring.config.location={args.config.as_uri()}",
                    "--spring.config.additional-location=",
                    "--spring.config.import=",
                    "--logging.config=classpath:logback-spring.xml",
                    f"--logging.file.path={work}",
                    f"--logging.file.name={Path(work, 'cx-flow.log')}",
                    f"--logging.logback.rollingpolicy.file-name-pattern={Path(work, 'cx-flow.%d{yyyy-MM-dd}.%i.gz')}",
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
            result = subprocess.run(
                command, cwd=work, env=env, stdin=subprocess.DEVNULL, stdout=sys.stderr
            )
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
        print(saved, flush=True)
    except BaseException:
        shutil.rmtree(output)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, help="absolute source directory to protect")
    products = parser.add_subparsers(dest="product", required=True)
    one = products.add_parser("one", help="export an existing Checkmarx One scan")
    one.add_argument("scan_id")
    one.add_argument("--cx", required=True)
    cxsast = products.add_parser("cxsast", help="retrieve an existing CxSAST scan with CxFlow")
    cxsast.add_argument("scan_id", type=int)
    cxsast.add_argument("--java", required=True)
    cxsast.add_argument("--jar", required=True)
    cxsast.add_argument("--config", required=True)
    cxsast.add_argument("--team", required=True)
    cxsast.add_argument("--project", required=True)
    args = parser.parse_args()
    if os.environ.get("CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS") != "1":
        parser.error("Set CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1 to enable external imports.")
    if args.product == "one":
        if not re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", args.scan_id, re.I | re.ASCII
        ):
            parser.error("Select a Checkmarx One scan UUID in hyphenated form.")
    else:
        if args.scan_id <= 0:
            parser.error("Select an existing positive CxSAST scan ID.")
        if not re.search(r"[^\s/\\]", args.team) or not args.project.strip():
            parser.error("Select a nonblank CxSAST team path and project.")

    def terminate(signum, _frame):
        # Unwind subprocess.run so it kills and reaps the vendor before capture cleanup.
        raise SystemExit(128 + signum)

    signals = [signal.SIGTERM]
    if os.name == "posix" and signal.getsignal(signal.SIGHUP) != signal.SIG_IGN:
        signals.append(signal.SIGHUP)
    previous = {number: signal.signal(number, terminate) for number in signals}
    try:
        source = source_root(args.source_root)
        if args.product == "one":
            args.cx = installed_launcher(args.cx, source)
        else:
            args.java = installed_launcher(args.java, source)
            args.jar = installed_file(args.jar, source)
            args.config = installed_file(args.config, source)
        collect(args, source)
    except (ValueError, OSError, expat.ExpatError) as error:
        print(error, file=sys.stderr)
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
