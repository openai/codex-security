"""Collect a selected existing scan using the user's installed Checkmarx tools."""

import argparse
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import zipfile
from contextlib import suppress
from email.parser import BytesHeaderParser
from pathlib import Path
from xml.parsers import expat


def is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or (
        os.name == "nt" and info.st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT
    )


def source_root(target: Path | None) -> Path | None:
    if target is not None and (not target.is_absolute() or not target.is_dir()):
        raise ValueError("Select an existing absolute source directory.")
    source = (target or Path.cwd()).resolve()
    # A nested checkout or submodule is still part of the enclosing source tree.
    for parent in (*reversed(source.parents), source):
        marker = parent / ".git"
        try:
            info = marker.lstat()
            if stat.S_ISDIR(info.st_mode) and not is_link(info):
                info = (marker / "HEAD").lstat()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if stat.S_ISREG(info.st_mode) or is_link(info):
            return parent
    return source if target is not None else None


def in_source(path: Path, source: Path | None) -> bool:
    if source is None:
        return False
    if path.is_relative_to(source):
        return True
    identity = source.stat()
    current = Path()
    parts = list(reversed(path.absolute().parts))
    active_links = set()
    while parts:
        part = parts.pop()
        if isinstance(part, Path):
            # The link target's components have all been checked.
            active_links.remove(part)
            continue
        current = current.parent if part == ".." else current / part
        if current == source:
            return True
        try:
            info = current.lstat()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if os.path.samestat(info, identity):
            return True
        if is_link(info):
            if current in active_links:
                raise OSError(f"Symbolic link loop at {current}")
            active_links.add(current)
            parts.append(current)
            parts.extend(reversed(current.readlink().parts))
            current = current.parent
    return False


def installed_file(value: str, source: Path | None) -> Path:
    path = Path(value)
    if path.is_absolute() and in_source(path, source):
        raise ValueError("use an installed file outside the source checkout")
    if not path.is_absolute() or not path.is_file():
        raise ValueError("expected an absolute path to an existing file")
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


def check_cxflow_version(jar: Path) -> None:
    # Earlier CxFlow versions accept --scanId but silently retrieve the latest scan.
    advice = "Use a released CxFlow 1.6.37 or later, or supply a scoped CxSAST XML export."
    try:
        with zipfile.ZipFile(jar) as archive:
            manifest = BytesHeaderParser().parsebytes(archive.read("META-INF/MANIFEST.MF"))
            metadata = archive.read("META-INF/build-info.properties").decode("utf-8")
    except (KeyError, UnicodeDecodeError, zipfile.BadZipFile) as error:
        raise ValueError(
            f"Could not read the CxFlow release metadata: {error}. {advice}"
        ) from error
    properties = dict(line.split("=", 1) for line in metadata.splitlines() if "=" in line)
    if (
        manifest.get("Start-Class") != "com.checkmarx.flow.CxFlowApplication"
        or properties.get("build.group") != "com.checkmarx"
    ):
        raise ValueError(f"The selected JAR does not identify itself as CxFlow. {advice}")
    version = properties.get("build.version", "")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or tuple(
        map(int, version.split("."))
    ) < (1, 6, 37):
        raise ValueError(f"Unsupported CxFlow version {version or '(unknown)'}. {advice}")


def private_environment(work: str, inherit: tuple[str, ...]) -> dict[str, str]:
    env = {name: os.environ[name] for name in inherit if name in os.environ}
    return env | dict.fromkeys(("TEMP", "TMP", "TMPDIR"), work)


def cxsast_environment(work: str, use_env_credentials: bool = False) -> dict[str, str]:
    # CxFlow uses the chosen profile for its server and Spring configuration.
    credentials = ("CHECKMARX_USERNAME", "CHECKMARX_PASSWORD", "CHECKMARX_CLIENT_SECRET")
    env = private_environment(work, credentials if use_env_credentials else ())
    if os.name == "nt":
        env["SystemRoot"] = os.environ["SystemRoot"]
    else:
        # The Java launcher decodes native arguments before applying file.encoding.
        env["LC_CTYPE"] = "UTF-8" if sys.platform == "darwin" else "C.UTF-8"
    return env


def one_environment(source: Path | None, work: str) -> dict[str, str]:
    # An inherited endpoint or proxy must never receive credentials from a saved profile.
    account = ("HOME", "USER", "LOGNAME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "SystemRoot")
    env = private_environment(work, (*account, "LANG", "LC_ALL", "LC_CTYPE"))
    configured = os.environ.get("CX_CONFIG_FILE_PATH")
    oauth = ("CX_CLIENT_ID", "CX_CLIENT_SECRET", "CX_BASE_URI", "CX_TENANT")
    api_key = os.environ.get("CX_APIKEY")
    if not configured and (api_key or all(os.environ.get(k) for k in oauth)):
        # A separate config path also separates the vendor's path-keyed credential store.
        profile = Path(work, "env-auth.yaml")
        profile.write_text("{}\n", encoding="utf-8")
        env["CX_CONFIG_FILE_PATH"] = str(profile)
        env["CX_KEYRING_MODE"] = "disabled"
        credentials = ("CX_APIKEY",) if api_key else (*oauth, "CX_BASE_AUTH_URI")
        env.update((name, os.environ[name]) for name in credentials if os.environ.get(name))
        return env

    profile = Path(configured) if configured else Path.home() / ".checkmarx" / "checkmarxcli.yaml"
    if not profile.is_absolute() or in_source(profile, source):
        raise ValueError(
            "Set CX_CONFIG_FILE_PATH to a trusted absolute path outside the source checkout. "
            "The collector runs Checkmarx One from a private directory."
        )
    env["CX_CONFIG_FILE_PATH"] = configured or str(profile)
    if "CX_KEYRING_MODE" in os.environ:
        env["CX_KEYRING_MODE"] = os.environ["CX_KEYRING_MODE"]
    return env


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


def capture_directory(temp: Path) -> Path:
    if os.name != "nt":
        return Path(tempfile.mkdtemp(prefix="checkmarx-report-", dir=temp)).resolve()

    import ctypes.wintypes
    import secrets

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", ctypes.wintypes.DWORD),
            ("descriptor", ctypes.wintypes.LPVOID),
            ("inherit", ctypes.wintypes.BOOL),
        ]

    # Older Windows Python releases ignore mkdir's 0700 mode. Apply CPython's
    # protected, inheritable SYSTEM/Administrators/owner DACL at creation.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    temp = temp.resolve()
    volume = ctypes.create_unicode_buffer(32768)
    flags = ctypes.wintypes.DWORD()
    if not kernel.GetVolumePathNameW(str(temp), volume, len(volume)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not kernel.GetVolumeInformationW(volume, None, 0, None, None, ctypes.byref(flags), None, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    if not flags.value & 0x8:  # FILE_PERSISTENT_ACLS
        raise ValueError("Select a temporary directory on a Windows volume that supports ACLs.")

    security = ctypes.WinDLL("advapi32", use_last_error=True)
    descriptor = ctypes.wintypes.LPVOID()
    dacl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        dacl, 1, ctypes.byref(descriptor), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        path = temp / f"checkmarx-report-{secrets.token_hex(16)}"
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
        return path
    finally:
        kernel.LocalFree(descriptor)


def create_capture(source: Path | None) -> Path:
    # gettempdir() probes candidates by writing a file. Check each candidate before
    # trying to create the actual capture directory in Python's platform order.
    cached = tempfile.tempdir
    candidates = [cached] if cached is not None else tempfile._candidate_tempdir_list()
    last_error = None
    for candidate in candidates:
        temp = Path(os.fsdecode(candidate)).absolute()
        if in_source(temp, source):
            raise ValueError(
                "Select a temporary directory outside the source checkout (TMPDIR or TEMP)."
            )
        try:
            return capture_directory(temp)
        except OSError as error:
            if cached is not None:
                raise
            last_error = error
    raise FileNotFoundError(
        f"No usable temporary directory outside the source checkout: {last_error}"
    )


def export_report(args: argparse.Namespace, source: Path | None, work: str, run_vendor) -> Path:
    def fetch(report, env, *command):
        # Only the validated report path goes to stdout; vendor diagnostics go to stderr.
        status = run_vendor(command, cwd=work, env=env, stdin=subprocess.DEVNULL, stdout=sys.stderr)
        if status:
            raise ValueError(f"The Checkmarx tool exited with status {status}.")
        if report.is_symlink() or not report.is_file():
            raise ValueError("The Checkmarx tool did not produce the requested report.")

    if args.product == "one":
        env = one_environment(source, work)
        report = Path(work, "cx_result.json")
        fetch(
            report,
            env,
            str(args.cx),
            "results",
            "show",
            # Older clients reject this flag instead of authenticating with another profile.
            "--config-file-path",
            env["CX_CONFIG_FILE_PATH"],
            "--scan-id",
            args.scan_id,
            "--report-format",
            "json",
            "--output-path",
            work,
            "--output-name",
            report.stem,
        )
        verify_one(report, args.scan_id)
        return report

    team = args.team.rstrip("/\\")
    report = Path(work, "checkmarx-results.xml")
    fetch(
        report,
        cxsast_environment(work, args.use_env_credentials),
        str(args.java),
        f"-Djava.io.tmpdir={work}",
        f"-DLOG_PATH={work}",
        "-Dfile.encoding=UTF-8",
        "-jar",
        str(args.jar),
        f"--spring.config.location={args.config.as_uri()}",
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
        "--checkmarx.cx-branch=false",
        "--checkmarx.preserve-xml=true",
        f"--cx-xml.data-folder={work}",
        f"--cx-xml.file-name-format={report.name}",
    )
    verify_cxsast(report, str(args.scan_id), args.project, args.team)
    return report


def collect(args: argparse.Namespace, source: Path | None, run_vendor) -> None:
    output = create_capture(source)
    try:
        with tempfile.TemporaryDirectory(dir=output) as work:
            report = export_report(args, source, work, run_vendor)
            report.chmod(0o600)
            saved = report.replace(output / report.name)
        sys.stdout.buffer.write(f"{saved}\n".encode("utf-8"))
        sys.stdout.buffer.flush()
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
    cxsast.add_argument(
        "--use-env-credentials",
        action="store_true",
        help="use the Checkmarx credentials selected for this profile's server",
    )
    args = parser.parse_args()
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

    pending_signal = None
    defer_termination = False

    def terminate(signum, _frame):
        nonlocal pending_signal
        if pending_signal is None:
            pending_signal = signum
            if not defer_termination:
                raise SystemExit(128 + signum)

    def run_vendor(command, **kwargs):
        nonlocal defer_termination
        child = None
        # Popen can have spawned the child before it returns the handle needed for cleanup.
        defer_termination = True
        try:
            child = subprocess.Popen(command, start_new_session=os.name == "posix", **kwargs)
            defer_termination = False
            if pending_signal is not None:
                raise SystemExit(128 + pending_signal)
            return child.wait()
        except BaseException:
            defer_termination = True
            if child is not None:
                if os.name == "posix":
                    # Kill any surviving credential helper if the process group still exists.
                    with suppress(ProcessLookupError):
                        os.killpg(child.pid, signal.SIGKILL)
                else:
                    child.kill()
                child.wait()
            raise
        finally:
            defer_termination = False

    signals = [signal.SIGTERM]
    if signal.getsignal(signal.SIGINT) != signal.SIG_IGN:
        signals.append(signal.SIGINT)
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
            check_cxflow_version(args.jar)
        collect(args, source, run_vendor)
    except (ValueError, OSError, expat.ExpatError) as error:
        print(error, file=sys.stderr)
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
