from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import FrameType
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

from ._version import __version__
from .api import CodexSecurity
from .config import CodexSecurityConfig
from .errors import CodexSecurityError
from .result import ScanResult
from .runtime import bundled_plugin_root, plugin_metadata
from .targets import DiffTarget, ScanTarget

_PROGRESS_REFRESH_SECONDS = 1.0
_HIDE_CURSOR = "\x1b[?25l"
_SHOW_CURSOR = "\x1b[?25h"


class _TerminationRequested(Exception):
    def __init__(self, signum: int) -> None:
        self.signum = signum
        super().__init__(f"signal {signum}")


class _VersionAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        _namespace: argparse.Namespace,
        _values: object,
        _option_string: str | None = None,
    ) -> None:
        print(_version_text())
        parser.exit()


class _Progress:
    def __init__(
        self,
        *,
        stream: Any = None,
        refresh_seconds: float = _PROGRESS_REFRESH_SECONDS,
    ) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._refresh_seconds = refresh_seconds
        self._started_at = time.monotonic()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._timer_line_active = False
        self._cursor_hidden = False

    def stage(self, message: str) -> None:
        print(self._line(message), file=self._stream, flush=True)

    def start_timer(self, message: str) -> None:
        if getattr(self._stream, "isatty", lambda: False)():
            print(_HIDE_CURSOR, end="", file=self._stream, flush=True)
            self._cursor_hidden = True
        self._render_timer(message)
        self._thread = threading.Thread(
            target=self._run_timer,
            args=(message,),
            daemon=True,
        )
        self._thread.start()

    def stop_timer(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
            self._thread = None
        if self._timer_line_active:
            print(file=self._stream, flush=True)
            self._timer_line_active = False
        if self._cursor_hidden:
            print(_SHOW_CURSOR, end="", file=self._stream, flush=True)
            self._cursor_hidden = False

    def _line(self, message: str) -> str:
        elapsed = max(0, int(time.monotonic() - self._started_at))
        minutes, seconds = divmod(elapsed, 60)
        return f"[{minutes:02d}:{seconds:02d}] {message}"

    def _render_timer(self, message: str) -> None:
        prefix = "\r" if self._timer_line_active else ""
        print(
            f"{prefix}{self._line(message)}",
            end="",
            file=self._stream,
            flush=True,
        )
        self._timer_line_active = True

    def _run_timer(self, message: str) -> None:
        while not self._stop.wait(self._refresh_seconds):
            self._render_timer(message)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments:
        parser.print_help()
        return 0
    args = parser.parse_args(arguments)
    scan_dir: Path | None = None

    def remember_output_dir(path: Path) -> None:
        nonlocal scan_dir
        scan_dir = path

    try:
        with _handle_sigterm():
            target = _target_from_args(args)
            config = CodexSecurityConfig(
                plugin_path=args.plugin_path,
                codex_overrides=_parse_codex_overrides(args.codex),
            )
            progress = _Progress()
            progress.stage("Preparing scan")
            with CodexSecurity(config) as security:
                handle = security.turn(
                    args.repository,
                    target=target,
                    mode=args.mode,
                    output_dir=args.output_dir,
                    _on_output_dir_ready=remember_output_dir,
                )
                scan_dir = handle.scan_dir
                progress.start_timer("Running scan")
                try:
                    result = handle.run()
                except (KeyboardInterrupt, _TerminationRequested):
                    _interrupt_scan(handle)
                    raise
                finally:
                    progress.stop_timer()
            progress.stage("Scan complete")
        if args.json:
            print(json.dumps(_result_json(result), indent=2))
        else:
            print(f"Scan: {result.scan_dir}")
            print(f"Report: {result.report_path}")
            print(f"Plugin: {result.plugin_version}")
            print(f"Findings: {len(result.findings.findings)}")
        return 0
    except KeyboardInterrupt:
        _print_interrupted_status("Scan canceled by Ctrl-C.", scan_dir)
        return 130
    except _TerminationRequested as exc:
        _print_interrupted_status("Scan terminated by SIGTERM.", scan_dir)
        return 128 + exc.signum
    except CodexSecurityError as exc:
        print(f"codex-security: {exc}", file=sys.stderr)
        return 1


@contextmanager
def _handle_sigterm() -> Iterator[None]:
    previous_handler = signal.getsignal(signal.SIGTERM)

    def terminate(signum: int, _frame: FrameType | None) -> None:
        raise _TerminationRequested(signum)

    try:
        signal.signal(signal.SIGTERM, terminate)
    except ValueError:
        # Console entry points run on the main thread. If a caller invokes main()
        # elsewhere, leave that process's signal handling untouched.
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous_handler)


def _interrupt_scan(handle: Any) -> None:
    try:
        handle.interrupt()
    except Exception:
        # The original interrupt still determines the CLI's concise exit status.
        pass


def _print_interrupted_status(status: str, scan_dir: Path | None) -> None:
    print(f"codex-security: {status}", file=sys.stderr)
    if scan_dir is None:
        print("codex-security: No partial output was kept.", file=sys.stderr)
    else:
        print(f"codex-security: Partial output was kept at {scan_dir}.", file=sys.stderr)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codex-security")
    parser.add_argument(
        "--version",
        action=_VersionAction,
        nargs=0,
        help="Print the SDK and bundled plugin versions, then exit.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Run a Codex Security scan.")
    scan.add_argument(
        "repository",
        nargs="?",
        default=Path.cwd(),
        help="Repository root to scan (default: current directory).",
    )
    targets = scan.add_mutually_exclusive_group()
    targets.add_argument(
        "--path",
        action="append",
        default=[],
        metavar="PATH",
        help="Scan only PATH relative to the repository; repeat for multiple paths.",
    )
    targets.add_argument(
        "--diff",
        metavar="BASE",
        help="Scan Git changes from BASE to --head (default: HEAD).",
    )
    targets.add_argument(
        "--working-tree",
        action="store_true",
        help="Scan staged and unstaged changes against --base (default: HEAD).",
    )
    scan.add_argument(
        "--head",
        help="Git head ref for --diff (default: HEAD).",
    )
    scan.add_argument(
        "--base",
        help="Git base ref for --working-tree (default: HEAD).",
    )
    scan.add_argument(
        "--mode",
        choices=("standard", "deep"),
        default="standard",
        help="Scan mode; deep mode supports repository and path targets only.",
    )
    scan.add_argument(
        "--output-dir",
        type=Path,
        metavar="DIR",
        help=(
            "Write scan artifacts to an empty DIR (default: a temporary directory); "
            "SARIF, when produced, is written to <scan-dir>/exports/results.sarif."
        ),
    )
    scan.add_argument(
        "--plugin-path",
        type=Path,
        metavar="PATH",
        help="Use a Codex Security plugin directory or ZIP instead of the bundled plugin.",
    )
    scan.add_argument(
        "--codex",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Override isolated Codex config with a TOML KEY=VALUE; repeat as needed.",
    )
    scan.add_argument(
        "--json",
        action="store_true",
        help=(
            "Print manifest, findings, coverage, output paths, and turn metadata as "
            "JSON instead of the human summary."
        ),
    )
    return parser


def _version_text() -> str:
    _, plugin_version = plugin_metadata(bundled_plugin_root())
    return f"codex-security {__version__}\ncodex-security plugin {plugin_version} (bundled)"


def _target_from_args(args: argparse.Namespace) -> ScanTarget:
    if args.head and not args.diff:
        raise CodexSecurityError("--head requires --diff.")
    if args.base and not args.working_tree:
        raise CodexSecurityError("--base requires --working-tree.")
    if any(path == "" for path in args.path):
        raise CodexSecurityError("--path must not be empty.")
    if args.path:
        return args.path
    if args.diff:
        return DiffTarget.refs(base=args.diff, head=args.head or "HEAD")
    if args.working_tree:
        return DiffTarget.working_tree(base=args.base or "HEAD")
    return "repository"


def _parse_codex_overrides(values: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for value in values:
        key, separator, literal = value.partition("=")
        if not separator or not key or not literal:
            raise CodexSecurityError("--codex expects KEY=VALUE.")
        try:
            parsed = tomllib.loads(f"value = {literal}")["value"]
        except tomllib.TOMLDecodeError as exc:
            raise CodexSecurityError(f"Invalid --codex TOML value for {key}: {exc}") from exc
        cursor = result
        parts = key.split(".")
        if any(not part for part in parts):
            raise CodexSecurityError(f"Invalid --codex key: {key}")
        for part in parts[:-1]:
            existing = cursor.setdefault(part, {})
            if not isinstance(existing, dict):
                raise CodexSecurityError(f"Conflicting --codex key: {key}")
            cursor = existing
        if parts[-1] in cursor:
            raise CodexSecurityError(f"Duplicate --codex key: {key}")
        cursor[parts[-1]] = parsed
    return result


def _result_json(result: ScanResult) -> dict[str, Any]:
    status = result.turn_result.status
    return {
        "manifest": result.manifest.model_dump(by_alias=True, mode="json"),
        "findings": result.findings.model_dump(by_alias=True, mode="json"),
        "coverage": result.coverage.model_dump(by_alias=True, mode="json"),
        "scanDir": str(result.scan_dir),
        "threadId": result.thread_id,
        "paths": {
            "report": str(result.report_path),
            "artifacts": str(result.artifacts_dir),
            "sarif": str(result.sarif_path) if result.sarif_path else None,
        },
        "turn": {
            "id": result.turn_result.id,
            "status": getattr(status, "value", status),
            "durationMs": result.turn_result.duration_ms,
            "finalResponse": result.turn_result.final_response,
            "usage": (
                result.turn_result.usage.model_dump(by_alias=True, mode="json")
                if result.turn_result.usage is not None
                else None
            ),
        },
    }


if __name__ == "__main__":
    raise SystemExit(main())
