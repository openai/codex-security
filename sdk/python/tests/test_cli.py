from __future__ import annotations

import argparse
import io
import json
import signal
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import openai_codex_security.cli as cli
from openai_codex_security import DiffTarget, __version__
from openai_codex_security.cli import (
    _parse_codex_overrides,
    _parser,
    _Progress,
    _result_json,
    _target_from_args,
    main,
)
from openai_codex_security.errors import CodexSecurityError
from openai_codex_security.result import ScanResult
from openai_codex_security.runtime import (
    bundled_plugin_root,
    plugin_metadata,
    prepare_output_dir,
)


def _args(*values: str) -> argparse.Namespace:
    return _parser().parse_args(["scan", ".", *values])


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parser().parse_args(["--version"])

    assert exc_info.value.code == 0
    _, plugin_version = plugin_metadata(bundled_plugin_root())
    assert capsys.readouterr().out == (
        f"codex-security {__version__}\ncodex-security plugin {plugin_version} (bundled)\n"
    )


def test_cli_help_describes_flags_and_outputs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = _parser()

    assert "SDK and bundled plugin versions" in parser.format_help()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["scan", "--help"])

    assert exc_info.value.code == 0
    help_text = capsys.readouterr().out
    assert "Repository root to scan" in help_text
    assert "Scan only PATH relative to the repository" in help_text
    assert "Scan Git changes from BASE" in help_text
    assert "staged and unstaged changes" in help_text
    assert "TOML KEY=VALUE" in help_text
    assert "manifest, findings, coverage" in help_text
    assert "exports/results.sarif" in help_text


def test_cli_without_arguments_prints_help_and_succeeds(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([]) == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.startswith("usage: codex-security")
    assert "scan" in captured.out


def test_parser_without_arguments_still_requires_a_command() -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parser().parse_args([])

    assert exc_info.value.code == 2


def test_cli_module_invocation_runs_main() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "openai_codex_security.cli", "--version"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert completed.stdout.startswith(f"codex-security {__version__}\n")


class _Dumpable:
    def __init__(self, value: dict[str, Any]) -> None:
        self.value = value
        for key, item in value.items():
            setattr(self, key, item)

    def model_dump(self, **_kwargs: object) -> dict[str, Any]:
        return self.value


def _fake_result() -> ScanResult:
    return cast(
        ScanResult,
        SimpleNamespace(
            manifest=_Dumpable(
                {"scan": {"producer": {"name": "codex-security-plugin", "version": "1.2.3"}}}
            ),
            findings=_Dumpable({"findings": []}),
            coverage=_Dumpable({"mode": "repository"}),
            scan_dir=Path("/tmp/scan"),
            report_path=Path("/tmp/scan/report.md"),
            artifacts_dir=Path("/tmp/scan/artifacts"),
            sarif_path=None,
            thread_id="thread-1",
            turn_result=SimpleNamespace(
                id="turn-1",
                status="completed",
                duration_ms=123,
                final_response="done",
                usage=None,
            ),
        ),
    )


def _capture_run_repositories(
    monkeypatch: pytest.MonkeyPatch,
) -> list[str | Path]:
    repositories: list[str | Path] = []

    class FakeSecurity:
        def __init__(self, _config: object) -> None:
            pass

        def __enter__(self) -> FakeSecurity:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def turn(
            self,
            repository: str | Path,
            **_kwargs: object,
        ) -> object:
            repositories.append(repository)
            result = _fake_result()
            return SimpleNamespace(scan_dir=result.scan_dir, run=lambda: result)

    monkeypatch.setattr("openai_codex_security.cli.CodexSecurity", FakeSecurity)
    return repositories


def test_result_json_uses_manifest_producer_without_html_path() -> None:
    result = _fake_result()

    payload = _result_json(result)

    assert payload["manifest"]["scan"]["producer"]["version"] == "1.2.3"
    assert "htmlReport" not in payload["paths"]
    assert "plugin" not in payload


def test_human_output_includes_effective_plugin_version(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = _fake_result()
    result.plugin_version = "1.2.3"

    class FakeHandle:
        scan_dir = result.scan_dir

        def run(self) -> ScanResult:
            return result

    class FakeSecurity:
        def __init__(self, _config: object) -> None:
            pass

        def __enter__(self) -> FakeSecurity:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def turn(self, *_args: object, **_kwargs: object) -> FakeHandle:
            return FakeHandle()

    monkeypatch.setattr("openai_codex_security.cli.CodexSecurity", FakeSecurity)

    assert main(["scan", "."]) == 0
    assert "Plugin: 1.2.3\n" in capsys.readouterr().out


def test_cli_reports_progress_without_corrupting_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = _fake_result()
    events: list[str] = []

    class FakeHandle:
        scan_dir = result.scan_dir

        def run(self) -> ScanResult:
            events.append("run")
            return result

    class FakeSecurity:
        def __init__(self, _config: object) -> None:
            pass

        def __enter__(self) -> FakeSecurity:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def turn(self, *_args: object, **_kwargs: object) -> FakeHandle:
            events.append("turn")
            return FakeHandle()

    monkeypatch.setattr("openai_codex_security.cli.CodexSecurity", FakeSecurity)

    assert main(["scan", ".", "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["scanDir"] == str(result.scan_dir)
    assert events == ["turn", "run"]
    progress_lines = captured.err.splitlines()
    assert all(line.startswith("[") and "] " in line for line in progress_lines)
    assert "Preparing scan" in captured.err
    assert "Output:" not in captured.err
    assert "Running scan" in captured.err
    assert "Scan complete" in captured.err


def test_progress_timer_updates_in_place(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 0.0
    monkeypatch.setattr("openai_codex_security.cli.time.monotonic", lambda: now)

    stream = io.StringIO()
    progress = _Progress(stream=stream)
    progress._render_timer("Running scan")
    now = 1.0
    progress._render_timer("Running scan")
    progress.stop_timer()

    assert stream.getvalue() == ("[00:00] Running scan\r[00:01] Running scan\n")


def test_progress_timer_hides_terminal_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    class TerminalStream(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("openai_codex_security.cli.time.monotonic", lambda: 0.0)

    stream = TerminalStream()
    progress = _Progress(stream=stream, refresh_seconds=60)
    progress.start_timer("Running scan")
    progress.stop_timer()

    assert stream.getvalue() == ("\x1b[?25l[00:00] Running scan\n\x1b[?25h")


def test_cli_reports_output_dir_with_file_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parent = tmp_path / "not-a-directory"
    parent.write_text("file\n", encoding="utf-8")

    class FakeSecurity:
        def __init__(self, _config: object) -> None:
            pass

        def __enter__(self) -> FakeSecurity:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def turn(self, *_args: object, **kwargs: Any) -> object:
            prepare_output_dir(kwargs["output_dir"], "repo")
            raise AssertionError("output directory should be rejected")

    monkeypatch.setattr("openai_codex_security.cli.CodexSecurity", FakeSecurity)

    assert main(["scan", ".", "--output-dir", str(parent / "scan")]) == 1
    assert "Unable to create scan output directory" in capsys.readouterr().err


def test_ctrl_c_interrupts_scan_and_keeps_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "scan"
    output.mkdir()
    (output / "partial.json").write_text("{}\n", encoding="utf-8")
    state = SimpleNamespace(interrupted=False, exited=False)

    class FakeHandle:
        scan_dir = output

        def run(self) -> ScanResult:
            raise KeyboardInterrupt

        def interrupt(self) -> None:
            state.interrupted = True

    class FakeSecurity:
        def __init__(self, _config: object) -> None:
            pass

        def __enter__(self) -> FakeSecurity:
            return self

        def __exit__(self, *_args: object) -> None:
            state.exited = True

        def turn(self, *_args: object, **_kwargs: object) -> FakeHandle:
            return FakeHandle()

    monkeypatch.setattr(cli, "CodexSecurity", FakeSecurity)

    assert main(["scan", ".", "--output-dir", str(output)]) == 130

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Scan canceled by Ctrl-C." in captured.err
    assert f"Partial output was kept at {output}." in captured.err
    assert "Traceback" not in captured.err
    assert state.interrupted is True
    assert state.exited is True


def test_sigterm_interrupts_scan_with_conventional_exit_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "scan"
    output.mkdir()
    state = SimpleNamespace(interrupted=False, exited=False)
    handlers: dict[int, Any] = {}

    def fake_signal(signum: int, handler: Any) -> Any:
        previous = handlers.get(signum, signal.SIG_DFL)
        handlers[signum] = handler
        return previous

    class FakeHandle:
        scan_dir = output

        def run(self) -> ScanResult:
            handler = handlers[signal.SIGTERM]
            handler(signal.SIGTERM, None)
            raise AssertionError("SIGTERM handler did not stop the scan")

        def interrupt(self) -> None:
            state.interrupted = True

    class FakeSecurity:
        def __init__(self, _config: object) -> None:
            pass

        def __enter__(self) -> FakeSecurity:
            return self

        def __exit__(self, *_args: object) -> None:
            state.exited = True

        def turn(self, *_args: object, **_kwargs: object) -> FakeHandle:
            return FakeHandle()

    monkeypatch.setattr(cli.signal, "getsignal", lambda _signum: signal.SIG_DFL)
    monkeypatch.setattr(cli.signal, "signal", fake_signal)
    monkeypatch.setattr(cli, "CodexSecurity", FakeSecurity)

    assert main(["scan", ".", "--output-dir", str(output)]) == 143

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Scan terminated by SIGTERM." in captured.err
    assert f"Partial output was kept at {output}." in captured.err
    assert "Traceback" not in captured.err
    assert state.interrupted is True
    assert state.exited is True
    assert handlers[signal.SIGTERM] == signal.SIG_DFL


def test_ctrl_c_during_turn_setup_reports_kept_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "scan"
    output.mkdir()

    class FakeSecurity:
        def __init__(self, _config: object) -> None:
            pass

        def __enter__(self) -> FakeSecurity:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def turn(self, *_args: object, **kwargs: object) -> object:
            callback = kwargs["_on_output_dir_ready"]
            assert callable(callback)
            callback(output)
            raise KeyboardInterrupt

    monkeypatch.setattr(cli, "CodexSecurity", FakeSecurity)

    assert main(["scan", ".", "--output-dir", str(output)]) == 130

    captured = capsys.readouterr()
    assert "Scan canceled by Ctrl-C." in captured.err
    assert f"Partial output was kept at {output}." in captured.err


def test_scan_without_repository_uses_current_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    repositories = _capture_run_repositories(monkeypatch)

    assert main(["scan", "--json"]) == 0
    assert repositories == [tmp_path]


def test_scan_preserves_explicit_repository_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    explicit_repository = tmp_path / "repository"
    repositories = _capture_run_repositories(monkeypatch)

    assert main(["scan", str(explicit_repository), "--json"]) == 0
    assert repositories == [str(explicit_repository)]


def test_cli_targets() -> None:
    assert _target_from_args(_args()) == "repository"
    assert _target_from_args(_args("--path", "src", "--path", "tests")) == [
        "src",
        "tests",
    ]
    assert _target_from_args(_args("--diff", "origin/main", "--head", "HEAD")) == DiffTarget.refs(
        base="origin/main",
        head="HEAD",
    )
    assert _target_from_args(_args("--working-tree")) == DiffTarget.working_tree()
    assert _target_from_args(
        _args("--working-tree", "--base", "origin/main")
    ) == DiffTarget.working_tree(
        base="origin/main",
    )


def test_cli_options_map_without_new_concepts() -> None:
    args = _args(
        "--mode",
        "deep",
        "--output-dir",
        "/tmp/scan",
        "--plugin-path",
        "/tmp/plugin.zip",
        "--json",
    )
    assert args.mode == "deep"
    assert args.output_dir == Path("/tmp/scan")
    assert args.plugin_path == Path("/tmp/plugin.zip")
    assert args.json is True


def test_cli_reports_malformed_plugin_zip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = tmp_path / "plugin.zip"
    archive.write_bytes(b"not a zip archive")

    assert main(["scan", str(tmp_path), "--plugin-path", str(archive)]) == 1

    captured = capsys.readouterr()
    assert "codex-security: Invalid plugin ZIP:" in captured.err
    assert "BadZipFile" not in captured.err


def test_codex_overrides_parse_toml_literals() -> None:
    assert _parse_codex_overrides(
        ["agents.max_threads=4", 'model_reasoning_effort="high"', "features.goals=true"]
    ) == {
        "agents": {"max_threads": 4},
        "model_reasoning_effort": "high",
        "features": {"goals": True},
    }


def test_codex_override_conflicts_are_clear() -> None:
    with pytest.raises(CodexSecurityError, match="Duplicate"):
        _parse_codex_overrides(["agents.max_threads=4", "agents.max_threads=8"])


def test_cli_rejects_native_v2_legacy_override_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["scan", str(tmp_path), "--codex", "agents.max_threads=2"]) == 1

    captured = capsys.readouterr()
    assert "agents.max_threads is a legacy v1 setting" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    "override",
    [
        "features.multi_agent_v2.enabled=false",
        "features.multi_agent_v2=false",
        "features.multi_agent_v2=true",
    ],
)
def test_cli_rejects_disabled_native_v2_override_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    override: str,
) -> None:
    assert main(["scan", str(tmp_path), "--codex", override]) == 1

    captured = capsys.readouterr()
    assert "requires native multi-agent v2" in captured.err
    assert "Traceback" not in captured.err


def test_target_specific_ref_flags_are_rejected() -> None:
    with pytest.raises(CodexSecurityError, match="--head requires --diff"):
        _target_from_args(_args("--head", "HEAD"))
    with pytest.raises(CodexSecurityError, match="--base requires"):
        _target_from_args(_args("--base", "origin/main"))


def test_empty_cli_path_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", ".", "--path", ""]) == 1
    assert capsys.readouterr().err == "codex-security: --path must not be empty.\n"
