from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path

import pytest
from openai_codex import CodexConfig, TurnResult
from openai_codex.types import TurnStatus

import openai_codex_security.api as api
import openai_codex_security.cli as cli
from openai_codex_security import (
    AsyncCodexSecurity,
    CodexSecurity,
    DiffTarget,
    OutputDirectoryError,
    ScanHandle,
)
from openai_codex_security.runtime import PluginInstall, bundled_plugin_root

PLUGIN_ROOT = bundled_plugin_root()
EXAMPLE = PLUGIN_ROOT / "examples/completed-scan"
PLUGIN_VERSION = json.loads(
    (PLUGIN_ROOT / ".codex-plugin/plugin.json").read_text(encoding="utf-8")
)["version"]


def _turn_result() -> TurnResult:
    return TurnResult(
        id="turn-1",
        status=TurnStatus.completed,
        error=None,
        started_at=1,
        completed_at=2,
        duration_ms=1,
        final_response="complete",
        items=[],
        usage=None,
    )


class FakeTurn:
    id = "turn-1"

    def __init__(self, scan_dir: Path) -> None:
        self.scan_dir = scan_dir
        self.steered = None
        self.interrupted = False

    def run(self) -> TurnResult:
        for source in EXAMPLE.iterdir():
            shutil.copy2(source, self.scan_dir / source.name)
        manifest_path = self.scan_dir / "scan-manifest.json"
        coverage_path = self.scan_dir / "coverage.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
        manifest["scan"]["producer"]["version"] = PLUGIN_VERSION
        manifest["scan"]["target"]["kind"] = "directory_snapshot"
        manifest["scan"]["scope"]["includePaths"] = ["."]
        coverage["includePaths"] = ["."]
        coverage_path.write_text(json.dumps(coverage, indent=2) + "\n", encoding="utf-8")
        for artifact in manifest["scan"]["artifacts"]:
            artifact["sha256"] = hashlib.sha256(
                (self.scan_dir / artifact["path"]).read_bytes()
            ).hexdigest()
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        (self.scan_dir / "report.md").write_text("# Test report\n", encoding="utf-8")
        return _turn_result()

    def stream(self):
        return iter(["one", "two"])

    def steer(self, input):
        self.steered = input
        return "steered"

    def interrupt(self):
        self.interrupted = True
        return "interrupted"


class FakeThread:
    id = "thread-1"

    def __init__(self, scan_dir: Path, calls: list[tuple[str, object]]) -> None:
        self.scan_dir = scan_dir
        self.calls = calls

    def turn(self, input, **kwargs):
        self.calls.append(("turn", (input, kwargs)))
        return FakeTurn(self.scan_dir)


@dataclass(frozen=True)
class FakeLoginResult:
    success: bool
    error: str | None = None


class FakeLoginHandle:
    login_id = "login-1"
    auth_url = "https://example.com/login"
    verification_url = "https://example.com/device"
    user_code = "CODE"

    def __init__(self, success: bool = True) -> None:
        self.success = success

    def wait(self):
        return FakeLoginResult(success=self.success, error=None if self.success else "denied")

    def cancel(self):
        return "login-cancelled"


class FakeAsyncLoginHandle(FakeLoginHandle):
    async def wait(self):
        return super().wait()

    async def cancel(self):
        return "login-cancelled"


class FakeCodex:
    def __init__(self, config) -> None:
        self.config = config
        self.calls: list[tuple[str, object]] = []
        self.closed = False
        self.metadata = {"name": "fake"}

    def thread_start(self, **kwargs):
        self.calls.append(("thread_start", kwargs))
        scan_dir = Path(kwargs["config"]["sandbox_workspace_write"]["writable_roots"][0])
        return FakeThread(scan_dir, self.calls)

    def close(self) -> None:
        self.closed = True

    def login_api_key(self, api_key: str) -> None:
        self.calls.append(("login_api_key", api_key))

    def login_chatgpt(self):
        return FakeLoginHandle()

    def login_chatgpt_device_code(self):
        return FakeLoginHandle()

    def account(self, *, refresh_token: bool = False):
        return refresh_token

    def logout(self) -> None:
        self.calls.append(("logout", None))


class FakeAsyncCodex:
    def __init__(self, config) -> None:
        self.config = config
        self.calls: list[tuple[str, object]] = []
        self.closed = False
        self.metadata = {"name": "fake"}

    async def login_api_key(self, api_key: str) -> None:
        self.calls.append(("login_api_key", api_key))

    async def close(self) -> None:
        self.closed = True


class FailingCloseCodex(FakeCodex):
    def close(self) -> None:
        raise RuntimeError("close failed")


class FailingAsyncCodex:
    def __init__(self, config) -> None:
        raise RuntimeError("init failed")


@pytest.fixture
def fake_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    runtime = api._PreparedRuntime(
        codex_home=home,
        plugin=PluginInstall(
            plugin_root=PLUGIN_ROOT,
            marketplace_root=tmp_path / "marketplace",
            installed_root=PLUGIN_ROOT,
            marketplace_name="test",
            name="codex-security",
            version=PLUGIN_VERSION,
        ),
        codex_config=CodexConfig(),
        credentials_available=True,
    )
    monkeypatch.setattr(api, "_prepare_runtime", lambda config: runtime)
    monkeypatch.setattr(api, "Codex", FakeCodex)
    return runtime


def _without_auth(runtime: api._PreparedRuntime) -> api._PreparedRuntime:
    return api._PreparedRuntime(
        codex_home=runtime.codex_home,
        plugin=runtime.plugin,
        codex_config=runtime.codex_config,
        credentials_available=False,
    )


def test_sync_run_returns_contract_and_turn_result(
    tmp_path: Path, fake_runtime: api._PreparedRuntime
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    output = tmp_path / "scan"
    with CodexSecurity() as security:
        result = security.run(repo, output_dir=output)
        assert result.thread_id == "thread-1"
        assert result.turn_result.final_response == "complete"
        assert result.findings.scan_id == result.manifest.scan.id
        assert result.plugin_version == PLUGIN_VERSION
        assert result.report_path.is_file()
        thread_call = security._codex.calls[0][1]
        assert thread_call["cwd"] == str(output)
        assert thread_call["config"]["sandbox_workspace_write"]["writable_roots"] == [str(output)]
        turn_call = security._codex.calls[1][1]
        assert "sandbox" not in turn_call[1]
        assert turn_call[1]["cwd"] == str(output)


def test_auth_methods_delegate(fake_runtime: api._PreparedRuntime) -> None:
    security = CodexSecurity()
    security.login_api_key("sk-test")
    browser = security.login_chatgpt()
    assert browser.auth_url == "https://example.com/login"
    assert browser.wait().success is True
    device = security.login_chatgpt_device_code()
    assert device.verification_url == "https://example.com/device"
    assert device.user_code == "CODE"
    assert device.cancel() == "login-cancelled"
    assert security.account(refresh_token=True) is True
    security.logout()
    assert ("login_api_key", "sk-test") in security._codex.calls
    security.close()


def test_chatgpt_auth_becomes_available_after_login_completion(
    tmp_path: Path,
    fake_runtime: api._PreparedRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = api._PreparedRuntime(
        codex_home=fake_runtime.codex_home,
        plugin=fake_runtime.plugin,
        codex_config=fake_runtime.codex_config,
        credentials_available=False,
    )
    monkeypatch.setattr(api, "_prepare_runtime", lambda config: runtime)
    security = CodexSecurity()
    handle = security.login_chatgpt()

    with pytest.raises(api.AuthenticationRequiredError):
        security.turn(tmp_path)

    assert handle.wait().success is True
    assert security.turn(tmp_path).thread_id == "thread-1"
    security.close()


def test_async_chatgpt_auth_becomes_available_after_login_completion() -> None:
    async def run() -> None:
        security = AsyncCodexSecurity()
        handle = api._AsyncChatgptLoginHandle(FakeAsyncLoginHandle(), security)
        assert security._auth_available is False
        assert (await handle.wait()).success is True
        assert security._auth_available is True

    asyncio.run(run())


def test_failed_chatgpt_login_remains_unauthenticated(
    fake_runtime: api._PreparedRuntime,
) -> None:
    security = CodexSecurity()
    security._auth_available = False
    handle = api._SyncChatgptLoginHandle(FakeLoginHandle(success=False), security)

    result = handle.wait()

    assert result.success is False
    assert security._auth_available is False
    security.close()


def test_failed_async_chatgpt_login_remains_unauthenticated() -> None:
    async def run() -> None:
        security = AsyncCodexSecurity()
        handle = api._AsyncChatgptLoginHandle(
            FakeAsyncLoginHandle(success=False),
            security,
        )

        result = await handle.wait()

        assert result.success is False
        assert security._auth_available is False

    asyncio.run(run())


def test_runtime_imports_ambient_auth_after_plugin_bootstrap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ambient = tmp_path / "ambient"
    ambient.mkdir()
    (ambient / "auth.json").write_text('{"token":"test"}\n', encoding="utf-8")
    home = tmp_path / "isolated"
    plugin_root = tmp_path / "plugin"
    profiles = plugin_root / "preflight/capability-profiles.toml"
    profiles.parent.mkdir(parents=True)
    profiles.write_text(
        "[profiles.deep_security_scan]\n"
        "[[profiles.deep_security_scan.requirements]]\n"
        'capability = "native_multi_agent_v2"\n'
        'severity = "block"\n',
        encoding="utf-8",
    )
    plugin = PluginInstall(
        plugin_root=plugin_root,
        marketplace_root=tmp_path / "marketplace",
        installed_root=plugin_root,
        marketplace_name="test",
        name="codex-security",
        version="1.2.3",
    )

    monkeypatch.setenv("CODEX_HOME", str(ambient))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CODEX_API_KEY", raising=False)
    monkeypatch.setattr(api, "create_isolated_home", lambda: home)

    def fake_resolve(_plugin_path, workspace: Path):
        assert workspace == home / "bootstrap"
        return plugin_root

    def fake_bootstrap(codex_home: Path, selected_plugin: Path):
        assert not (codex_home / "auth.json").exists()
        assert selected_plugin == plugin_root
        written_config = (codex_home / "config.toml").read_text(encoding="utf-8")
        assert "features.multi_agent_v2.enabled = true" in written_config
        with (codex_home / "config.toml").open("a", encoding="utf-8") as config:
            config.write('\n[marketplaces.test]\nsource = "/plugin"\n')
        return plugin

    monkeypatch.setattr(api, "resolve_plugin_path", fake_resolve)
    monkeypatch.setattr(api, "bootstrap_plugin", fake_bootstrap)
    runtime = api._prepare_runtime(api.CodexSecurityConfig())

    assert runtime.credentials_available is True
    assert (home / "auth.json").read_text(encoding="utf-8") == '{"token":"test"}\n'
    written_config = (home / "config.toml").read_text(encoding="utf-8")
    assert "features.multi_agent_v2.enabled = true" in written_config
    assert "features.multi_agent_v2.max_concurrent_threads_per_session = 9" in written_config
    assert "agents.max_threads" not in written_config
    assert "[marketplaces.test]" in written_config


def test_runtime_marks_environment_api_key_for_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_key = "sk-environment-secret"
    home = tmp_path / "isolated"
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    plugin = PluginInstall(
        plugin_root=plugin_root,
        marketplace_root=tmp_path / "marketplace",
        installed_root=plugin_root,
        marketplace_name="test",
        name="codex-security",
        version="1.2.3",
    )
    monkeypatch.setenv("OPENAI_API_KEY", api_key)
    monkeypatch.delenv("CODEX_API_KEY", raising=False)
    monkeypatch.setattr(api, "create_isolated_home", lambda: home)
    monkeypatch.setattr(api, "resolve_plugin_path", lambda _path, _workspace: plugin_root)
    monkeypatch.setattr(api, "bootstrap_plugin", lambda _home, _plugin_root: plugin)

    runtime = api._prepare_runtime(api.CodexSecurityConfig())

    assert runtime.credentials_available is True
    assert runtime.environment_api_key_available is True
    assert api_key not in repr(runtime)
    assert not (home / "auth.json").exists()


def test_environment_api_key_is_materialized_for_sync_runtime(
    tmp_path: Path,
    fake_runtime: api._PreparedRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_key = "sk-environment-secret"
    runtime = api._PreparedRuntime(
        codex_home=fake_runtime.codex_home,
        plugin=fake_runtime.plugin,
        codex_config=fake_runtime.codex_config,
        credentials_available=True,
        environment_api_key_available=True,
    )
    monkeypatch.setenv("OPENAI_API_KEY", api_key)
    monkeypatch.setattr(api, "_prepare_runtime", lambda config: runtime)

    security = CodexSecurity()

    assert security._codex.calls == []
    assert security._auth_available is False
    with pytest.raises(api.InvalidTargetError, match="Repository is not a directory"):
        security.turn(tmp_path / "missing")
    assert security._codex.calls == []
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "old.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(OutputDirectoryError, match="must be empty"):
        security.turn(tmp_path, output_dir=occupied)
    assert security._codex.calls == []

    security.turn(tmp_path, output_dir=tmp_path / "scan")

    assert ("login_api_key", api_key) in security._codex.calls
    assert security._auth_available is True
    assert api_key not in repr(runtime)
    security.close()


def test_environment_api_key_is_materialized_for_async_runtime(
    tmp_path: Path,
    fake_runtime: api._PreparedRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_key = "sk-environment-secret"
    runtime = api._PreparedRuntime(
        codex_home=fake_runtime.codex_home,
        plugin=fake_runtime.plugin,
        codex_config=fake_runtime.codex_config,
        credentials_available=True,
        environment_api_key_available=True,
    )
    monkeypatch.setenv("OPENAI_API_KEY", api_key)
    monkeypatch.setattr(api, "_prepare_runtime", lambda config: runtime)
    monkeypatch.setattr(api, "AsyncCodex", FakeAsyncCodex)

    async def run() -> None:
        security = AsyncCodexSecurity()
        await security._ensure_initialized()

        assert security._codex.calls == []
        assert security._auth_available is False
        with pytest.raises(api.InvalidTargetError, match="Repository is not a directory"):
            await security.turn(tmp_path / "missing")
        assert security._codex.calls == []
        occupied = tmp_path / "occupied"
        occupied.mkdir()
        (occupied / "old.json").write_text("{}\n", encoding="utf-8")
        with pytest.raises(OutputDirectoryError, match="must be empty"):
            await security.turn(tmp_path, output_dir=occupied)
        assert security._codex.calls == []

        await security._ensure_automatic_auth()

        assert ("login_api_key", api_key) in security._codex.calls
        assert security._auth_available is True
        await security.close()

    asyncio.run(run())


def test_cancelled_async_environment_login_cleans_runtime(
    tmp_path: Path,
    fake_runtime: api._PreparedRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_key = "sk-environment-secret"
    runtime = api._PreparedRuntime(
        codex_home=fake_runtime.codex_home,
        plugin=fake_runtime.plugin,
        codex_config=fake_runtime.codex_config,
        credentials_available=True,
        environment_api_key_available=True,
    )
    instances: list[BlockingAsyncCodex] = []

    class BlockingAsyncCodex(FakeAsyncCodex):
        def __init__(self, config) -> None:
            super().__init__(config)
            self.login_started = asyncio.Event()
            instances.append(self)

        async def login_api_key(self, api_key: str) -> None:
            self.login_started.set()
            await asyncio.Event().wait()

    monkeypatch.setenv("OPENAI_API_KEY", api_key)
    monkeypatch.setattr(api, "_prepare_runtime", lambda config: runtime)
    monkeypatch.setattr(api, "AsyncCodex", BlockingAsyncCodex)

    async def run() -> None:
        security = AsyncCodexSecurity()
        await security._ensure_initialized()
        login = asyncio.create_task(security.turn(tmp_path))
        await instances[0].login_started.wait()

        login.cancel()
        with pytest.raises(asyncio.CancelledError):
            await login

        assert instances[0].closed is True
        assert security._codex is None
        assert security._runtime is None
        assert not runtime.codex_home.exists()

    asyncio.run(run())


def test_scan_requires_isolated_runtime_auth(
    tmp_path: Path,
    fake_runtime: api._PreparedRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_runtime = api._PreparedRuntime(
        codex_home=fake_runtime.codex_home,
        plugin=fake_runtime.plugin,
        codex_config=fake_runtime.codex_config,
        credentials_available=False,
    )
    monkeypatch.setattr(api, "_prepare_runtime", lambda config: fake_runtime)
    security = CodexSecurity()
    with pytest.raises(api.AuthenticationRequiredError, match="isolated Codex home"):
        security.turn(tmp_path)
    security.login_api_key("sk-test")
    handle = security.turn(tmp_path)
    assert handle.thread_id == "thread-1"
    security.close()


def test_sync_validates_repository_target_and_mode_before_auth(
    tmp_path: Path,
    fake_runtime: api._PreparedRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api, "_prepare_runtime", lambda config: _without_auth(fake_runtime))
    repository = tmp_path / "repo"
    repository.mkdir()
    security = CodexSecurity()

    with pytest.raises(api.InvalidTargetError, match="Repository is not a directory"):
        security.turn(tmp_path / "missing")
    with pytest.raises(api.InvalidTargetError, match="at least one path"):
        security.turn(repository, target=[])
    with pytest.raises(api.InvalidTargetError, match="mode must be"):
        security.turn(repository, mode="invalid")  # type: ignore[arg-type]

    security.close()


def test_sync_validates_output_before_auth_without_creating_it(
    tmp_path: Path,
    fake_runtime: api._PreparedRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api, "_prepare_runtime", lambda config: _without_auth(fake_runtime))
    repository = tmp_path / "repo"
    repository.mkdir()
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "old.json").write_text("{}\n", encoding="utf-8")
    absent = tmp_path / "new-parent" / "scan"
    security = CodexSecurity()

    with pytest.raises(OutputDirectoryError, match="must be empty"):
        security.turn(repository, output_dir=occupied)
    with pytest.raises(api.AuthenticationRequiredError, match="isolated Codex home"):
        security.turn(repository, output_dir=absent)
    assert not absent.exists()

    security.close()


def test_async_validates_scan_inputs_before_auth_without_creating_output(
    tmp_path: Path,
    fake_runtime: api._PreparedRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api, "_prepare_runtime", lambda config: _without_auth(fake_runtime))
    monkeypatch.setattr(api, "AsyncCodex", FakeAsyncCodex)
    repository = tmp_path / "repo"
    repository.mkdir()
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "old.json").write_text("{}\n", encoding="utf-8")
    absent = tmp_path / "new-parent" / "scan"

    async def run() -> None:
        security = AsyncCodexSecurity()
        with pytest.raises(api.InvalidTargetError, match="Repository is not a directory"):
            await security.turn(tmp_path / "missing")
        with pytest.raises(api.InvalidTargetError, match="at least one path"):
            await security.turn(repository, target=[])
        with pytest.raises(api.InvalidTargetError, match="mode must be"):
            await security.turn(repository, mode="invalid")  # type: ignore[arg-type]
        with pytest.raises(OutputDirectoryError, match="must be empty"):
            await security.turn(repository, output_dir=occupied)
        with pytest.raises(api.AuthenticationRequiredError, match="isolated Codex home"):
            await security.turn(repository, output_dir=absent)
        assert not absent.exists()
        await security.close()

    asyncio.run(run())


def test_cli_reports_missing_repository_before_auth(
    tmp_path: Path,
    fake_runtime: api._PreparedRuntime,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(api, "_prepare_runtime", lambda config: _without_auth(fake_runtime))

    assert cli.main(["scan", str(tmp_path / "missing")]) == 1
    error = capsys.readouterr().err
    assert "Repository is not a directory" in error
    assert "authentication" not in error.lower()


def test_cli_reports_occupied_output_before_auth(
    tmp_path: Path,
    fake_runtime: api._PreparedRuntime,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(api, "_prepare_runtime", lambda config: _without_auth(fake_runtime))
    repository = tmp_path / "repo"
    repository.mkdir()
    output = tmp_path / "occupied"
    output.mkdir()
    (output / "old.json").write_text("{}\n", encoding="utf-8")

    assert cli.main(["scan", str(repository), "--output-dir", str(output)]) == 1
    error = capsys.readouterr().err
    assert "Scan output directory must be empty" in error
    assert "authentication" not in error.lower()


def test_close_cleans_runtime_when_underlying_close_fails(
    fake_runtime: api._PreparedRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api, "Codex", FailingCloseCodex)
    security = CodexSecurity()
    home = fake_runtime.codex_home
    with pytest.raises(RuntimeError, match="close failed"):
        security.close()
    assert not home.exists()
    assert security._runtime is None
    assert security._codex is None


def test_closed_client_does_not_create_output(
    tmp_path: Path,
    fake_runtime: api._PreparedRuntime,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    output = tmp_path / "scan"
    security = CodexSecurity()
    security.close()
    with pytest.raises(RuntimeError, match="closed"):
        security.turn(repository, output_dir=output)
    assert not output.exists()


def test_async_init_failure_cleans_runtime(
    fake_runtime: api._PreparedRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api, "AsyncCodex", FailingAsyncCodex)
    security = AsyncCodexSecurity()
    home = fake_runtime.codex_home
    with pytest.raises(RuntimeError, match="init failed"):
        asyncio.run(security._ensure_initialized())
    assert not home.exists()
    assert security._runtime is None
    assert security._codex is None


def test_async_init_cancellation_cleans_completed_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = threading.Event()
    release = threading.Event()
    home = tmp_path / "home"

    def prepare(_config) -> api._PreparedRuntime:
        home.mkdir()
        (home / "auth.json").write_text('{"token":"test"}\n', encoding="utf-8")
        started.set()
        assert release.wait(timeout=5)
        return api._PreparedRuntime(
            codex_home=home,
            plugin=PluginInstall(
                plugin_root=PLUGIN_ROOT,
                marketplace_root=tmp_path / "marketplace",
                installed_root=PLUGIN_ROOT,
                marketplace_name="test",
                name="codex-security",
                version=PLUGIN_VERSION,
            ),
            codex_config=CodexConfig(),
            credentials_available=True,
        )

    monkeypatch.setattr(api, "_prepare_runtime", prepare)

    async def run() -> None:
        security = AsyncCodexSecurity()
        task = asyncio.create_task(security._ensure_initialized())
        assert await asyncio.to_thread(started.wait, 5)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert security._runtime is None
        assert security._codex is None
        assert security._init_task is None

    asyncio.run(run())
    assert not home.exists()


def test_scan_handle_delegates_controls(tmp_path: Path) -> None:
    turn = FakeTurn(tmp_path)
    expectation = api.ScanExpectation(
        repository=tmp_path,
        repository_revision=None,
        target=api.NormalizedTarget(kind="repository"),
        mode="standard",
        plugin_version=PLUGIN_VERSION,
    )
    handle = ScanHandle(turn, "thread-1", tmp_path, PLUGIN_ROOT, expectation)
    assert handle.id == "turn-1"
    assert list(handle.stream()) == ["one", "two"]
    assert handle.steer("focus") == "steered"
    assert handle.interrupt() == "interrupted"


def test_deep_diff_is_rejected(tmp_path: Path, fake_runtime: api._PreparedRuntime) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess = pytest.importorskip("subprocess")
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / "file").write_text("x", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, check=True)
    with CodexSecurity() as security:
        with pytest.raises(api.InvalidTargetError, match="Deep mode"):
            security.turn(
                repo,
                target=DiffTarget.refs(base="HEAD", head="HEAD"),
                mode="deep",
            )


def test_working_tree_prompt_uses_combined_scope() -> None:
    prompt = api._target_instruction(
        api.NormalizedTarget(kind="working_tree", base="sha", base_ref="HEAD")
    )
    assert "staged and unstaged working-tree changes against HEAD" in prompt
    assert "--local-patch-scope" not in prompt


def test_collect_result_requires_markdown_report(tmp_path: Path) -> None:
    scan_dir = tmp_path / "scan"
    shutil.copytree(EXAMPLE, scan_dir)
    expectation = api.ScanExpectation(
        repository=tmp_path,
        repository_revision="deadbeef",
        target=api.NormalizedTarget(kind="repository"),
        mode="standard",
        plugin_version="0.1.0",
    )

    with pytest.raises(api.IncompleteScanError, match="report.md"):
        api._collect_result(
            _turn_result(),
            "thread-1",
            scan_dir,
            PLUGIN_ROOT,
            expectation,
        )


def test_public_scan_signatures_match() -> None:
    sync = inspect.signature(CodexSecurity.run)
    async_signature = inspect.signature(AsyncCodexSecurity.run)
    assert list(sync.parameters) == list(async_signature.parameters)
    assert sync.parameters["target"].default == "repository"
    assert sync.parameters["mode"].default == "standard"
