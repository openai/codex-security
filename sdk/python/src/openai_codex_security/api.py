from __future__ import annotations

import asyncio
import os
import shutil
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from openai_codex import (
    AsyncChatgptLoginHandle,
    AsyncCodex,
    AsyncDeviceCodeLoginHandle,
    ChatgptLoginHandle,
    Codex,
    CodexConfig,
    DeviceCodeLoginHandle,
    RunInput,
    Sandbox,
    SkillInput,
    TextInput,
    TurnResult,
)

from .config import CodexSecurityConfig, merged_codex_config, write_codex_config
from .contract import ScanExpectation, load_contract, require_scan_file
from .errors import AuthenticationRequiredError, IncompleteScanError, InvalidTargetError
from .result import ScanResult
from .runtime import (
    PluginInstall,
    bootstrap_plugin,
    create_isolated_home,
    import_ambient_auth,
    prepare_output_dir,
    resolve_plugin_path,
    validate_output_dir,
)
from .targets import (
    NormalizedTarget,
    PathInput,
    ScanMode,
    ScanTarget,
    normalize_repository,
    normalize_target,
    repository_revision,
)


@dataclass(frozen=True, slots=True)
class _PreparedRuntime:
    codex_home: Path
    plugin: PluginInstall
    codex_config: CodexConfig
    credentials_available: bool
    environment_api_key_available: bool = False


class CodexSecurity:
    """Synchronous client for running Codex Security scans."""

    def __init__(self, config: CodexSecurityConfig | None = None) -> None:
        self.config = config or CodexSecurityConfig()
        self._runtime: _PreparedRuntime | None = None
        self._codex: Codex | None = None
        try:
            self._runtime = _prepare_runtime(self.config)
            self._codex = Codex(config=self._runtime.codex_config)
            self._auth_available = (
                self._runtime.credentials_available
                and not self._runtime.environment_api_key_available
            )
        except Exception:
            if self._codex is not None:
                try:
                    self._codex.close()
                except Exception:
                    pass
                self._codex = None
            self._cleanup_runtime()
            raise

    def __enter__(self) -> CodexSecurity:
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()

    @property
    def metadata(self):
        return self._require_codex().metadata

    def close(self) -> None:
        codex = self._codex
        self._codex = None
        try:
            if codex is not None:
                codex.close()
        finally:
            self._auth_available = False
            self._cleanup_runtime()

    def login_api_key(self, api_key: str) -> None:
        self._require_codex().login_api_key(api_key)
        self._auth_available = True

    def login_chatgpt(self):
        return _SyncChatgptLoginHandle(self._require_codex().login_chatgpt(), self)

    def login_chatgpt_device_code(self):
        return _SyncDeviceCodeLoginHandle(self._require_codex().login_chatgpt_device_code(), self)

    def account(self, *, refresh_token: bool = False):
        return self._require_codex().account(refresh_token=refresh_token)

    def logout(self) -> None:
        self._require_codex().logout()
        self._auth_available = False

    def run(
        self,
        repository: PathInput,
        *,
        target: ScanTarget = "repository",
        mode: ScanMode = "standard",
        output_dir: PathInput | None = None,
    ) -> ScanResult:
        return self.turn(
            repository,
            target=target,
            mode=mode,
            output_dir=output_dir,
        ).run()

    def turn(
        self,
        repository: PathInput,
        *,
        target: ScanTarget = "repository",
        mode: ScanMode = "standard",
        output_dir: PathInput | None = None,
        _on_output_dir_ready: Callable[[Path], None] | None = None,
    ) -> ScanHandle:
        codex = self._require_codex()
        runtime = self._require_runtime()
        repo, normalized = _validate_scan(repository, target, mode, output_dir)
        self._ensure_automatic_auth()
        self._require_auth()
        scan_dir = prepare_output_dir(output_dir, repo.name)
        if _on_output_dir_ready is not None:
            _on_output_dir_ready(scan_dir)
        thread = codex.thread_start(
            cwd=str(scan_dir),
            config=_scan_thread_config(scan_dir),
            sandbox=Sandbox.workspace_write,
        )
        turn = thread.turn(
            _scan_input(runtime.plugin.installed_root, repo, normalized, mode, scan_dir),
            cwd=str(scan_dir),
        )
        expectation = _scan_expectation(repo, normalized, mode, runtime.plugin.version)
        return ScanHandle(
            turn,
            thread.id,
            scan_dir,
            runtime.plugin.installed_root,
            expectation,
        )

    def _require_codex(self) -> Codex:
        if self._codex is None:
            raise RuntimeError("CodexSecurity is closed.")
        return self._codex

    def _require_runtime(self) -> _PreparedRuntime:
        if self._runtime is None:
            raise RuntimeError("CodexSecurity is closed.")
        return self._runtime

    def _cleanup_runtime(self) -> None:
        if self._runtime is not None:
            shutil.rmtree(self._runtime.codex_home, ignore_errors=True)
            self._runtime = None

    def _ensure_automatic_auth(self) -> None:
        if self._auth_available:
            return
        runtime = self._require_runtime()
        if not runtime.environment_api_key_available:
            return
        self._require_codex().login_api_key(_required_environment_api_key())
        self._auth_available = True

    def _require_auth(self) -> None:
        if not self._auth_available:
            raise AuthenticationRequiredError(
                "The isolated Codex home has no reusable authentication. Set OPENAI_API_KEY or "
                "CODEX_API_KEY, call a login method, or use file-backed Codex authentication."
            )


class AsyncCodexSecurity:
    """Asynchronous mirror of :class:`CodexSecurity`."""

    def __init__(self, config: CodexSecurityConfig | None = None) -> None:
        self.config = config or CodexSecurityConfig()
        self._runtime: _PreparedRuntime | None = None
        self._codex: AsyncCodex | None = None
        self._init_lock = asyncio.Lock()
        self._init_task: asyncio.Task[_PreparedRuntime] | None = None
        self._auth_available = False

    async def __aenter__(self) -> AsyncCodexSecurity:
        await self._ensure_initialized()
        assert self._codex is not None
        try:
            await self._codex.__aenter__()
        except Exception:
            await self.close()
            raise
        return self

    async def __aexit__(self, _exc_type, _exc, _tb) -> None:
        await self.close()

    async def _ensure_initialized(self) -> None:
        if self._codex is not None:
            return
        async with self._init_lock:
            if self._codex is not None:
                return
            task = asyncio.create_task(asyncio.to_thread(_prepare_runtime, self.config))
            self._init_task = task
            try:
                runtime = await asyncio.shield(task)
            except asyncio.CancelledError:
                try:
                    runtime = await task
                except Exception:
                    pass
                else:
                    await asyncio.to_thread(shutil.rmtree, runtime.codex_home, True)
                self._init_task = None
                raise
            except Exception:
                self._init_task = None
                raise
            self._init_task = None
            try:
                self._runtime = runtime
                self._codex = AsyncCodex(config=runtime.codex_config)
                self._auth_available = (
                    runtime.credentials_available and not runtime.environment_api_key_available
                )
            except Exception:
                if self._codex is not None:
                    try:
                        await self._codex.close()
                    except Exception:
                        pass
                    self._codex = None
                self._runtime = None
                await asyncio.to_thread(shutil.rmtree, runtime.codex_home, True)
                raise

    @property
    def metadata(self):
        if self._codex is None:
            raise RuntimeError(
                "AsyncCodexSecurity is not initialized yet. Prefer `async with "
                "AsyncCodexSecurity()`."
            )
        return self._codex.metadata

    async def close(self) -> None:
        codex = self._codex
        runtime = self._runtime
        self._codex = None
        self._runtime = None
        try:
            if codex is not None:
                await codex.close()
        finally:
            self._auth_available = False
            if runtime is not None:
                await asyncio.to_thread(shutil.rmtree, runtime.codex_home, True)

    async def login_api_key(self, api_key: str) -> None:
        await self._ensure_initialized()
        assert self._codex is not None
        await self._codex.login_api_key(api_key)
        self._auth_available = True

    async def login_chatgpt(self):
        await self._ensure_initialized()
        assert self._codex is not None
        return _AsyncChatgptLoginHandle(await self._codex.login_chatgpt(), self)

    async def login_chatgpt_device_code(self):
        await self._ensure_initialized()
        assert self._codex is not None
        return _AsyncDeviceCodeLoginHandle(await self._codex.login_chatgpt_device_code(), self)

    async def account(self, *, refresh_token: bool = False):
        await self._ensure_initialized()
        assert self._codex is not None
        return await self._codex.account(refresh_token=refresh_token)

    async def logout(self) -> None:
        await self._ensure_initialized()
        assert self._codex is not None
        await self._codex.logout()
        self._auth_available = False

    async def run(
        self,
        repository: PathInput,
        *,
        target: ScanTarget = "repository",
        mode: ScanMode = "standard",
        output_dir: PathInput | None = None,
    ) -> ScanResult:
        handle = await self.turn(
            repository,
            target=target,
            mode=mode,
            output_dir=output_dir,
        )
        return await handle.run()

    async def turn(
        self,
        repository: PathInput,
        *,
        target: ScanTarget = "repository",
        mode: ScanMode = "standard",
        output_dir: PathInput | None = None,
        _on_output_dir_ready: Callable[[Path], None] | None = None,
    ) -> AsyncScanHandle:
        await self._ensure_initialized()
        assert self._codex is not None
        assert self._runtime is not None
        repo, normalized = _validate_scan(repository, target, mode, output_dir)
        await self._ensure_automatic_auth()
        self._require_auth()
        scan_dir = prepare_output_dir(output_dir, repo.name)
        if _on_output_dir_ready is not None:
            _on_output_dir_ready(scan_dir)
        thread = await self._codex.thread_start(
            cwd=str(scan_dir),
            config=_scan_thread_config(scan_dir),
            sandbox=Sandbox.workspace_write,
        )
        turn = await thread.turn(
            _scan_input(self._runtime.plugin.installed_root, repo, normalized, mode, scan_dir),
            cwd=str(scan_dir),
        )
        expectation = _scan_expectation(
            repo,
            normalized,
            mode,
            self._runtime.plugin.version,
        )
        return AsyncScanHandle(
            turn,
            thread.id,
            scan_dir,
            self._runtime.plugin.installed_root,
            expectation,
        )

    async def _ensure_automatic_auth(self) -> None:
        if self._auth_available:
            return
        assert self._codex is not None
        assert self._runtime is not None
        if not self._runtime.environment_api_key_available:
            return
        try:
            await self._codex.login_api_key(_required_environment_api_key())
        except asyncio.CancelledError:
            await self.close()
            raise
        self._auth_available = True

    def _require_auth(self) -> None:
        if not self._auth_available:
            raise AuthenticationRequiredError(
                "The isolated Codex home has no reusable authentication. Set OPENAI_API_KEY or "
                "CODEX_API_KEY, call a login method, or use file-backed Codex authentication."
            )


@dataclass(slots=True)
class _SyncLoginHandle:
    _handle: ChatgptLoginHandle | DeviceCodeLoginHandle
    _owner: CodexSecurity

    def wait(self):
        result = self._handle.wait()
        self._owner._auth_available = result.success
        return result

    def cancel(self):
        return self._handle.cancel()


@dataclass(slots=True)
class _SyncChatgptLoginHandle(_SyncLoginHandle):
    _handle: ChatgptLoginHandle

    @property
    def login_id(self) -> str:
        return self._handle.login_id

    @property
    def auth_url(self) -> str:
        return self._handle.auth_url


@dataclass(slots=True)
class _SyncDeviceCodeLoginHandle(_SyncLoginHandle):
    _handle: DeviceCodeLoginHandle

    @property
    def login_id(self) -> str:
        return self._handle.login_id

    @property
    def verification_url(self) -> str:
        return self._handle.verification_url

    @property
    def user_code(self) -> str:
        return self._handle.user_code


@dataclass(slots=True)
class _AsyncLoginHandle:
    _handle: AsyncChatgptLoginHandle | AsyncDeviceCodeLoginHandle
    _owner: AsyncCodexSecurity

    async def wait(self):
        result = await self._handle.wait()
        self._owner._auth_available = result.success
        return result

    async def cancel(self):
        return await self._handle.cancel()


@dataclass(slots=True)
class _AsyncChatgptLoginHandle(_AsyncLoginHandle):
    _handle: AsyncChatgptLoginHandle

    @property
    def login_id(self) -> str:
        return self._handle.login_id

    @property
    def auth_url(self) -> str:
        return self._handle.auth_url


@dataclass(slots=True)
class _AsyncDeviceCodeLoginHandle(_AsyncLoginHandle):
    _handle: AsyncDeviceCodeLoginHandle

    @property
    def login_id(self) -> str:
        return self._handle.login_id

    @property
    def verification_url(self) -> str:
        return self._handle.verification_url

    @property
    def user_code(self) -> str:
        return self._handle.user_code


@dataclass(slots=True)
class ScanHandle:
    """Control and consume a synchronous Codex Security scan."""

    _turn: Any
    thread_id: str
    scan_dir: Path
    _plugin_root: Path
    _expectation: ScanExpectation

    @property
    def id(self) -> str:
        return self._turn.id

    def steer(self, input: RunInput):
        return self._turn.steer(input)

    def interrupt(self):
        return self._turn.interrupt()

    def stream(self) -> Iterator[Any]:
        return self._turn.stream()

    def run(self) -> ScanResult:
        return _collect_result(
            self._turn.run(),
            self.thread_id,
            self.scan_dir,
            self._plugin_root,
            self._expectation,
        )


@dataclass(slots=True)
class AsyncScanHandle:
    """Control and consume an asynchronous Codex Security scan."""

    _turn: Any
    thread_id: str
    scan_dir: Path
    _plugin_root: Path
    _expectation: ScanExpectation

    @property
    def id(self) -> str:
        return self._turn.id

    async def steer(self, input: RunInput):
        return await self._turn.steer(input)

    async def interrupt(self):
        return await self._turn.interrupt()

    def stream(self) -> AsyncIterator[Any]:
        return self._turn.stream()

    async def run(self) -> ScanResult:
        turn_result = await self._turn.run()
        return await asyncio.to_thread(
            _collect_result,
            turn_result,
            self.thread_id,
            self.scan_dir,
            self._plugin_root,
            self._expectation,
        )


def _prepare_runtime(config: CodexSecurityConfig) -> _PreparedRuntime:
    codex_home = create_isolated_home()
    try:
        workspace = codex_home / "bootstrap"
        workspace.mkdir(parents=True)
        plugin_root = resolve_plugin_path(config.plugin_path, workspace)
        write_codex_config(
            codex_home / "config.toml",
            merged_codex_config(config, plugin_root=plugin_root),
        )
        plugin = bootstrap_plugin(codex_home, plugin_root)
        environment_api_key_available = _environment_api_key() is not None
        credentials_available = environment_api_key_available
        if not credentials_available:
            ambient_home = Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()
            credentials_available = import_ambient_auth(ambient_home, codex_home)
        codex_config = CodexConfig(
            env={"CODEX_HOME": str(codex_home)},
            client_name="codex_security_python_sdk",
            client_title="Codex Security Python SDK",
        )
        return _PreparedRuntime(
            codex_home,
            plugin,
            codex_config,
            credentials_available,
            environment_api_key_available,
        )
    except Exception:
        shutil.rmtree(codex_home, ignore_errors=True)
        raise


def _environment_api_key() -> str | None:
    """Return the configured API key without copying it into runtime metadata."""

    return os.environ.get("OPENAI_API_KEY") or os.environ.get("CODEX_API_KEY")


def _required_environment_api_key() -> str:
    api_key = _environment_api_key()
    if api_key is None:
        raise AuthenticationRequiredError(
            "The API key environment variable disappeared while preparing the isolated "
            "Codex runtime."
        )
    return api_key


def _validate_scan(
    repository: PathInput,
    target: ScanTarget,
    mode: ScanMode,
    output_dir: PathInput | None,
) -> tuple[Path, NormalizedTarget]:
    repo = normalize_repository(repository)
    if mode not in ("standard", "deep"):
        raise InvalidTargetError("mode must be 'standard' or 'deep'.")
    normalized = normalize_target(repo, target)
    if mode == "deep" and normalized.kind in ("refs", "working_tree"):
        raise InvalidTargetError(
            "Deep mode supports repository and path targets, not diff targets."
        )
    validate_output_dir(output_dir)
    return repo, normalized


def _scan_thread_config(scan_dir: Path) -> dict[str, object]:
    return {
        "sandbox_workspace_write": {
            "writable_roots": [str(scan_dir)],
        }
    }


def _scan_input(
    plugin_root: Path,
    repository: Path,
    target: NormalizedTarget,
    mode: ScanMode,
    scan_dir: Path,
) -> list[TextInput | SkillInput]:
    skill_name = _skill_name(target, mode)
    skill_path = plugin_root / "skills" / skill_name / "SKILL.md"
    if not skill_path.is_file():
        raise IncompleteScanError(f"Installed plugin is missing scan skill: {skill_name}")
    prompt = "\n".join(
        [
            "Run this Codex Security scan non-interactively.",
            "This SDK host does not render MCP Apps; use the terminal/chat workflow.",
            f"Repository root: {repository}",
            f"Use this exact scan directory for all scan output: {scan_dir}",
            _target_instruction(target),
            "Complete and seal the canonical JSON contract before returning.",
        ]
    )
    return [
        TextInput(prompt),
        SkillInput(f"codex-security:{skill_name}", str(skill_path)),
    ]


def _skill_name(target: NormalizedTarget, mode: ScanMode) -> str:
    if target.kind in ("refs", "working_tree"):
        return "security-diff-scan"
    return "deep-security-scan" if mode == "deep" else "security-scan"


def _target_instruction(target: NormalizedTarget) -> str:
    if target.kind == "repository":
        return "Scan target: the entire repository."
    if target.kind == "paths":
        return "Scan target paths: " + ", ".join(target.paths)
    if target.kind == "refs":
        return f"Scan target: Git diff from {target.base_ref} to {target.head_ref}."
    return f"Scan target: staged and unstaged working-tree changes against {target.base_ref}."


def _scan_expectation(
    repository: Path,
    target: NormalizedTarget,
    mode: ScanMode,
    plugin_version: str,
) -> ScanExpectation:
    return ScanExpectation(
        repository=repository,
        repository_revision=repository_revision(repository),
        target=target,
        mode=mode,
        plugin_version=plugin_version,
    )


def _collect_result(
    turn_result: TurnResult,
    thread_id: str,
    scan_dir: Path,
    plugin_root: Path,
    expectation: ScanExpectation,
) -> ScanResult:
    required = ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
    missing = [name for name in required if not (scan_dir / name).is_file()]
    if missing:
        raise IncompleteScanError(
            "Codex Security scan completed without required artifacts: " + ", ".join(missing)
        )
    require_scan_file(scan_dir, "report.md", "report.md")
    manifest, findings, coverage = load_contract(
        scan_dir,
        plugin_root=plugin_root,
        expectation=expectation,
    )
    return ScanResult(
        manifest=manifest,
        findings=findings,
        coverage=coverage,
        scan_dir=scan_dir,
        thread_id=thread_id,
        turn_result=turn_result,
    )
