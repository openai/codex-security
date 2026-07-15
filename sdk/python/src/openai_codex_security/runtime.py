from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path, PurePosixPath, PureWindowsPath

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib

from .errors import OutputDirectoryError, PluginBootstrapError

MARKETPLACE_NAME = "codex-security-sdk"
PLUGIN_NAME = "codex-security"


@dataclass(frozen=True, slots=True)
class PluginInstall:
    plugin_root: Path
    marketplace_root: Path
    installed_root: Path
    marketplace_name: str
    name: str
    version: str


def _source_plugin_root() -> Path | None:
    module_path = Path(__file__).absolute()
    if len(module_path.parents) <= 4:
        return None
    candidate = module_path.parents[4] / "plugins/codex-security"
    return candidate if (candidate / ".codex-plugin/plugin.json").is_file() else None


def bundled_plugin_root() -> Path:
    source_root = _source_plugin_root()
    if source_root is not None:
        return source_root
    packaged = files("openai_codex_security").joinpath("_bundled_plugin")
    path = Path(str(packaged))
    if not (path / ".codex-plugin/plugin.json").is_file():
        raise PluginBootstrapError("The bundled Codex Security plugin is missing.")
    return path


def validate_output_dir(output_dir: str | os.PathLike[str] | None) -> Path | None:
    """Validate an explicit scan output path without creating it."""

    if output_dir is None:
        return None
    try:
        path = Path(output_dir).expanduser().resolve()
        if path.exists():
            if not path.is_dir():
                raise OutputDirectoryError(f"Scan output is not a directory: {path}")
            if any(path.iterdir()):
                raise OutputDirectoryError(f"Scan output directory must be empty: {path}")
            return path

        parent = path.parent
        while not parent.exists() and parent != parent.parent:
            parent = parent.parent
        if not parent.is_dir():
            raise OutputDirectoryError(f"Unable to create scan output directory: {path}")
        return path
    except OutputDirectoryError:
        raise
    except (OSError, RuntimeError) as exc:
        raise OutputDirectoryError(
            f"Unable to inspect scan output directory: {output_dir}"
        ) from exc


def prepare_output_dir(output_dir: str | os.PathLike[str] | None, repo_name: str) -> Path:
    path = validate_output_dir(output_dir)
    if path is None:
        return Path(tempfile.mkdtemp(prefix=f"codex-security-{repo_name}-")).resolve()
    if not path.exists():
        try:
            path.mkdir(parents=True)
        except OSError as exc:
            raise OutputDirectoryError(f"Unable to create scan output directory: {path}") from exc
    return path


def create_isolated_home() -> Path:
    path = Path(tempfile.mkdtemp(prefix="openai-codex-security-home-")).resolve()
    path.chmod(0o700)
    return path


def import_ambient_auth(ambient_home: Path, isolated_home: Path) -> bool:
    source = ambient_home.expanduser() / "auth.json"
    if not source.is_file():
        return False
    isolated_home.mkdir(parents=True, exist_ok=True)
    destination = isolated_home / "auth.json"
    shutil.copyfile(source, destination)
    destination.chmod(0o600)
    return True


def extract_plugin_zip(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(archive) as handle:
            for info in handle.infolist():
                path = PurePosixPath(info.filename)
                mode = info.external_attr >> 16
                if (
                    not info.filename
                    or path.is_absolute()
                    or ".." in path.parts
                    or "\\" in info.filename
                    or PureWindowsPath(info.filename).drive
                    or any(":" in part for part in path.parts)
                    or stat.S_ISLNK(mode)
                ):
                    raise PluginBootstrapError(
                        f"Plugin ZIP contains an unsafe path: {info.filename}"
                    )
                target = destination.joinpath(*path.parts)
                try:
                    target.resolve(strict=False).relative_to(destination.resolve())
                except (RuntimeError, ValueError) as exc:
                    raise PluginBootstrapError(
                        f"Plugin ZIP contains an unsafe path: {info.filename}"
                    ) from exc
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with handle.open(info) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
    except zipfile.BadZipFile as exc:
        raise PluginBootstrapError(f"Invalid plugin ZIP: {archive}") from exc
    return _discover_plugin_root(destination)


def resolve_plugin_path(plugin_path: str | os.PathLike[str] | None, workspace: Path) -> Path:
    if plugin_path is None:
        source = bundled_plugin_root()
        source_plugin = _source_plugin_root()
        if source_plugin is not None and source == source_plugin:
            destination = workspace / "bundled-plugin"
            _copy_external_payload(source, destination)
            return destination
        return source

    path = Path(plugin_path).expanduser().resolve()
    if path.is_file() and path.suffix.lower() == ".zip":
        return extract_plugin_zip(path, workspace / "extracted-plugin")
    if path.is_dir():
        return _validate_plugin_root(path)
    raise PluginBootstrapError(f"Plugin path must be a directory or ZIP: {path}")


def create_marketplace(codex_home: Path, plugin_root: Path) -> Path:
    plugin_root = _validate_plugin_root(plugin_root)
    marketplace = codex_home / "sdk-marketplace"
    plugin_destination = marketplace / "plugins/codex-security"
    _copy_plugin_tree(plugin_root, plugin_destination)
    manifest = {
        "name": MARKETPLACE_NAME,
        "interface": {"displayName": "Codex Security SDK"},
        "plugins": [
            {
                "name": PLUGIN_NAME,
                "source": {
                    "source": "local",
                    "path": "./plugins/codex-security",
                },
                "policy": {
                    "installation": "AVAILABLE",
                    "authentication": "ON_INSTALL",
                },
                "category": "Security",
            }
        ],
    }
    manifest_path = marketplace / ".agents/plugins/marketplace.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return marketplace


def resolve_codex_bin() -> Path:
    try:
        from codex_cli_bin import bundled_codex_path
    except ImportError as exc:
        raise PluginBootstrapError(
            "Unable to locate the Codex runtime bundled with openai-codex."
        ) from exc
    return bundled_codex_path()


def bootstrap_plugin(codex_home: Path, plugin_root: Path) -> PluginInstall:
    plugin_root = _validate_plugin_root(plugin_root)
    name, version = plugin_metadata(plugin_root)
    marketplace = create_marketplace(codex_home, plugin_root)
    codex_bin = resolve_codex_bin()
    env = os.environ.copy()
    env["CODEX_HOME"] = str(codex_home)
    _run_codex(
        codex_bin,
        ["plugin", "marketplace", "add", str(marketplace)],
        env,
    )
    _run_codex(
        codex_bin,
        ["plugin", "add", f"{PLUGIN_NAME}@{MARKETPLACE_NAME}"],
        env,
    )
    _verify_plugin_registration(codex_home, marketplace)
    installed_root = _find_installed_plugin(codex_home)
    installed_name, installed_version = plugin_metadata(installed_root)
    if (installed_name, installed_version) != (name, version):
        raise PluginBootstrapError(
            "Installed Codex Security plugin metadata does not match the selected plugin."
        )
    return PluginInstall(
        plugin_root=plugin_root,
        marketplace_root=marketplace,
        installed_root=installed_root,
        marketplace_name=MARKETPLACE_NAME,
        name=name,
        version=version,
    )


def _run_codex(codex_bin: Path, args: list[str], env: dict[str, str]) -> str:
    result = subprocess.run(
        [str(codex_bin), *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise PluginBootstrapError(f"Codex plugin bootstrap failed: {detail}")
    return result.stdout


def _find_installed_plugin(codex_home: Path) -> Path:
    root = codex_home / "plugins/cache" / MARKETPLACE_NAME / PLUGIN_NAME
    candidates = (
        [
            path
            for path in root.iterdir()
            if path.is_dir() and (path / ".codex-plugin/plugin.json").is_file()
        ]
        if root.is_dir()
        else []
    )
    if len(candidates) != 1:
        raise PluginBootstrapError(
            "Codex plugin install did not produce one installed Codex Security plugin."
        )
    return candidates[0].resolve()


def _discover_plugin_root(root: Path) -> Path:
    if (root / ".codex-plugin/plugin.json").is_file():
        return _validate_plugin_root(root)
    children = [child for child in root.iterdir() if child.is_dir()]
    if len(children) == 1 and (children[0] / ".codex-plugin/plugin.json").is_file():
        return _validate_plugin_root(children[0])
    raise PluginBootstrapError(
        "Plugin ZIP must contain Codex Security at its root or in one top-level directory."
    )


def _validate_plugin_root(root: Path) -> Path:
    plugin_metadata(root)
    return root.resolve()


def plugin_metadata(root: Path) -> tuple[str, str]:
    manifest_path = root / ".codex-plugin/plugin.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PluginBootstrapError(f"Invalid Codex plugin directory: {root}") from exc
    if not isinstance(manifest, dict) or manifest.get("name") != PLUGIN_NAME:
        raise PluginBootstrapError("Plugin manifest must have name 'codex-security'.")
    version = manifest.get("version")
    if not isinstance(version, str) or not version.strip():
        raise PluginBootstrapError("Plugin manifest must have a non-empty version.")
    return PLUGIN_NAME, version


def _verify_plugin_registration(codex_home: Path, marketplace: Path) -> None:
    config_path = codex_home / "config.toml"
    try:
        with config_path.open("rb") as source:
            config = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PluginBootstrapError(
            "Codex plugin bootstrap produced an unreadable config.toml."
        ) from exc

    marketplaces = config.get("marketplaces")
    plugins = config.get("plugins")
    marketplace_config = (
        marketplaces.get(MARKETPLACE_NAME) if isinstance(marketplaces, dict) else None
    )
    plugin_config = (
        plugins.get(f"{PLUGIN_NAME}@{MARKETPLACE_NAME}") if isinstance(plugins, dict) else None
    )
    if not isinstance(marketplace_config, dict) or not isinstance(plugin_config, dict):
        raise PluginBootstrapError("Codex plugin bootstrap did not preserve plugin registration.")
    # Codex canonicalizes local sources; Windows can persist a device-prefixed alias.
    registered_source = Path(str(marketplace_config.get("source", "")))
    try:
        source_matches_marketplace = registered_source.samefile(marketplace)
    except (OSError, ValueError):
        source_matches_marketplace = False
    if not source_matches_marketplace:
        raise PluginBootstrapError("Codex plugin marketplace registration has the wrong source.")
    if plugin_config.get("enabled") is not True:
        raise PluginBootstrapError("Codex Security plugin is not enabled after bootstrap.")


def _copy_plugin_tree(source: Path, destination: Path) -> None:
    for path in source.rglob("*"):
        if path.is_symlink():
            raise PluginBootstrapError(f"Plugin contains a symbolic link: {path}")
    shutil.copytree(source, destination)


def _copy_external_payload(source: Path, destination: Path) -> None:
    contract_path = source / ".internal/external-promotion/external-projection-contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    relative_paths = [
        path
        for path in [".codex-plugin/plugin.json", *contract["shippedExact"]]
        if not path.startswith("sdk/")
    ]
    for relative in relative_paths:
        source_path = source / relative
        destination_path = destination / relative
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination_path)
