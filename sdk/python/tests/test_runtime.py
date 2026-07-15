from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

import openai_codex_security.runtime as runtime
from openai_codex_security import PluginBootstrapError
from openai_codex_security.runtime import (
    bootstrap_plugin,
    bundled_plugin_root,
    create_marketplace,
    extract_plugin_zip,
    import_ambient_auth,
)


def _plugin(root: Path) -> Path:
    plugin = root / "plugin"
    (plugin / ".codex-plugin").mkdir(parents=True)
    (plugin / ".codex-plugin/plugin.json").write_text(
        json.dumps({"name": "codex-security", "version": "1.2.3"}),
        encoding="utf-8",
    )
    return plugin


def test_create_marketplace_wraps_plugin(tmp_path: Path) -> None:
    plugin = _plugin(tmp_path)
    marketplace = create_marketplace(tmp_path / "home", plugin)
    payload = json.loads(
        (marketplace / ".agents/plugins/marketplace.json").read_text(encoding="utf-8")
    )
    assert payload["name"] == "codex-security-sdk"
    assert payload["plugins"][0]["source"]["path"] == "./plugins/codex-security"
    assert (marketplace / "plugins/codex-security/.codex-plugin/plugin.json").is_file()


def test_zip_may_contain_one_top_level_directory(tmp_path: Path) -> None:
    archive = tmp_path / "plugin.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            "release/.codex-plugin/plugin.json",
            json.dumps({"name": "codex-security", "version": "1.2.3"}),
        )
    plugin = extract_plugin_zip(archive, tmp_path / "extract")
    assert plugin.name == "release"


def test_zip_rejects_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "plugin.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../escape", "bad")
    with pytest.raises(PluginBootstrapError, match="unsafe"):
        extract_plugin_zip(archive, tmp_path / "extract")


def test_malformed_zip_raises_plugin_bootstrap_error(tmp_path: Path) -> None:
    archive = tmp_path / "plugin.zip"
    archive.write_bytes(b"not a zip archive")

    with pytest.raises(PluginBootstrapError, match="Invalid plugin ZIP") as exc_info:
        extract_plugin_zip(archive, tmp_path / "extract")

    assert isinstance(exc_info.value.__cause__, zipfile.BadZipFile)


@pytest.mark.parametrize("name", ["D:/escape", "D:escape", "//server/share/escape"])
def test_zip_rejects_windows_qualified_paths(tmp_path: Path, name: str) -> None:
    archive = tmp_path / "plugin.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(name, "bad")
    with pytest.raises(PluginBootstrapError, match="unsafe"):
        extract_plugin_zip(archive, tmp_path / "extract")


def test_file_auth_is_imported_with_private_permissions(tmp_path: Path) -> None:
    ambient = tmp_path / "ambient"
    isolated = tmp_path / "isolated"
    ambient.mkdir()
    (ambient / "auth.json").write_text('{"token":"test"}\n', encoding="utf-8")
    assert import_ambient_auth(ambient, isolated) is True
    auth = isolated / "auth.json"
    assert auth.read_text(encoding="utf-8") == '{"token":"test"}\n'
    assert auth.stat().st_mode & 0o777 == 0o600


def test_bootstrap_uses_supported_plugin_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = _plugin(tmp_path)
    calls: list[list[str]] = []
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text("[features]\nplugins = true\n", encoding="utf-8")

    def fake_run(codex_bin: Path, args: list[str], env: dict[str, str]):
        assert codex_bin == Path("/codex")
        assert env["CODEX_HOME"] == str(home)
        calls.append(args)
        if args[:2] == ["plugin", "marketplace"]:
            with (home / "config.toml").open("a", encoding="utf-8") as config:
                config.write(
                    '\n[marketplaces.codex-security-sdk]\nsource_type = "local"\n'
                    f'source = "{home / "sdk-marketplace"}"\n'
                )
        elif args[:2] == ["plugin", "add"]:
            with (home / "config.toml").open("a", encoding="utf-8") as config:
                config.write('\n[plugins."codex-security@codex-security-sdk"]\nenabled = true\n')
        return ""

    monkeypatch.setattr(runtime, "resolve_codex_bin", lambda: Path("/codex"))
    monkeypatch.setattr(runtime, "_run_codex", fake_run)
    installed = home / "plugins/cache/codex-security-sdk/codex-security/1.2.3"
    (installed / ".codex-plugin").mkdir(parents=True)
    (installed / ".codex-plugin/plugin.json").write_text(
        json.dumps({"name": "codex-security", "version": "1.2.3"}),
        encoding="utf-8",
    )
    install = bootstrap_plugin(home, plugin)
    assert calls == [
        [
            "plugin",
            "marketplace",
            "add",
            str(home / "sdk-marketplace"),
        ],
        ["plugin", "add", "codex-security@codex-security-sdk"],
    ]
    assert install.installed_root == installed.resolve()
    assert install.name == "codex-security"
    assert install.version == "1.2.3"
    config = (home / "config.toml").read_text(encoding="utf-8")
    assert "plugins = true" in config
    assert "[marketplaces.codex-security-sdk]" in config
    assert '[plugins."codex-security@codex-security-sdk"]' in config


def test_registration_accepts_same_source_with_different_path_spelling(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    marketplace = tmp_path / "sdk-marketplace"
    marketplace.write_text("", encoding="utf-8")
    registered_source = tmp_path / "registered-sdk-marketplace"
    registered_source.hardlink_to(marketplace)
    _write_plugin_registration(home, registered_source)

    runtime._verify_plugin_registration(home, marketplace)


def test_registration_rejects_missing_source(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    marketplace = tmp_path / "sdk-marketplace"
    marketplace.write_text("", encoding="utf-8")
    _write_plugin_registration(home, tmp_path / "missing-marketplace")

    with pytest.raises(PluginBootstrapError, match="wrong source"):
        runtime._verify_plugin_registration(home, marketplace)


def test_bundled_plugin_falls_back_in_shallow_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "package"
    bundled = package / "_bundled_plugin"
    (bundled / ".codex-plugin").mkdir(parents=True)
    (bundled / ".codex-plugin/plugin.json").write_text(
        json.dumps({"name": "codex-security", "version": "1.2.3"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(runtime, "__file__", "/app/openai_codex_security/runtime.py")
    monkeypatch.setattr(runtime, "files", lambda _package: package)

    assert bundled_plugin_root() == bundled


def _write_plugin_registration(home: Path, source: Path) -> None:
    (home / "config.toml").write_text(
        "[marketplaces.codex-security-sdk]\n"
        'source_type = "local"\n'
        f"source = {json.dumps(str(source))}\n"
        '\n[plugins."codex-security@codex-security-sdk"]\n'
        "enabled = true\n",
        encoding="utf-8",
    )
