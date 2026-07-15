from __future__ import annotations

import copy
import json
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

SDK_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_PACKAGE_ROOT = SDK_ROOT / "public-repo/sdk/python"
PUBLIC_PYPROJECT = PUBLIC_PACKAGE_ROOT / "pyproject.public.toml"
PUBLIC_PLUGIN_MANIFEST = PUBLIC_PACKAGE_ROOT / "plugin.public.json"
PLUGIN_ROOT = SDK_ROOT.parents[1] / "plugins/codex-security"
BUNDLED_PLUGIN_MANIFEST = (
    SDK_ROOT / "src/openai_codex_security/_bundled_plugin/.codex-plugin/plugin.json"
)
PUBLIC_REPOSITORY = "openai/codex-security"


def _repository_root() -> Path:
    monorepo_public_root = SDK_ROOT / "public-repo"
    return monorepo_public_root if monorepo_public_root.is_dir() else SDK_ROOT.parents[1]


def _load(path: Path) -> dict[str, object]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def test_public_pyproject_matches_canonical_metadata() -> None:
    if not PUBLIC_PYPROJECT.is_file():
        assert "tool.oaipkg" not in (SDK_ROOT / "pyproject.toml").read_text()
        return

    canonical = copy.deepcopy(_load(SDK_ROOT / "pyproject.toml"))
    public = _load(PUBLIC_PYPROJECT)
    project = canonical["project"]
    assert isinstance(project, dict)
    project["version"] = "0.0.0-dev"
    tools = canonical["tool"]
    assert isinstance(tools, dict)
    tools.pop("oaipkg")
    tools.pop("buildkite")
    ruff = tools["ruff"]
    assert isinstance(ruff, dict)
    ruff.pop("extend")
    ruff["line-length"] = 100
    lint = ruff["lint"]
    assert isinstance(lint, dict)
    lint["select"] = lint.pop("extend-select")

    assert public == canonical


def test_public_lock_contains_no_internal_registry_urls() -> None:
    root = PUBLIC_PACKAGE_ROOT if PUBLIC_PYPROJECT.is_file() else SDK_ROOT
    lock = (root / "uv.lock").read_text(encoding="utf-8")
    assert "internal.api." + "openai.org" not in lock
    assert "https://pypi.org/simple" in lock


def test_public_plugin_manifest_matches_external_metadata() -> None:
    manifest_path = (
        PUBLIC_PLUGIN_MANIFEST if PUBLIC_PLUGIN_MANIFEST.is_file() else BUNDLED_PLUGIN_MANIFEST
    )
    actual = json.loads(manifest_path.read_text())
    if PUBLIC_PLUGIN_MANIFEST.is_file():
        source = json.loads((PLUGIN_ROOT / ".codex-plugin/plugin.json").read_text())
        contract = json.loads(
            (
                PLUGIN_ROOT / ".internal/external-promotion/external-projection-contract.json"
            ).read_text()
        )
        expected = copy.deepcopy(source)
        expected.update(contract["externalManifestOverrides"])
        expected["license"] = "Apache-2.0"
        assert actual == expected

    assert actual["homepage"] == "https://developers.openai.com/codex/security"
    assert actual["repository"] == "https://github.com/openai/plugins"
    assert actual["license"] == "Apache-2.0"


def test_release_workflow_targets_public_repository() -> None:
    workflow = (_repository_root() / ".github/workflows/python-release.yml").read_text()
    assert workflow.count(f"github.repository == '{PUBLIC_REPOSITORY}'") == 2


def test_public_metadata_contains_no_internal_markers() -> None:
    if PUBLIC_PYPROJECT.is_file():
        repository_root = _repository_root()
        package_root = PUBLIC_PACKAGE_ROOT
        pyproject = PUBLIC_PYPROJECT
    else:
        repository_root = SDK_ROOT.parents[1]
        package_root = SDK_ROOT
        pyproject = package_root / "pyproject.toml"
    forbidden = (
        "LicenseRef-" + "Proprietary",
        '"license": "' + "Proprietary" + '"',
        "internal.api." + "openai.org",
        "github.com/openai/" + "openai",
        "[tool." + "oaipkg]",
        "[tool." + "buildkite]",
    )
    paths = [
        repository_root / "CONTRIBUTING.md",
        repository_root / "README.md",
        repository_root / "SECURITY.md",
        PUBLIC_PLUGIN_MANIFEST if PUBLIC_PLUGIN_MANIFEST.is_file() else BUNDLED_PLUGIN_MANIFEST,
        pyproject,
        package_root / "uv.lock",
    ]
    for path in paths:
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert not any(marker in text for marker in forbidden), path
