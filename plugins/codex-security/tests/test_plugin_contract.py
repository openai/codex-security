from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
CODEX_SECURITY_ACCESS_APP_NAME = "codex-security-access"
CODEX_SECURITY_ACCESS_CONNECTOR_ID = "connector_openai_codex_security_access"


def read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict), path
    return payload


def read_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict), path
    return payload


def read_skill_frontmatter(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"\A---\n(.*?)\n---\n", text, re.DOTALL)
    assert match is not None, f"{path}: missing YAML frontmatter"
    payload = yaml.safe_load(match.group(1))
    assert isinstance(payload, dict), path
    return payload


def test_plugin_manifest_references_existing_assets_and_skills() -> None:
    manifest = read_json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json")

    required_fields = {
        "name",
        "version",
        "description",
        "author",
        "homepage",
        "repository",
        "license",
        "keywords",
        "skills",
        "mcpServers",
        "interface",
    }
    assert required_fields <= manifest.keys()
    assert manifest["name"] == "codex-security"
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:-alpha)?", manifest["version"])
    assert isinstance(manifest["description"], str) and manifest["description"].strip()
    assert manifest["author"] == {"name": "OpenAI"}
    for field in ("homepage", "repository"):
        assert isinstance(manifest[field], str) and manifest[field].startswith("https://")
    assert isinstance(manifest["license"], str) and manifest["license"].strip()
    assert isinstance(manifest["keywords"], list) and manifest["keywords"]
    assert all(isinstance(keyword, str) and keyword.strip() for keyword in manifest["keywords"])
    assert manifest["skills"] == "./skills/"
    assert (PLUGIN_ROOT / manifest["skills"]).is_dir()
    assert manifest["mcpServers"] == "./.mcp.json"
    assert (PLUGIN_ROOT / manifest["mcpServers"]).is_file()

    interface = manifest["interface"]
    assert isinstance(interface, dict)
    required_interface_fields = {
        "displayName",
        "shortDescription",
        "longDescription",
        "developerName",
        "category",
        "capabilities",
        "websiteURL",
        "privacyPolicyURL",
        "termsOfServiceURL",
        "defaultPrompt",
        "brandColor",
        "composerIcon",
        "logo",
        "screenshots",
    }
    assert required_interface_fields <= interface.keys()
    assert interface["displayName"] == "Codex Security"
    for field in (
        "shortDescription",
        "longDescription",
        "developerName",
        "category",
    ):
        assert isinstance(interface[field], str) and interface[field].strip()
    for field in ("websiteURL", "privacyPolicyURL", "termsOfServiceURL"):
        assert isinstance(interface[field], str) and interface[field].startswith("https://")
    for field in ("capabilities", "defaultPrompt"):
        assert isinstance(interface[field], list) and interface[field]
        assert all(isinstance(value, str) and value.strip() for value in interface[field])
    assert re.fullmatch(r"#[0-9A-Fa-f]{6}", interface["brandColor"])
    assert isinstance(interface["screenshots"], list)
    for key in ("composerIcon", "logo"):
        relative_path = interface[key]
        assert isinstance(relative_path, str) and relative_path.startswith("./")
        assert (PLUGIN_ROOT / relative_path).is_file(), relative_path


def test_codex_security_access_app_contract() -> None:
    apps = read_json(PLUGIN_ROOT / ".app.json")["apps"]
    mcp_servers = read_json(PLUGIN_ROOT / ".mcp.json")["mcpServers"]

    assert apps[CODEX_SECURITY_ACCESS_APP_NAME] == {
        "id": CODEX_SECURITY_ACCESS_CONNECTOR_ID,
        "category": "Security",
        "required": False,
    }
    assert CODEX_SECURITY_ACCESS_APP_NAME not in mcp_servers


def test_deep_scan_config_override_is_forwarded_to_mcp_server() -> None:
    mcp_server = read_json(PLUGIN_ROOT / ".mcp.json")["mcpServers"]["codex-security"]

    assert "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH" in mcp_server["env_vars"]


def test_every_skill_has_valid_frontmatter_and_agent_interface() -> None:
    skill_dirs = sorted(path for path in (PLUGIN_ROOT / "skills").iterdir() if path.is_dir())
    assert skill_dirs

    for skill_dir in skill_dirs:
        skill_path = skill_dir / "SKILL.md"
        agent_path = skill_dir / "agents" / "openai.yaml"
        assert skill_path.is_file(), skill_path
        assert agent_path.is_file(), agent_path

        frontmatter = read_skill_frontmatter(skill_path)
        assert set(frontmatter) == {"name", "description"}
        assert frontmatter["name"] == skill_dir.name
        assert isinstance(frontmatter["description"], str) and frontmatter["description"].strip()

        agent = read_yaml(agent_path)
        interface = agent["interface"]
        assert isinstance(interface, dict)
        for field in ("display_name", "short_description", "default_prompt"):
            assert isinstance(interface[field], str), f"{agent_path}: {field}"
            assert interface[field].strip(), f"{agent_path}: {field}"


def test_fix_finding_uses_product_language_for_workbench_state() -> None:
    skill = (PLUGIN_ROOT / "skills" / "fix-finding" / "SKILL.md").read_text(encoding="utf-8")

    assert "terminal workbench update" in skill
    assert "SQLite" not in skill
