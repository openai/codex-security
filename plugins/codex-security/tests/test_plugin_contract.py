from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
LEGACY_CODEX_SECURITY_ACCESS_APP_NAME = "codex-security-access"
LEGACY_CODEX_SECURITY_ACCESS_CONNECTOR_ID = "connector_openai_codex_security_access"


def read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict), path
    return payload


def test_plugin_manifest_references_existing_assets_and_skills() -> None:
    manifest = read_json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json")

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


def test_daybreak_access_uses_plugin_mcp() -> None:
    apps = read_json(PLUGIN_ROOT / ".app.json")["apps"]
    mcp_servers = read_json(PLUGIN_ROOT / ".mcp.json")["mcpServers"]

    assert LEGACY_CODEX_SECURITY_ACCESS_APP_NAME not in apps
    assert all(app["id"] != LEGACY_CODEX_SECURITY_ACCESS_CONNECTOR_ID for app in apps.values())
    assert "codex-security" in mcp_servers
    assert LEGACY_CODEX_SECURITY_ACCESS_APP_NAME not in mcp_servers


def test_cloud_connection_is_optional_and_skill_is_shipped() -> None:
    apps = read_json(PLUGIN_ROOT / ".app.json")["apps"]
    cloud = apps["codex-security-cloud"]
    assert cloud["id"] == "connector_openai_defense_factory"
    assert cloud["category"] == "Code Hosting & Security Findings"
    assert cloud.get("required") is False

    shipped = read_json(PLUGIN_ROOT / "plugin-files.json")["shippedExact"]
    assert "skills/cloud-findings/SKILL.md" in shipped
    assert "skills/cloud-findings/agents/openai.yaml" in shipped


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

        text = skill_path.read_text(encoding="utf-8")
        match = re.match(r"\A---\n(.*?)\n---\n", text, re.DOTALL)
        assert match is not None, f"{skill_path}: missing YAML frontmatter"
        frontmatter = yaml.safe_load(match.group(1))
        assert isinstance(frontmatter, dict), skill_path
        assert set(frontmatter) == {"name", "description"}
        assert frontmatter["name"] == skill_dir.name
        assert isinstance(frontmatter["description"], str) and frontmatter["description"].strip()

        agent = yaml.safe_load(agent_path.read_text(encoding="utf-8"))
        assert isinstance(agent, dict), agent_path
        interface = agent["interface"]
        assert isinstance(interface, dict)
        for field in ("display_name", "short_description", "default_prompt"):
            assert isinstance(interface[field], str), f"{agent_path}: {field}"
            assert interface[field].strip(), f"{agent_path}: {field}"
