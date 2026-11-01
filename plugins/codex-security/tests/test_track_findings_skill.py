from __future__ import annotations

import json
import re
import shlex
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
APP_MANIFEST = PLUGIN_ROOT / ".app.json"
PLUGIN_MANIFEST = PLUGIN_ROOT / ".codex-plugin" / "plugin.json"


class TrackFindingsSkillTest(unittest.TestCase):
    def test_provider_apps_are_available_on_demand(self) -> None:
        apps = json.loads(APP_MANIFEST.read_text(encoding="utf-8"))["apps"]
        self.assertTrue({"linear", "github", "atlassian"}.issubset(apps))
        app_ids = [apps[name].get("id") for name in ("linear", "github", "atlassian")]
        self.assertTrue(all(isinstance(app_id, str) and app_id for app_id in app_ids))
        self.assertEqual(len(set(app_ids)), len(app_ids))
        self.assertEqual(apps["atlassian"]["capabilities"], ["read", "write"])
        self.assertEqual(apps["atlassian"]["id"], "asdk_app_6a83901dde988191b3f3cefdcc19acfa")

        plugin = json.loads(PLUGIN_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(plugin["apps"], "./.app.json")

    def test_github_cli_readback_uses_the_returned_issue_and_reviewed_content(self) -> None:
        skill = (PLUGIN_ROOT / "skills/track-findings/SKILL.md").read_text(encoding="utf-8")
        writes = next(
            paragraph for paragraph in skill.split("\n\n") if "`gh issue edit`" in paragraph
        )
        match = re.search(r"`(gh issue view [^`]+)`", writes)
        self.assertIsNotNone(match, "expected a readback command for CLI issue writes")
        args = shlex.split(match[1])
        field_args = args[args.index("--json") + 1 :]
        self.assertTrue(field_args, "gh issue view --json requires a field list")
        self.assertLessEqual({"number", "url", "title", "body"}, set(field_args[0].split(",")))
        self.assertIn("$issue_url", args)

    def test_skill_app_links_resolve_to_declared_connectors(self) -> None:
        apps = json.loads(APP_MANIFEST.read_text(encoding="utf-8"))["apps"]
        declared_ids = {app["id"] for app in apps.values()}
        linked_ids = set()
        for path in (PLUGIN_ROOT / "skills").rglob("*.md"):
            for app_id in re.findall(r"app://([\w-]+)", path.read_text(encoding="utf-8")):
                with self.subTest(path=path, app_id=app_id):
                    self.assertIn(app_id, declared_ids)
                linked_ids.add(app_id)
        self.assertIn(apps["atlassian"]["id"], linked_ids)


if __name__ == "__main__":
    unittest.main()
