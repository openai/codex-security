from __future__ import annotations

import json
import re
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

    def test_skill_app_links_resolve_to_declared_connectors(self) -> None:
        apps = json.loads(APP_MANIFEST.read_text(encoding="utf-8"))["apps"]
        declared_ids = {app["id"] for app in apps.values()}
        linked_ids = set()
        for path in (PLUGIN_ROOT / "skills").rglob("*.md"):
            for app_id in re.findall(r"app://([\w-]+)", path.read_text(encoding="utf-8")):
                with self.subTest(path=path, app_id=app_id):
                    self.assertIn(app_id, declared_ids)
                linked_ids.add(app_id)
        self.assertEqual(linked_ids, declared_ids)


if __name__ == "__main__":
    unittest.main()
