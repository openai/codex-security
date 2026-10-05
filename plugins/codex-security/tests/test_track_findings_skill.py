from __future__ import annotations

import json
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

        plugin = json.loads(PLUGIN_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(plugin["apps"], "./.app.json")


if __name__ == "__main__":
    unittest.main()
