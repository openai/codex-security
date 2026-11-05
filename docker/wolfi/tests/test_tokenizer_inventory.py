"""Check bundled tokenizer component identities and the legacy npm dependency fallback."""

import json
import runpy
import unittest
from pathlib import Path


verifier = runpy.run_path(str(Path(__file__).resolve().parents[1] / "verify-public.py"))
inventory = verifier["inventory_tokenizer"]
SCANNER = verifier["SCANNER"]


def component(name, version):
    return {"name": name, "version": version, "type": "library", "purl": f"pkg:npm/{name}@{version}",
            "licenses": [{"license": {"id": "MIT"}}]}


def bom(items):
    return json.dumps({"bomFormat": "CycloneDX", "components": items})


class TokenizerInventoryTest(unittest.TestCase):
    def setUp(self):
        self.scanner = {"dependencies": {}, "devDependencies": {"js-tiktoken": "1.2.3"}}
        self.manifests = {SCANNER: self.scanner}
        self.items = [component("js-tiktoken", "1.2.3"), component("base64-js", "4.5.6")]

    def test_bundled_components(self):
        self.assertEqual(inventory(self.manifests, bom(self.items)), self.items)
        for payload in (None, bom([]), bom(self.items[:1]), bom(self.items[:1] * 2)):
            with self.subTest(payload=payload), self.assertRaises(SystemExit):
                inventory(self.manifests, payload)

    def test_invalid_identity(self):
        for change in ({"version": ""}, {"purl": "pkg:npm/base64-js@9.0.0"}, {"licenses": []},
                       {"type": "application"}, component("js-tiktoken", "9.0.0")):
            with self.subTest(change=change), self.assertRaises(SystemExit):
                inventory(self.manifests, bom([self.items[0] | change, self.items[1]]))

    def test_only_the_direct_installed_dependency_supports_legacy_releases(self):
        self.manifests["node_modules/js-tiktoken"] = {"name": "js-tiktoken", "version": "1.2.3"}
        with self.assertRaises(SystemExit):
            inventory(self.manifests, None)
        self.scanner["dependencies"]["js-tiktoken"] = "1.2.3"
        self.assertEqual(inventory(self.manifests, None), [])
        self.manifests[SCANNER + "/node_modules/js-tiktoken"] = {"name": "js-tiktoken", "version": "0.9.0"}
        with self.assertRaises(SystemExit):
            inventory(self.manifests, None)
        del self.manifests[SCANNER + "/node_modules/js-tiktoken"], self.manifests["node_modules/js-tiktoken"]
        with self.assertRaises(SystemExit):
            inventory(self.manifests, None)
