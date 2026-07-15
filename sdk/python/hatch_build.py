from __future__ import annotations

import json
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, object]) -> None:
        sdk_root = Path(self.root)
        source_plugin = sdk_root.parents[1] / "plugins/codex-security"
        prebundled = sdk_root / "src/openai_codex_security/_bundled_plugin"
        if (prebundled / ".codex-plugin/plugin.json").is_file():
            source_plugin = prebundled
            relative_paths = [
                path.relative_to(source_plugin).as_posix()
                for path in source_plugin.rglob("*")
                if path.is_file()
            ]
        else:
            contract_path = (
                source_plugin / ".internal/external-promotion/external-projection-contract.json"
            )
            if contract_path.is_file():
                contract = json.loads(contract_path.read_text(encoding="utf-8"))
                relative_paths = [".codex-plugin/plugin.json", *contract["shippedExact"]]
                relative_paths = [path for path in relative_paths if not path.startswith("sdk/")]
            else:
                relative_paths = [
                    path.relative_to(source_plugin).as_posix()
                    for path in source_plugin.rglob("*")
                    if path.is_file()
                    and not path.relative_to(source_plugin).as_posix().startswith("sdk/")
                ]

        public_manifest = sdk_root / "public-repo/sdk/python/plugin.public.json"
        target_prefix = (
            "src/openai_codex_security/_bundled_plugin"
            if self.target_name == "sdist"
            else "openai_codex_security/_bundled_plugin"
        )
        force_include = build_data.setdefault("force_include", {})
        assert isinstance(force_include, dict)
        for relative in relative_paths:
            source = (
                public_manifest
                if relative == ".codex-plugin/plugin.json" and public_manifest.is_file()
                else source_plugin / relative
            )
            if not source.is_file():
                raise RuntimeError(f"Bundled plugin file is missing: {source}")
            force_include[str(source)] = f"{target_prefix}/{relative}"
