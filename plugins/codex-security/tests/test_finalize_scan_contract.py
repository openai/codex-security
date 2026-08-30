from __future__ import annotations

import copy
import csv
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from unittest import mock


def load_finalizer() -> ModuleType:
    script = Path(__file__).resolve().parent.parent / "scripts" / "finalize_scan_contract.py"
    spec = importlib.util.spec_from_file_location("finalize_scan_contract", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FINALIZER = load_finalizer()
EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "examples" / "completed-scan"


class FinalizeScanContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scan_dir = Path(self.temp_dir.name).resolve()
        self.manifest = {
            "documentType": "codex-security.scan-manifest",
            "schemaVersion": "1.0",
            "scan": {
                "id": "scan_001",
                "producer": {
                    "name": "codex-security-plugin",
                    "version": "0.1.0",
                },
                "status": "completed",
                "startedAt": "2026-05-31T18:00:00Z",
                "completedAt": "2026-05-31T18:09:00Z",
                "target": {
                    "kind": "git_worktree",
                    "targetId": "target_sha256_example",
                    "displayName": "example/repo",
                    "remote": "https://github.com/example/repo",
                    "revision": "deadbeef",
                    "snapshotDigest": "codex-security-snapshot/v1:sha256:0000000000000000000000000000000000000000000000000000000000000000",
                },
                "scope": {
                    "includePaths": ["src/"],
                    "excludePaths": [],
                },
                "coverageRef": "coverage.json",
                "findingsRef": "findings.json",
            },
        }
        self.finding = {
            "ruleId": "path-traversal.archive-extraction",
            "identity": {
                "anchor": "archive-entry-write-without-containment",
            },
            "title": "Unsafe archive extraction can escape the output directory",
            "summary": "An attacker-controlled path reaches a filesystem write without containment validation.",
            "severity": {
                "level": "high",
                "score": 8.1,
                "scoringSystem": "CVSS:3.1",
            },
            "confidence": {
                "level": "high",
                "rationale": "Direct source trace reaches the filesystem write without a containment check.",
            },
            "taxonomy": {
                "category": "path-traversal",
                "cwe": ["CWE-22"],
            },
            "locations": [
                {
                    "path": "src/extract.py",
                    "startLine": 41,
                    "endLine": 44,
                    "role": "sink",
                }
            ],
            "remediation": "Normalize destinations and reject entries that escape the extraction root.",
            "validation": None,
            "attackPath": None,
            "provenance": {
                "source": "local_plugin",
            },
            "extensions": {},
        }
        self.findings = {
            "documentType": "codex-security.findings",
            "schemaVersion": "1.0",
            "scanId": "scan_001",
            "findings": [copy.deepcopy(self.finding)],
        }
        self.coverage = {
            "documentType": "codex-security.coverage",
            "schemaVersion": "1.0",
            "scanId": "scan_001",
            "mode": "repository",
            "completeness": "complete",
            "inventoryStrategy": "repository",
            "includePaths": ["src/"],
            "excludePaths": [],
            "surfaces": [
                {
                    "id": "surface_archive_extraction",
                    "label": "Archive extraction",
                    "disposition": "reported",
                    "receiptRefs": [],
                }
            ],
            "explicitExclusions": [],
            "deferred": [],
        }

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_scan(self) -> None:
        self.write_json("scan-manifest.json", self.manifest)
        self.write_json("findings.json", self.findings)
        self.write_json("coverage.json", self.coverage)
        (self.scan_dir / "report.md").write_text(
            """# Security Review: example/repo

## Findings

| Title | Severity |
| --- | --- |
| [Unsafe archive extraction can escape the output directory](#1-unsafe-archive-extraction-can-escape-the-output-directory) | high |

### [1] Unsafe archive extraction can escape the output directory

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | Direct source trace reaches the filesystem write without a containment check. |
| Category | Path traversal |
| CWE | CWE-22 |
| Affected lines | src/extract.py:41-44 |

#### Summary

The extraction root is not enforced.
""",
            encoding="utf-8",
        )

    def write_json(self, relative_path: str, payload: object) -> None:
        path = self.scan_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def read_json(self, relative_path: str) -> dict[str, object]:
        return json.loads((self.scan_dir / relative_path).read_text(encoding="utf-8"))

    def completion_binding(self) -> dict[str, object]:
        return {
            "scanId": "scan_001",
            "startedAt": "2026-05-31T18:00:00Z",
            "completedAt": "2026-05-31T18:10:00Z",
            "producer": {"name": "codex-security-plugin", "version": "0.1.0"},
            "target": {
                "targetId": "target_sha256_example",
                "displayName": "example/repo",
                "revision": "deadbeef",
                "snapshotDigest": (
                    "codex-security-snapshot/v1:sha256:"
                    "0000000000000000000000000000000000000000000000000000000000000000"
                ),
            },
            "allowedTargetKinds": ["git_worktree"],
            "scope": {"includePaths": ["src/"], "excludePaths": []},
            "coverageMode": "repository",
        }

    def rewrite_sealed_artifact(self, relative_path: str, payload: object) -> None:
        self.write_json(relative_path, payload)
        manifest = self.read_json("scan-manifest.json")
        artifacts = manifest["scan"]["artifacts"]
        for artifact in artifacts:
            if artifact["path"] == relative_path:
                artifact["sha256"] = FINALIZER._sha256_bytes(
                    (self.scan_dir / relative_path).read_bytes()
                )
                break
        else:
            raise AssertionError(f"missing sealed artifact: {relative_path}")
        self.write_json("scan-manifest.json", manifest)

    def test_finalize_seals_manifest_deterministically(self) -> None:
        self.write_scan()

        manifest_result, findings_result, coverage_result = FINALIZER.finalize_scan(self.scan_dir)
        first_manifest = (self.scan_dir / "scan-manifest.json").read_bytes()
        first_findings = (self.scan_dir / "findings.json").read_bytes()
        first_sarif = (self.scan_dir / "exports" / "results.sarif").read_bytes()
        with mock.patch.dict(os.environ, {"CODEX_SECURITY_STARTED_AT": "not-a-timestamp"}):
            FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(manifest_result["scan"]["id"], "scan_001")
        self.assertEqual(findings_result["scanId"], "scan_001")
        self.assertEqual(coverage_result["scanId"], "scan_001")

        self.assertEqual(first_manifest, (self.scan_dir / "scan-manifest.json").read_bytes())
        self.assertEqual(first_findings, (self.scan_dir / "findings.json").read_bytes())
        self.assertEqual(first_sarif, (self.scan_dir / "exports" / "results.sarif").read_bytes())

        manifest = self.read_json("scan-manifest.json")
        self.assertEqual(manifest["scan"]["sealedAt"], "2026-05-31T18:09:00Z")
        self.assertEqual(
            [artifact["path"] for artifact in manifest["scan"]["artifacts"]],
            [
                "findings.json",
                "coverage.json",
            ],
        )
        findings = self.read_json("findings.json")
        finding = findings["findings"][0]
        self.assertRegex(finding["findingId"], r"^csf_[a-f0-9]{24}$")
        self.assertRegex(finding["occurrenceId"], r"^occ_[a-f0-9]{24}$")
        sarif = self.read_json("exports/results.sarif")
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(rule["id"], "path-traversal.archive-extraction")
        self.assertEqual(
            rule["properties"],
            {
                "security-severity": "8.1",
                "tags": ["external/cwe/cwe-022", "path-traversal", "security"],
            },
        )
        self.assertEqual(result["ruleId"], "path-traversal.archive-extraction")
        self.assertNotIn("primaryLocationLineHash", result["partialFingerprints"])
        self.assertEqual(
            result["partialFingerprints"]["codexSecurity/v1"], finding["fingerprints"]["primary"]
        )

    def test_headless_finalization_replaces_model_timestamps_with_machine_clock(self) -> None:
        self.manifest["scan"]["startedAt"] = "2026-07-21T23:20:33Z"
        self.manifest["scan"]["completedAt"] = "2026-07-21T23:30:52Z"
        self.write_scan()
        started_at = "2026-07-22T06:20:33Z"
        before = datetime.now(timezone.utc)

        with mock.patch.dict(os.environ, {"CODEX_SECURITY_STARTED_AT": started_at}):
            manifest, _, _ = FINALIZER.finalize_scan(self.scan_dir)

        completed_at = manifest["scan"]["completedAt"]
        self.assertEqual(manifest["scan"]["startedAt"], started_at)
        self.assertTrue(completed_at.endswith("Z"))
        self.assertGreaterEqual(datetime.fromisoformat(completed_at), before)
        self.assertLessEqual(datetime.fromisoformat(completed_at), datetime.now(timezone.utc))
        self.assertEqual(manifest["scan"]["sealedAt"], completed_at)

    def test_headless_finalization_rejects_invalid_authoritative_start(self) -> None:
        self.write_scan()

        with mock.patch.dict(os.environ, {"CODEX_SECURITY_STARTED_AT": "not-a-timestamp"}):
            with self.assertRaisesRegex(FINALIZER.ContractError, "RFC 3339 timestamp"):
                FINALIZER.finalize_scan(self.scan_dir)

        self.assertNotIn("sealedAt", self.read_json("scan-manifest.json")["scan"])

    def test_finalizes_canonical_document_beyond_previous_size_limit(self) -> None:
        self.manifest["metadata"] = "x" * (16 * 1024 * 1024)
        self.write_scan()

        manifest, _, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(len(manifest["metadata"]), 16 * 1024 * 1024)

    def test_reads_schema_beyond_previous_size_limit(self) -> None:
        schema = self.scan_dir / "large.schema.json"
        schema.write_text(json.dumps({"description": "x" * (4 * 1024 * 1024)}))

        self.assertEqual(len(FINALIZER._read_json(schema)["description"]), 4 * 1024 * 1024)

    def test_finalizes_json_beyond_previous_nesting_limit(self) -> None:
        nested: list[object] | int = 0
        for _ in range(258):
            nested = [nested]
        self.findings["findings"][0]["extensions"]["nested"] = nested
        self.write_scan()

        _, findings, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(findings["findings"][0]["extensions"]["nested"], nested)

    def test_rejects_unsafe_canonical_json_values_without_reflecting_keys(self) -> None:
        marker = "DO_NOT_REFLECT_PRIVATE_JSON_KEY"
        for payload, reason in (
            ({marker: 1 << 53}, "unsafe integer-valued JSON numbers"),
            ({marker: float(1 << 53)}, "unsafe integer-valued JSON numbers"),
            ({marker: 1e20}, "unsafe integer-valued JSON numbers"),
            ({marker: float("inf")}, "non-finite JSON numbers"),
            ({marker: "bad-" + chr(0xD800)}, "well-formed Unicode"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(FINALIZER.ContractError, reason) as raised:
                    FINALIZER._contract_json_bytes("findings.json", payload)
                self.assertNotIn(marker, str(raised.exception))

    def test_validates_wide_json_arrays_incrementally(self) -> None:
        events: list[str] = []

        class ObservedList(list[str]):
            def __iter__(self):
                for index, value in enumerate(super().__iter__()):
                    events.append(f"yield:{index}")
                    yield value

        payload = ObservedList(["first", "second", "third"])
        require_string = FINALIZER._require_safe_json_string

        def observe_string(value: str, context: str) -> None:
            events.append(f"validate:{value}")
            require_string(value, context)

        with mock.patch.object(FINALIZER, "_require_safe_json_string", side_effect=observe_string):
            FINALIZER._require_safe_json_value(payload, "findings.json")

        self.assertEqual(
            events,
            [
                "yield:0",
                "validate:first",
                "yield:1",
                "validate:second",
                "yield:2",
                "validate:third",
            ],
        )

    def test_rejects_non_object_contract_documents_before_traversing_them(self) -> None:
        self.write_scan()
        path = self.scan_dir / "findings.json"
        path.write_text(json.dumps(["unexpected"] * 1_000), encoding="utf-8")

        with mock.patch.object(
            FINALIZER,
            "_require_safe_json_value",
            wraps=FINALIZER._require_safe_json_value,
        ) as validate:
            with self.assertRaisesRegex(FINALIZER.ContractError, "expected a JSON object"):
                FINALIZER._read_scan_local_json_bytes(
                    self.scan_dir,
                    "findings.json",
                    "findings.json",
                )

        validate.assert_not_called()

    def test_sealed_rerun_rejects_malformed_unicode_extensions_without_mutating_files(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["extensions"]["note"] = "bad-" + chr(0xD800)
        self.write_json("findings.json", findings)
        manifest = self.read_json("scan-manifest.json")
        for artifact in manifest["scan"]["artifacts"]:
            if artifact["path"] == "findings.json":
                artifact["sha256"] = FINALIZER._sha256_file(self.scan_dir / "findings.json")
                break
        self.write_json("scan-manifest.json", manifest)
        before = {
            path.name: path.read_bytes() for path in self.scan_dir.iterdir() if path.is_file()
        }

        with self.assertRaisesRegex(FINALIZER.ContractError, "well-formed Unicode"):
            FINALIZER.finalize_scan(self.scan_dir)

        after = {path.name: path.read_bytes() for path in self.scan_dir.iterdir() if path.is_file()}
        self.assertEqual(before, after)

    def test_sealed_rerun_preserves_existing_document_bytes(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["summary"] = "é" * 128
        compact = (json.dumps(findings, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        path = self.scan_dir / "findings.json"
        path.write_bytes(compact)
        manifest = self.read_json("scan-manifest.json")
        for artifact in manifest["scan"]["artifacts"]:
            if artifact["path"] == "findings.json":
                artifact["sha256"] = FINALIZER._sha256_bytes(compact)
                break
        self.write_json("scan-manifest.json", manifest)
        self.assertGreater(len(FINALIZER._json_bytes(findings)), len(compact))

        _, accepted, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(accepted, findings)
        self.assertEqual(path.read_bytes(), compact)

    def test_sealed_rerun_accepts_legacy_unknown_evidence_references(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["codeEvidence"] = [
            {
                "id": "shared-source",
                "label": "Canonical source",
                "path": "src/extract.py",
                "startLine": 41,
                "code": "canonical_source()",
                "explanation": "Canonical snippet.",
            }
        ]
        findings["findings"][0]["code_evidence"] = [
            {"id": "shared-source", "code": "legacy_source()"}
        ]
        findings["findings"][0]["validation"] = {"evidence_refs": ["legacy-validation-evidence"]}
        findings["findings"][0]["attackPath"] = {
            "evidence_refs": ["legacy-attack-evidence"],
            "dataFlow": {"evidenceRefs": ["legacy-missing-evidence"]},
        }
        self.rewrite_sealed_artifact("findings.json", findings)
        sealed_findings = (self.scan_dir / "findings.json").read_bytes()

        _, accepted, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(accepted, findings)
        self.assertEqual((self.scan_dir / "findings.json").read_bytes(), sealed_findings)

    def test_sealed_rerun_ignores_malformed_legacy_evidence_references(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["code_evidence"] = [
            {"id": "legacy-source", "code": "legacy_source()"}
        ]
        findings["findings"][0]["validation"] = {
            "evidenceRefs": [None, "", 42, "legacy-source", "missing-source"]
        }
        findings["findings"][0]["attackPath"] = {
            "dataflow": {"evidence_refs": [None, "", 42, "legacy-source", "missing-source"]}
        }
        self.rewrite_sealed_artifact("findings.json", findings)
        sealed_findings = (self.scan_dir / "findings.json").read_bytes()

        _, accepted, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(accepted, findings)
        self.assertEqual((self.scan_dir / "findings.json").read_bytes(), sealed_findings)

    def test_unsealed_scan_rejects_malformed_legacy_evidence_references(self) -> None:
        self.findings["findings"][0]["validation"] = {"evidenceRefs": [None]}
        self.write_scan()

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            r"validation\.evidenceRefs: expected strings",
        ):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_sealed_rerun_accepts_duplicate_legacy_evidence_ids(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["code_evidence"] = [
            {"id": "legacy-duplicate", "code": "first_legacy_source()"},
            {"id": "legacy-duplicate", "code": "second_legacy_source()"},
        ]
        self.rewrite_sealed_artifact("findings.json", findings)
        sealed_findings = (self.scan_dir / "findings.json").read_bytes()

        _, accepted, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(accepted, findings)
        self.assertEqual((self.scan_dir / "findings.json").read_bytes(), sealed_findings)

    def test_sealed_rerun_ignores_non_string_legacy_validation_scalars(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["validation"] = {
            "method": [],
            "summary": {"legacy": True},
        }
        self.rewrite_sealed_artifact("findings.json", findings)
        sealed_findings = (self.scan_dir / "findings.json").read_bytes()

        _, accepted, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(accepted, findings)
        self.assertEqual((self.scan_dir / "findings.json").read_bytes(), sealed_findings)

    def test_sealed_rerun_accepts_formerly_free_form_finding_details(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["validation"] = {
            "evidence": {"kind": "trace"},
        }
        findings["findings"][0]["attackPath"] = {
            "steps": {"first": "upload"},
        }
        self.rewrite_sealed_artifact("findings.json", findings)
        sealed_findings = (self.scan_dir / "findings.json").read_bytes()

        _, accepted, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(accepted, findings)
        self.assertEqual((self.scan_dir / "findings.json").read_bytes(), sealed_findings)

    def test_sealed_rerun_ignores_blank_legacy_attack_path_details(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["attackPath"] = {
            field: ""
            for field in (
                "dataFlow",
                "data_flow",
                "dataflow",
                "reachability",
                "impact",
                "likelihood",
            )
        }
        self.rewrite_sealed_artifact("findings.json", findings)
        sealed_findings = (self.scan_dir / "findings.json").read_bytes()

        _, accepted, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(accepted, findings)
        self.assertEqual((self.scan_dir / "findings.json").read_bytes(), sealed_findings)

    def test_sealed_rerun_rejects_nullable_canonical_evidence_catalog(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["codeEvidence"] = None
        self.rewrite_sealed_artifact("findings.json", findings)

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            r"codeEvidence: expected (?:an |schema type )?array",
        ):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_accepts_custom_schema_beyond_previous_complexity_limits(self) -> None:
        schema = {
            "type": "object",
            "allOf": [{"type": "object"}] * 129,
            "properties": {
                **{f"property_{index}": {} for index in range(4097)},
                "name": {"type": "string", "pattern": "^a+$"},
            },
        }
        path = self.scan_dir / "custom.schema.json"
        path.write_text(json.dumps(schema), encoding="utf-8")

        FINALIZER.validate_against_schema({"name": "aaa"}, path)

    def test_allows_schema_properties_named_like_validation_keywords(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "$ref": {"type": "string"},
                "pattern": {"type": "string"},
                "uniqueItems": {"type": "boolean"},
            },
        }
        path = self.scan_dir / "custom.schema.json"
        path.write_text(json.dumps(schema), encoding="utf-8")

        FINALIZER.validate_against_schema(
            {"$ref": "value", "pattern": "^(a+)+$", "uniqueItems": True},
            path,
        )

    def test_finalize_normalizes_unsealed_deep_inventory_strategy_alias(self) -> None:
        self.coverage["mode"] = "deep_repository"
        self.coverage["inventoryStrategy"] = "deep_repository_repeated_discovery"
        self.write_scan()

        _, _, coverage = FINALIZER.finalize_scan(
            self.scan_dir,
            expected_coverage_mode="deep_repository",
        )

        self.assertEqual(coverage["inventoryStrategy"], "repository")
        self.assertEqual(self.read_json("coverage.json")["inventoryStrategy"], "repository")

    def test_finalize_rejects_deep_inventory_strategy_alias_outside_deep(self) -> None:
        for expected_mode in ("repository", "scoped_path"):
            with self.subTest(expected_mode=expected_mode):
                self.coverage["mode"] = expected_mode
                self.coverage["inventoryStrategy"] = "deep_repository_repeated_discovery"
                self.write_scan()

                with self.assertRaisesRegex(
                    FINALIZER.ContractError,
                    "coverage.schema.inventoryStrategy: unsupported value",
                ):
                    FINALIZER.finalize_scan(
                        self.scan_dir,
                        expected_coverage_mode=expected_mode,
                    )

    def test_finalize_rejects_unknown_deep_inventory_strategy_alias(self) -> None:
        self.coverage["mode"] = "deep_repository"
        self.coverage["inventoryStrategy"] = "deep_repository_repeated_discovery_v2"
        self.write_scan()

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            "coverage.schema.inventoryStrategy: unsupported value",
        ):
            FINALIZER.finalize_scan(
                self.scan_dir,
                expected_coverage_mode="deep_repository",
            )

    def test_finalize_rejects_sealed_deep_inventory_strategy_alias(self) -> None:
        self.coverage["mode"] = "deep_repository"
        self.write_scan()
        FINALIZER.finalize_scan(
            self.scan_dir,
            expected_coverage_mode="deep_repository",
        )
        coverage = self.read_json("coverage.json")
        coverage["inventoryStrategy"] = "deep_repository_repeated_discovery"
        self.write_json("coverage.json", coverage)
        manifest = self.read_json("scan-manifest.json")
        coverage_artifact = next(
            artifact
            for artifact in manifest["scan"]["artifacts"]
            if artifact["path"] == "coverage.json"
        )
        coverage_artifact["sha256"] = FINALIZER._sha256_bytes(
            (self.scan_dir / "coverage.json").read_bytes()
        )
        self.write_json("scan-manifest.json", manifest)

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            "coverage.schema.inventoryStrategy: unsupported value",
        ):
            FINALIZER.finalize_scan(
                self.scan_dir,
                expected_coverage_mode="deep_repository",
            )

    def test_finalize_allows_diff_and_deep_findings_without_optional_documents(self) -> None:
        for coverage_mode, inventory_strategy in (
            ("diff", "diff"),
            ("deep_repository", "repository"),
        ):
            with self.subTest(coverage_mode=coverage_mode):
                self.coverage["mode"] = coverage_mode
                self.coverage["inventoryStrategy"] = inventory_strategy
                self.write_scan()

                manifest, findings, coverage = FINALIZER.finalize_scan(
                    self.scan_dir,
                    expected_coverage_mode=coverage_mode,
                )

                self.assertEqual(coverage["mode"], coverage_mode)
                self.assertNotIn("hardening", manifest["scan"])
                self.assertNotIn("writeup", findings["findings"][0])
                self.assertTrue((self.scan_dir / "report.md").is_file())

    def test_finalize_requires_linked_writeup_to_be_regular_scan_local_file(self) -> None:
        report_path = "findings/archive-extraction/archive-extraction.md"
        self.findings["findings"][0]["writeup"] = {"reportPath": report_path}
        self.write_scan()

        with self.assertRaisesRegex(FINALIZER.ContractError, "expected a file inside"):
            FINALIZER.finalize_scan(self.scan_dir)

        writeup_path = self.scan_dir / report_path
        writeup_path.parent.mkdir(parents=True)
        writeup_path.mkdir()
        with self.assertRaisesRegex(FINALIZER.ContractError, "regular non-symlink file"):
            FINALIZER.finalize_scan(self.scan_dir)

        writeup_path.rmdir()
        writeup_path.write_text("# Archive extraction\n", encoding="utf-8")
        FINALIZER.finalize_scan(self.scan_dir)
        writeup_path.unlink()
        with self.assertRaisesRegex(FINALIZER.ContractError, "expected a file inside"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_finalize_requires_hardening_portfolio_to_be_regular_scan_local_file(self) -> None:
        portfolio_path = "hardening/hardening.md"
        self.manifest["scan"]["hardening"] = {"portfolioPath": portfolio_path}
        self.write_scan()

        with self.assertRaisesRegex(FINALIZER.ContractError, "expected a file inside"):
            FINALIZER.finalize_scan(self.scan_dir)

        portfolio = self.scan_dir / portfolio_path
        portfolio.parent.mkdir(parents=True)
        portfolio.mkdir()
        with self.assertRaisesRegex(FINALIZER.ContractError, "regular non-symlink file"):
            FINALIZER.finalize_scan(self.scan_dir)

        portfolio.rmdir()
        portfolio.write_text("# Structural hardening\n", encoding="utf-8")
        FINALIZER.finalize_scan(self.scan_dir)
        portfolio.unlink()
        with self.assertRaisesRegex(FINALIZER.ContractError, "expected a file inside"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_rerun_regenerates_sarif_projection_without_mutating_seal(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        first_manifest = (self.scan_dir / "scan-manifest.json").read_bytes()

        source_root = self.scan_dir / "source"
        source_path = source_root / "src" / "extract.py"
        source_path.parent.mkdir(parents=True)
        source_path.write_text(
            "\n".join(f"line {index}" for index in range(1, 60)), encoding="utf-8"
        )
        FINALIZER.finalize_scan(self.scan_dir, source_root=source_root)

        self.assertEqual(first_manifest, (self.scan_dir / "scan-manifest.json").read_bytes())
        sarif = self.read_json("exports/results.sarif")
        result = sarif["runs"][0]["results"][0]
        self.assertIn("primaryLocationLineHash", result["partialFingerprints"])

    def test_sarif_export_failure_does_not_fail_finalization(self) -> None:
        self.write_scan()
        with tempfile.TemporaryDirectory() as external_dir:
            (self.scan_dir / "exports").symlink_to(external_dir, target_is_directory=True)
            stderr = io.StringIO()
            with mock.patch("sys.stderr", stderr):
                FINALIZER.finalize_scan(self.scan_dir)
            self.assertIn("automatic SARIF", stderr.getvalue())
            self.assertIn(
                "Run `codex-security export <scan-dir> --export-format sarif` to retry.",
                stderr.getvalue(),
            )
            with self.assertRaisesRegex(FINALIZER.ContractError, "inside the scan directory"):
                FINALIZER.write_sarif_projection(self.scan_dir)
            self.assertFalse((Path(external_dir) / "results.sarif").exists())
            manifest = self.read_json("scan-manifest.json")
            self.assertEqual(manifest["scan"]["sealedAt"], "2026-05-31T18:09:00Z")

    def test_sarif_only_entrypoint_exports_a_sealed_scan_without_mutating_it(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        sarif_path = self.scan_dir / "exports" / "results.sarif"
        sarif_path.unlink()
        canonical = {
            name: (self.scan_dir / name).read_bytes()
            for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
        }

        result = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--sarif-only",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        sarif = json.loads(result.stdout)
        self.assertEqual(sarif["version"], "2.1.0")
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["id"], self.finding["ruleId"])
        self.assertIn(self.finding["remediation"], rule["help"]["markdown"])
        self.assertEqual(rule["properties"]["security-severity"], "8.1")
        self.assertIn("external/cwe/cwe-022", rule["properties"]["tags"])
        self.assertFalse(sarif_path.exists())
        self.assertEqual(
            canonical, {name: (self.scan_dir / name).read_bytes() for name in canonical}
        )

    def test_export_entrypoint_writes_json_csv_and_sarif_without_mutating_a_sealed_scan(
        self,
    ) -> None:
        self.finding["title"] = "=Unsafe archive extraction"
        self.finding["locations"] = [
            {"path": "src/support.py", "startLine": 4, "role": "supporting_evidence"},
            {"path": "src/extract.py", "startLine": 41, "endLine": 44, "role": "root_control"},
        ]
        self.findings["findings"] = [copy.deepcopy(self.finding)]
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        canonical = {
            name: (self.scan_dir / name).read_bytes()
            for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
        }

        for export_format in ("json", "csv", "sarif"):
            with self.subTest(export_format=export_format):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(Path(FINALIZER.__file__)),
                        "--scan-dir",
                        str(self.scan_dir),
                        "--export-format",
                        export_format,
                    ],
                    capture_output=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 0, result.stderr.decode())
                if export_format == "json":
                    self.assertEqual(result.stdout, canonical["findings.json"])
                elif export_format == "csv":
                    reader = csv.DictReader(io.StringIO(result.stdout.decode(), newline=""))
                    self.assertEqual(
                        reader.fieldnames,
                        [
                            "occurrence_id",
                            "finding_id",
                            "title",
                            "summary",
                            "severity",
                            "confidence",
                            "status",
                            "close_reason",
                            "note",
                            "remediation",
                            "path",
                            "start_line",
                            "end_line",
                        ],
                    )
                    row = next(reader)
                    self.assertEqual(row["title"], "'=Unsafe archive extraction")
                    self.assertEqual(row["status"], "open")
                    self.assertEqual(row["path"], "src/extract.py")
                    self.assertEqual(row["start_line"], "41")
                    self.assertEqual(row["end_line"], "44")
                else:
                    self.assertEqual(json.loads(result.stdout)["version"], "2.1.0")
                self.assertEqual(
                    canonical,
                    {name: (self.scan_dir / name).read_bytes() for name in canonical},
                )

    def test_deep_csv_export_includes_the_canonical_candidate_id(self) -> None:
        self.coverage["mode"] = "deep_repository"
        self.finding["extensions"] = {"candidateId": "DSS-145", "reportId": "DSS-145-rogue"}
        self.findings["findings"] = [copy.deepcopy(self.finding)]
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)

        result = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--export-format",
                "csv",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        reader = csv.DictReader(io.StringIO(result.stdout, newline=""))
        self.assertIn("candidate_id", reader.fieldnames or [])
        row = next(reader)
        self.assertEqual(row["candidate_id"], "DSS-145")
        self.assertNotIn("report_id", row)

    def test_scoped_deep_csv_export_keeps_candidate_and_single_line_location(self) -> None:
        self.coverage["mode"] = "scoped_path"
        self.finding["extensions"] = {"candidateId": "DSS-146", "reportId": "DSS-146-rogue"}
        self.finding["locations"] = [{"path": "src/extract.py", "startLine": 41, "role": "sink"}]
        self.findings["findings"] = [copy.deepcopy(self.finding)]
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)

        result = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--export-format",
                "csv",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        reader = csv.DictReader(io.StringIO(result.stdout, newline=""))
        self.assertIn("candidate_id", reader.fieldnames or [])
        row = next(reader)
        self.assertEqual(row["candidate_id"], "DSS-146")
        self.assertEqual(row["start_line"], "41")
        self.assertEqual(row["end_line"], "41")

    def test_scoped_deep_csv_export_uses_legacy_candidate_id_fallbacks(self) -> None:
        for field, coverage_mode in (
            ("reportId", "scoped_path"),
            ("ledgerRowId", "deep_repository"),
        ):
            with self.subTest(field=field):
                self.coverage["mode"] = coverage_mode
                self.finding["extensions"] = {field: f"legacy-{field}"}
                self.findings["findings"] = [copy.deepcopy(self.finding)]
                self.write_scan()
                FINALIZER.finalize_scan(self.scan_dir)

                result = subprocess.run(
                    [
                        sys.executable,
                        str(Path(FINALIZER.__file__)),
                        "--scan-dir",
                        str(self.scan_dir),
                        "--export-format",
                        "csv",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                reader = csv.DictReader(io.StringIO(result.stdout, newline=""))
                self.assertIn("candidate_id", reader.fieldnames or [])
                self.assertEqual(next(reader)["candidate_id"], f"legacy-{field}")

    def test_scoped_csv_export_does_not_classify_ordinary_ledger_ids_as_deep(self) -> None:
        self.coverage["mode"] = "scoped_path"
        self.finding["extensions"] = {"ledgerRowId": "SCAN-001-parser"}
        self.findings["findings"] = [copy.deepcopy(self.finding)]
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)

        result = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--export-format",
                "csv",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        reader = csv.DictReader(io.StringIO(result.stdout, newline=""))
        self.assertNotIn("candidate_id", reader.fieldnames or [])

    def test_csv_export_escapes_newline_and_full_width_formula_prefixes(self) -> None:
        self.finding["title"] = "\n=1+1"
        self.finding["summary"] = "＝1+1"
        self.finding["remediation"] = " \t＋1+1"
        self.findings["findings"] = [copy.deepcopy(self.finding)]
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)

        result = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--export-format",
                "csv",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        row = next(csv.DictReader(io.StringIO(result.stdout, newline="")))
        self.assertEqual(row["title"], "'\n=1+1")
        self.assertEqual(row["summary"], "'＝1+1")
        self.assertEqual(row["remediation"], "' \t＋1+1")

    def test_export_entrypoint_rejects_unsealed_and_tampered_scans(self) -> None:
        self.write_scan()
        for export_format in ("json", "csv"):
            with self.subTest(export_format=export_format, state="unsealed"):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(Path(FINALIZER.__file__)),
                        "--scan-dir",
                        str(self.scan_dir),
                        "--export-format",
                        export_format,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f"{export_format.upper()} export requires a sealed scan", result.stderr
                )

        FINALIZER.finalize_scan(self.scan_dir)
        self.write_json("findings.json", {"changed": True})
        for export_format in ("json", "csv"):
            with self.subTest(export_format=export_format, state="tampered"):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(Path(FINALIZER.__file__)),
                        "--scan-dir",
                        str(self.scan_dir),
                        "--export-format",
                        export_format,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("sealed artifact changed or is missing", result.stderr)

    def test_export_entrypoint_writes_external_output_and_rejects_artifact_overwrite(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.scan_dir / "findings.json"
        before = findings.read_bytes()
        output = self.scan_dir.parent / "findings.csv"

        exported = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--export-format",
                "csv",
                "--export-output",
                str(output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        rejected = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--export-format",
                "json",
                "--export-output",
                str(findings),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(exported.returncode, 0, exported.stderr)
        self.assertTrue(output.read_text().startswith("occurrence_id,finding_id,title,summary"))
        self.assertEqual(exported.stdout, "")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("JSON output path cannot overwrite a scan artifact", rejected.stderr)
        self.assertEqual(findings.read_bytes(), before)

    def test_export_entrypoint_rejects_overwriting_a_sealed_reserved_export(self) -> None:
        for artifact_path in (
            "exports/findings.csv",
            "exports/./findings.csv",
            "exports//findings.csv",
            "exports/FINDINGS.CSV",
            "exports/sealed-findings.csv",
        ):
            with self.subTest(artifact_path=artifact_path):
                self.write_scan()
                FINALIZER.finalize_scan(self.scan_dir)
                output = self.scan_dir / "exports" / "findings.csv"
                output.parent.mkdir(parents=True, exist_ok=True)
                sealed_export = b"SEALED_EXPORT_SENTINEL\n"
                output.write_bytes(sealed_export)
                if artifact_path.endswith("sealed-findings.csv"):
                    os.link(output, self.scan_dir / artifact_path)
                if (
                    artifact_path.endswith("FINDINGS.CSV")
                    and not (self.scan_dir / artifact_path).exists()
                ):
                    self.skipTest("filesystem is case-sensitive")
                manifest = self.read_json("scan-manifest.json")
                manifest["scan"]["artifacts"].append(
                    {
                        "path": artifact_path,
                        "sha256": hashlib.sha256(sealed_export).hexdigest(),
                        "mediaType": "text/csv",
                    }
                )
                self.write_json("scan-manifest.json", manifest)

                result = subprocess.run(
                    [
                        sys.executable,
                        str(Path(FINALIZER.__file__)),
                        "--scan-dir",
                        str(self.scan_dir),
                        "--export-format",
                        "csv",
                        "--export-output",
                        str(output),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "CSV output path cannot overwrite a sealed scan artifact",
                    result.stderr,
                )
                self.assertEqual(output.read_bytes(), sealed_export)

    def test_export_entrypoint_rejects_a_case_aliased_scan_directory(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        alias = self.scan_dir.parent / self.scan_dir.name.swapcase()
        if alias == self.scan_dir or not alias.exists() or not alias.samefile(self.scan_dir):
            self.skipTest("filesystem is case-sensitive")

        output = self.scan_dir / "exports" / "findings.csv"
        output.parent.mkdir(parents=True, exist_ok=True)
        sealed_export = b"SEALED_EXPORT_SENTINEL\n"
        output.write_bytes(sealed_export)
        manifest = self.read_json("scan-manifest.json")
        manifest["scan"]["artifacts"].append(
            {
                "path": "exports/findings.csv",
                "sha256": hashlib.sha256(sealed_export).hexdigest(),
                "mediaType": "text/csv",
            }
        )
        self.write_json("scan-manifest.json", manifest)

        result = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--export-format",
                "csv",
                "--export-output",
                str(alias / "exports" / "findings.csv"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CSV output path cannot overwrite a sealed scan artifact", result.stderr)
        self.assertEqual(output.read_bytes(), sealed_export)

    def test_export_entrypoint_rejects_symlink_aliased_scan_directories(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        output = self.scan_dir / "exports" / "findings.csv"
        protected_contents = b"PROTECTED_EXPORT_SENTINEL\n"

        with tempfile.TemporaryDirectory() as repository:
            repository_path = Path(repository)
            direct_alias = repository_path / "reports"
            parent_alias = repository_path / "workspace"
            direct_alias.symlink_to(self.scan_dir, target_is_directory=True)
            parent_alias.symlink_to(self.scan_dir.parent, target_is_directory=True)

            for alias in (direct_alias, parent_alias / self.scan_dir.name):
                with self.subTest(alias=str(alias)):
                    output.write_bytes(protected_contents)
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(Path(FINALIZER.__file__)),
                            "--scan-dir",
                            str(self.scan_dir),
                            "--export-format",
                            "csv",
                            "--export-output",
                            str(alias / "exports" / "findings.csv"),
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("symbolic link", result.stderr)
                    self.assertEqual(output.read_bytes(), protected_contents)

    def test_export_entrypoint_rejects_orphaned_or_mismatched_output_flags(
        self,
    ) -> None:
        for arguments in (
            ("--export-output", "exports/findings.csv"),
            ("--export-format", "csv", "--sarif-output", "exports/results.sarif"),
        ):
            with self.subTest(arguments=arguments):
                self.write_scan()
                before = {
                    name: (self.scan_dir / name).read_bytes()
                    for name in ("scan-manifest.json", "findings.json", "coverage.json")
                }

                result = subprocess.run(
                    [
                        sys.executable,
                        str(Path(FINALIZER.__file__)),
                        "--scan-dir",
                        str(self.scan_dir),
                        *arguments,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("requires", result.stderr)
                self.assertEqual(
                    before,
                    {name: (self.scan_dir / name).read_bytes() for name in before},
                )

    def test_sarif_only_entrypoint_rejects_changed_sealed_artifact(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        self.write_json("findings.json", {"changed": True})
        sarif_path = self.scan_dir / "exports" / "results.sarif"
        sarif_path.unlink()

        result = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--sarif-only",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sealed artifact changed or is missing", result.stderr)
        self.assertFalse(sarif_path.exists())

    def test_sarif_only_entrypoint_rejects_invalid_source_root(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        source_file = self.scan_dir / "source-file"
        source_file.write_text("not a directory\n", encoding="utf-8")

        for source_root in (self.scan_dir / "missing-source", source_file):
            for export_args in (("--sarif-only",), ("--export-format", "sarif")):
                with self.subTest(source_root=str(source_root), export_args=export_args):
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(Path(FINALIZER.__file__)),
                            "--scan-dir",
                            str(self.scan_dir),
                            *export_args,
                            "--source-root",
                            str(source_root),
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("source root: expected an existing directory", result.stderr)
                    self.assertEqual(result.stdout, "")

    def test_sarif_only_entrypoint_writes_external_output_atomically(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        sarif_path = self.scan_dir / "exports" / "results.sarif"
        sarif_path.unlink()
        output = self.scan_dir.parent / "results.sarif"

        result = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--sarif-only",
                "--sarif-output",
                str(output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["version"], "2.1.0")
        self.assertFalse(sarif_path.exists())

    def test_failed_sarif_only_entrypoint_does_not_create_exports_directory(self) -> None:
        self.write_scan()
        output = self.scan_dir / "exports" / "results.sarif"

        result = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--sarif-only",
                "--sarif-output",
                str(output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SARIF projection requires a sealed scan", result.stderr)
        self.assertFalse(output.parent.exists())

    def test_sarif_only_entrypoint_rejects_sealed_artifact_output(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.scan_dir / "findings.json"
        before = findings.read_bytes()

        result = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--sarif-only",
                "--sarif-output",
                "findings.json",
            ],
            capture_output=True,
            text=True,
            check=False,
            cwd=self.scan_dir,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot overwrite a scan artifact", result.stderr)
        self.assertEqual(findings.read_bytes(), before)

    @unittest.skipIf(os.name == "nt", "backslash is a path separator on Windows")
    def test_sarif_only_entrypoint_accepts_posix_backslash_output_name(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        output = self.scan_dir.parent / "results\\v1.sarif"

        result = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--sarif-only",
                "--sarif-output",
                str(output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["version"], "2.1.0")

    def test_sarif_only_entrypoint_accepts_read_only_scan_directory(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        sarif_path = self.scan_dir / "exports" / "results.sarif"
        sarif_path.unlink()
        sarif_path.parent.rmdir()
        self.scan_dir.chmod(0o500)
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(FINALIZER.__file__)),
                    "--scan-dir",
                    str(self.scan_dir),
                    "--sarif-only",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        finally:
            self.scan_dir.chmod(0o700)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["version"], "2.1.0")
        self.assertFalse(sarif_path.exists())

    def test_sarif_projection_rejects_symlinked_scan_directory(self) -> None:
        outside_dir = self.scan_dir / "outside"
        outside_dir.mkdir()
        stored_scan_dir = self.scan_dir / "stored"
        stored_scan_dir.symlink_to(outside_dir, target_is_directory=True)

        with self.assertRaisesRegex(FINALIZER.ContractError, "non-symlink directory"):
            FINALIZER.write_sarif_projection(stored_scan_dir)

        self.assertFalse((outside_dir / "exports" / "results.sarif").exists())

    def test_sarif_projection_rejects_symlinked_scan_directory_ancestor(self) -> None:
        stored_root = self.scan_dir / "stored-root"
        stored_scan_dir = stored_root / "scan"
        stored_scan_dir.mkdir(parents=True)
        moved_root = self.scan_dir / "moved-root"
        stored_root.rename(moved_root)
        replacement_root = self.scan_dir / "replacement-root"
        (replacement_root / "scan").mkdir(parents=True)
        stored_root.symlink_to(replacement_root, target_is_directory=True)

        with self.assertRaisesRegex(FINALIZER.ContractError, "canonical non-symlink"):
            FINALIZER.write_sarif_projection(stored_scan_dir)

        self.assertFalse((replacement_root / "scan" / "exports" / "results.sarif").exists())

    def test_scan_local_json_read_stays_on_open_ancestor_after_swap(self) -> None:
        original_dir = self.scan_dir / "nested"
        original_dir.mkdir()
        (original_dir / "payload.json").write_text('{"source": "original"}\n', encoding="utf-8")
        outside_dir = Path(self.temp_dir.name).parent / f"{self.scan_dir.name}-outside"
        outside_dir.mkdir()
        self.addCleanup(lambda: outside_dir.rmdir())
        (outside_dir / "payload.json").write_text('{"source": "outside"}\n', encoding="utf-8")
        self.addCleanup(lambda: (outside_dir / "payload.json").unlink())
        moved_dir = self.scan_dir / "nested-original"
        open_directory = FINALIZER._open_scan_local_directory

        def open_then_swap(root_fd: int, parts: tuple[str, ...], *, create: bool) -> int:
            descriptor = open_directory(root_fd, parts, create=create)
            original_dir.rename(moved_dir)
            original_dir.symlink_to(outside_dir, target_is_directory=True)
            return descriptor

        with mock.patch.object(FINALIZER, "_open_scan_local_directory", side_effect=open_then_swap):
            payload = FINALIZER._read_scan_local_json(
                self.scan_dir, "nested/payload.json", "nested/payload.json"
            )

        self.assertEqual(payload, {"source": "original"})

    def test_sarif_projection_revalidates_sealed_findings(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["locations"][0]["path"] = "../../outside.py"
        self.write_json("findings.json", findings)
        manifest = self.read_json("scan-manifest.json")
        for artifact in manifest["scan"]["artifacts"]:
            if artifact["path"] == "findings.json":
                artifact["sha256"] = FINALIZER._sha256_file(self.scan_dir / "findings.json")
        self.write_json("scan-manifest.json", manifest)

        with self.assertRaisesRegex(FINALIZER.ContractError, "safe repository-relative"):
            FINALIZER.write_sarif_projection(self.scan_dir)

    def test_sarif_projection_uses_findings_read_before_seal_validation(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        original_summary = self.finding["summary"]
        replaced = self.read_json("findings.json")
        replaced["findings"][0]["summary"] = "Replaced after seal validation"
        validate_seal = FINALIZER._validate_existing_seal

        def validate_then_replace(
            scan_dir: Path,
            scan: dict[str, object],
            *,
            artifact_contents: dict[str, bytes] | None = None,
        ) -> None:
            validate_seal(scan_dir, scan, artifact_contents=artifact_contents)
            self.write_json("findings.json", replaced)

        with mock.patch.object(
            FINALIZER,
            "_validate_existing_seal",
            side_effect=validate_then_replace,
        ):
            FINALIZER.write_sarif_projection(self.scan_dir)

        result = self.read_json("exports/results.sarif")["runs"][0]["results"][0]
        self.assertIn(original_summary, result["message"]["text"])
        self.assertNotIn("Replaced after seal validation", result["message"]["text"])

    def test_sarif_projection_hashes_the_findings_bytes_it_parsed(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings_path = self.scan_dir / "findings.json"
        sealed_bytes = findings_path.read_bytes()
        replaced = self.read_json("findings.json")
        replaced["findings"][0]["summary"] = "Unsealed swap content"
        self.write_json("findings.json", replaced)
        validate_seal = FINALIZER._validate_existing_seal

        def restore_then_validate(
            scan_dir: Path,
            scan: dict[str, object],
            *,
            artifact_contents: dict[str, bytes] | None = None,
        ) -> None:
            findings_path.write_bytes(sealed_bytes)
            validate_seal(scan_dir, scan, artifact_contents=artifact_contents)

        with mock.patch.object(
            FINALIZER,
            "_validate_existing_seal",
            side_effect=restore_then_validate,
        ):
            with self.assertRaisesRegex(FINALIZER.ContractError, "sealed artifact changed"):
                FINALIZER.write_sarif_projection(self.scan_dir)

    def test_first_seal_revalidates_receipts_after_manifest_publication(self) -> None:
        receipt_ref = "artifacts/02_discovery/work_ledger.jsonl"
        receipt = self.scan_dir / receipt_ref
        receipt.parent.mkdir(parents=True)
        receipt.write_text('{"candidate":"original"}\n')
        self.coverage["surfaces"][0]["receiptRefs"] = [receipt_ref]
        self.write_scan()
        artifact_record = FINALIZER._artifact_record

        def record_then_replace(
            scan_dir: Path,
            relative_path: str,
            media_type: str,
            contents: bytes | None = None,
        ) -> dict[str, str]:
            record = artifact_record(scan_dir, relative_path, media_type, contents)
            if relative_path == receipt_ref:
                receipt.write_text('{"candidate":"changed"}\n')
            return record

        with mock.patch.object(
            FINALIZER,
            "_artifact_record",
            side_effect=record_then_replace,
        ):
            with self.assertRaisesRegex(FINALIZER.ContractError, "sealed artifact changed"):
                FINALIZER.finalize_scan(self.scan_dir)

    def test_sarif_projection_requires_canonical_sealed_artifacts(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        sealed_manifest = self.read_json("scan-manifest.json")

        for required_path in ("findings.json", "coverage.json"):
            with self.subTest(required_path=required_path):
                manifest = copy.deepcopy(sealed_manifest)
                manifest["scan"]["artifacts"] = [
                    artifact
                    for artifact in manifest["scan"]["artifacts"]
                    if artifact["path"] != required_path
                ]
                self.write_json("scan-manifest.json", manifest)

                with self.assertRaisesRegex(FINALIZER.ContractError, required_path):
                    FINALIZER.write_sarif_projection(self.scan_dir)

    def test_sarif_projection_revalidates_sealed_coverage_receipts(self) -> None:
        receipt_ref = "artifacts/02_discovery/work_ledger.jsonl"
        self.coverage["surfaces"][0]["receiptRefs"] = [receipt_ref]
        self.write_scan()
        receipt_path = self.scan_dir / receipt_ref
        receipt_path.parent.mkdir(parents=True)
        receipt_path.write_text('{"status":"reviewed"}\n', encoding="utf-8")
        FINALIZER.finalize_scan(self.scan_dir)
        manifest = self.read_json("scan-manifest.json")
        manifest["scan"]["artifacts"] = [
            artifact
            for artifact in manifest["scan"]["artifacts"]
            if artifact["path"] != receipt_ref
        ]
        self.write_json("scan-manifest.json", manifest)

        with self.assertRaisesRegex(FINALIZER.ContractError, "missing from sealed artifacts"):
            FINALIZER.write_sarif_projection(self.scan_dir)

    def test_sarif_projection_revalidates_manifest_schema(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        manifest = self.read_json("scan-manifest.json")
        manifest["scan"]["startedAt"] = "not-a-time"
        self.write_json("scan-manifest.json", manifest)

        with self.assertRaisesRegex(FINALIZER.ContractError, "RFC 3339 timestamp"):
            FINALIZER.write_sarif_projection(self.scan_dir)

    def test_sarif_rejects_surrogate_location_before_sealing(self) -> None:
        self.findings["findings"][0]["locations"][0]["path"] = "src/bad" + chr(0xDCFF) + ".py"
        self.write_scan()

        with self.assertRaisesRegex(FINALIZER.ContractError, "safe repository-relative"):
            FINALIZER.finalize_scan(self.scan_dir)

        self.assertNotIn("sealedAt", self.read_json("scan-manifest.json")["scan"])

    def test_sarif_rejects_nul_location_before_sealing(self) -> None:
        self.findings["findings"][0]["locations"][0]["path"] = "src/bad\0.py"
        self.write_scan()

        with self.assertRaisesRegex(FINALIZER.ContractError, "safe repository-relative"):
            FINALIZER.finalize_scan(self.scan_dir, source_root=self.scan_dir)

        self.assertNotIn("sealedAt", self.read_json("scan-manifest.json")["scan"])

    def test_sarif_output_fails_closed_without_secure_file_backend(self) -> None:
        with mock.patch.object(FINALIZER.os, "supports_dir_fd", set()):
            with self.assertRaisesRegex(FINALIZER.ContractError, "descriptor-relative"):
                FINALIZER._write_scan_local_json(
                    self.scan_dir, "exports/results.sarif", {"ok": True}
                )

        self.assertFalse((self.scan_dir / "exports" / "results.sarif").exists())

    def test_finalize_uses_windows_backend_without_dir_fd(self) -> None:
        self.findings["findings"] = []
        self.coverage["surfaces"][0]["disposition"] = "no_issue_found"
        self.write_scan()

        backend = mock.Mock()

        def open_read_fd(scan_dir: Path, relative_path: str, _context: str) -> int:
            return os.open(scan_dir / relative_path, os.O_RDONLY)

        def atomic_write(
            scan_dir: Path,
            relative_path: str,
            payload: bytes,
            *,
            expected_root_identity: tuple[int, int] | None = None,
        ) -> None:
            path = scan_dir / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)

        def unlink_if_exists(scan_dir: Path, relative_path: str) -> None:
            (scan_dir / relative_path).unlink(missing_ok=True)

        backend.open_read_fd.side_effect = open_read_fd
        backend.atomic_write.side_effect = atomic_write
        backend.unlink_if_exists.side_effect = unlink_if_exists

        with (
            mock.patch.object(FINALIZER.os, "supports_dir_fd", set()),
            mock.patch.object(FINALIZER, "_is_windows", return_value=True),
            mock.patch.object(FINALIZER, "_windows_scan_local_files", return_value=backend),
        ):
            FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(self.read_json("findings.json")["findings"], [])
        self.assertEqual(
            self.read_json("scan-manifest.json")["scan"]["sealedAt"],
            "2026-05-31T18:09:00Z",
        )
        self.assertTrue((self.scan_dir / "report.md").is_file())

    def test_rejects_symlink_sarif_export_file(self) -> None:
        self.write_scan()
        exports_dir = self.scan_dir / "exports"
        exports_dir.mkdir()
        with tempfile.TemporaryDirectory() as external_dir:
            external_path = Path(external_dir) / "results.sarif"
            external_path.write_text("unchanged\n", encoding="utf-8")
            (exports_dir / "results.sarif").symlink_to(external_path)
            FINALIZER.finalize_scan(self.scan_dir)
            with self.assertRaisesRegex(FINALIZER.ContractError, "non-symlink file"):
                FINALIZER.write_sarif_projection(self.scan_dir)
            self.assertEqual(external_path.read_text(encoding="utf-8"), "unchanged\n")

    def test_sarif_export_replaces_hard_link_without_overwriting_target(self) -> None:
        self.write_scan()
        exports_dir = self.scan_dir / "exports"
        exports_dir.mkdir()
        with tempfile.TemporaryDirectory() as external_dir:
            external_path = Path(external_dir) / "results.sarif"
            external_path.write_text("unchanged\n", encoding="utf-8")
            sarif_path = exports_dir / "results.sarif"
            os.link(external_path, sarif_path)
            FINALIZER.finalize_scan(self.scan_dir)
            self.assertEqual(external_path.read_text(encoding="utf-8"), "unchanged\n")
            self.assertNotEqual(sarif_path.stat().st_ino, external_path.stat().st_ino)

    def test_checked_in_semantic_fixture_has_derived_identities(self) -> None:
        manifest = json.loads((EXAMPLE_DIR / "scan-manifest.json").read_text(encoding="utf-8"))
        findings = json.loads((EXAMPLE_DIR / "findings.json").read_text(encoding="utf-8"))
        original = copy.deepcopy(findings)
        FINALIZER._populate_unsealed_finding_identities(manifest, findings)
        FINALIZER._populate_unsealed_finding_identities(manifest, findings)
        self.assertEqual(findings, original)

    def test_rejects_changed_canonical_artifact_after_sealing(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        (self.scan_dir / "findings.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(FINALIZER.ContractError, "sealed artifact changed"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_sealed_findings_missing_derived_identity(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        sealed_manifest = self.read_json("scan-manifest.json")
        sealed_findings = self.read_json("findings.json")

        for field in ("findingId", "occurrenceId", "fingerprints"):
            with self.subTest(field=field):
                manifest = copy.deepcopy(sealed_manifest)
                findings = copy.deepcopy(sealed_findings)
                findings["findings"][0].pop(field)
                self.write_json("findings.json", findings)
                for artifact in manifest["scan"]["artifacts"]:
                    if artifact["path"] == "findings.json":
                        artifact["sha256"] = FINALIZER._sha256_file(self.scan_dir / "findings.json")
                self.write_json("scan-manifest.json", manifest)

                with self.assertRaisesRegex(FINALIZER.ContractError, field):
                    FINALIZER.finalize_scan(self.scan_dir)

    def test_finalize_generates_unsealed_reports_from_canonical_json(self) -> None:
        self.manifest["scan"]["scope"].update(
            {
                "summary": "Review archive extraction in src/.",
                "runtimeStatus": "Focused unit tests passed.",
                "validationMode": "source review and focused tests",
            }
        )
        self.manifest["scan"]["threatModel"] = {
            "summary": "Attackers can supply archive entry names across an extraction boundary.",
            "assets": ["Files outside the extraction root"],
            "trustBoundaries": ["Uploaded archive to local filesystem"],
            "attackerCapabilities": ["Control archive entry paths"],
            "securityObjectives": ["Keep extraction writes inside the destination root"],
        }
        finding = self.findings["findings"][0]
        finding["codeEvidence"] = [
            {
                "id": "archive-write",
                "label": "Unchecked archive write",
                "path": "src/archive.py",
                "startLine": 41,
                "endLine": 44,
                "language": "python",
                "code": "destination.write_bytes(entry.read())",
                "explanation": "The write occurs before containment is checked.",
            }
        ]
        finding["rootCause"] = {
            "summary": "The extractor writes `destination` before checking containment.",
            "evidenceRefs": ["archive-write"],
        }
        finding["validation"] = {
            "assertions": ["The destination resolves outside the extraction root."],
            "summary": "A source trace confirmed the missing containment check.",
            "method": "source review",
            "evidenceRefs": ["archive-write"],
            "evidence": ["The archive entry path is joined directly to the output root."],
            "counterEvidence": ["The caller requires an authenticated upload."],
            "limitations": ["The upload route was not exercised dynamically."],
        }
        finding["attackPath"] = {
            "evidenceRefs": ["archive-write"],
            "dataflow": {
                "summary": "An archive entry path reaches the filesystem write unchanged.",
                "source": "archive entry name",
                "sink": "filesystem write",
                "outcome": "write outside the extraction root",
            },
            "reachability": {
                "summary": "Authenticated uploaders can trigger extraction.",
                "attacker": "authenticated uploader",
                "entrypoint": "archive upload endpoint",
                "preconditions": ["Archive extraction is enabled"],
                "outcome": "arbitrary file overwrite",
            },
        }
        finding["severity"].update(
            {
                "rationale": "Reachable file overwrite crosses the extraction boundary.",
                "changeConditions": "Unauthenticated reachability would raise severity.",
            }
        )
        finding["remediationTests"] = ["Reject ../ entry paths in an extraction unit test."]
        finding["preventiveControls"] = ["Use a shared containment-checking extraction helper."]
        self.coverage["surfaces"][0].update(
            {
                "riskArea": "Path traversal",
                "notes": "The vulnerable extraction sink became finding 1.",
            }
        )
        self.coverage["openQuestions"] = [
            {
                "question": "Do other archive formats use the same sink?",
                "followUpPrompt": "Review archive handlers under src/ for the same containment gap.",
            }
        ]
        self.write_scan()
        (self.scan_dir / "report.md").write_text("# Untrusted authored report\n", encoding="utf-8")
        (self.scan_dir / "report.html").write_text(
            "<p>untrusted authored report</p>", encoding="utf-8"
        )

        FINALIZER.finalize_scan(self.scan_dir)

        manifest = self.read_json("scan-manifest.json")
        artifact_paths = [artifact["path"] for artifact in manifest["scan"]["artifacts"]]
        self.assertNotIn("report.md", artifact_paths)
        self.assertNotIn("report.html", artifact_paths)
        self.assertNotIn("exports/results.sarif", artifact_paths)
        report = (self.scan_dir / "report.md").read_text(encoding="utf-8")
        self.assertNotIn("Untrusted authored report", report)
        for expected in (
            "Review archive extraction in src/.",
            "Attackers can supply archive entry names",
            "The extractor writes `destination` before checking containment.",
            "Unchecked archive write",
            "destination.write_bytes(entry.read())",
            "A source trace confirmed the missing containment check.",
            "The destination resolves outside the extraction root.",
            "The upload route was not exercised dynamically.",
            "An archive entry path reaches the filesystem write unchanged.",
            "Authenticated uploaders can trigger extraction.",
            "Reachable file overwrite crosses the extraction boundary.",
            "Reject ../ entry paths in an extraction unit test.",
            "Path traversal",
            "Do other archive formats use the same sink?",
        ):
            self.assertIn(expected, report)
        self.assertFalse((self.scan_dir / "report.html").exists())

    def test_finalize_accepts_legacy_unstructured_report_semantics(self) -> None:
        finding = self.findings["findings"][0]
        finding["validation"] = {"evidence": "legacy validation evidence"}
        finding["attackPath"] = {"dataflow": "legacy data flow"}
        self.write_scan()

        FINALIZER.finalize_scan(self.scan_dir)

        report = (self.scan_dir / "report.md").read_text(encoding="utf-8")
        self.assertIn("Validation details were not recorded separately.", report)
        self.assertIn("legacy validation evidence", report)
        self.assertIn("legacy data flow", report)

    def test_report_projection_preserves_data_flow_aliases_and_scalar_reachability(self) -> None:
        for data_flow_key in ("dataFlow", "data_flow", "dataflow"):
            with self.subTest(data_flow_key=data_flow_key):
                findings = copy.deepcopy(self.findings)
                findings["findings"][0]["attackPath"] = {
                    data_flow_key: "request -> filesystem write",
                    "reachability": "An authenticated uploader can reach extraction.",
                }

                report = FINALIZER._generate_report_projection(
                    self.manifest, findings, self.coverage
                ).decode("utf-8")

                self.assertIn("request -\\> filesystem write", report)
                self.assertIn("An authenticated uploader can reach extraction.", report)

    def test_report_projection_prefers_populated_data_flow_alias(self) -> None:
        findings = copy.deepcopy(self.findings)
        findings["findings"][0]["attackPath"] = {
            "dataFlow": {"producerExtension": True},
            "dataflow": {"summary": "request -> populated lowercase dataflow -> filesystem write"},
        }

        report = FINALIZER._generate_report_projection(
            self.manifest, findings, self.coverage
        ).decode("utf-8")

        self.assertIn("request -\\> populated lowercase dataflow -\\> filesystem write", report)

    def test_finalize_rejects_unknown_code_evidence_reference(self) -> None:
        finding = self.findings["findings"][0]
        finding["rootCause"] = {
            "summary": "The write occurs before containment is checked.",
            "evidenceRefs": ["missing-evidence"],
        }
        self.write_scan()

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            "rootCause.evidenceRefs: unknown code-evidence ids: missing-evidence",
        ):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_finalize_rejects_unknown_root_cause_alias_evidence_reference(self) -> None:
        finding = self.findings["findings"][0]
        finding["root_cause"] = {
            "summary": "The write occurs before containment is checked.",
            "evidenceRefs": ["missing-evidence"],
        }
        self.write_scan()

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            "root_cause.evidenceRefs: unknown code-evidence ids: missing-evidence",
        ):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_finalize_rejects_unknown_snake_case_code_evidence_reference(self) -> None:
        finding = self.findings["findings"][0]
        finding["validation"] = {"evidence_refs": ["missing-evidence"]}
        self.write_scan()

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            "validation.evidence_refs: unknown code-evidence ids: missing-evidence",
        ):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_finalize_rejects_unknown_nested_code_evidence_reference(self) -> None:
        finding = self.findings["findings"][0]
        finding["attackPath"] = {
            "dataflow": {"evidenceRefs": ["missing-dataflow-evidence"]},
            "reachability": {"evidence_refs": ["missing-reachability-evidence"]},
        }
        self.write_scan()

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            "attackPath.dataflow.evidenceRefs: unknown code-evidence ids: "
            "missing-dataflow-evidence",
        ):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_finalize_accepts_nested_reference_to_legacy_code_evidence(self) -> None:
        finding = self.findings["findings"][0]
        finding["code_evidence"] = [
            {
                "id": "legacy-source",
                "code": "entry_path = archive_entry.name",
            }
        ]
        finding["attackPath"] = {"dataflow": {"evidence_refs": ["legacy-source"]}}
        self.write_scan()

        _, findings, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(
            findings["findings"][0]["attackPath"]["dataflow"]["evidence_refs"],
            ["legacy-source"],
        )

    def test_finalize_rejects_duplicate_ids_across_code_evidence_aliases(self) -> None:
        finding = self.findings["findings"][0]
        finding["codeEvidence"] = [
            {
                "id": "shared-source",
                "label": "Canonical source",
                "path": "src/extract.py",
                "startLine": 41,
                "code": "canonical_source()",
                "explanation": "Canonical snippet.",
            }
        ]
        finding["code_evidence"] = [{"id": "shared-source", "code": "conflicting_legacy_source()"}]
        self.write_scan()

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            r"code_evidence\[0\]\.id: duplicate code-evidence id",
        ):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_sealed_rerun_accepts_legacy_scalar_finding_details(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["validation"] = {
            "assertions": "The destination escapes the extraction root.",
            "counterEvidence": None,
            "limitations": "",
            "method": "",
            "status": "",
            "summary": "",
            "disposition": "",
            "result": "",
        }
        findings["findings"][0]["attackPath"] = {
            "dataFlow": None,
            "dataflow": {
                "summary": "",
                "source": None,
                "sink": None,
                "outcome": None,
            },
            "impact": {"level": "", "rationale": None, "why": None},
            "likelihood": {"level": None, "rationale": None, "why": None},
            "reachability": None,
            "summary": "",
        }
        findings["findings"][0]["root_cause"] = None
        self.rewrite_sealed_artifact("findings.json", findings)
        sealed_bytes = (self.scan_dir / "findings.json").read_bytes()

        _, accepted, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(
            accepted["findings"][0]["validation"]["assertions"],
            "The destination escapes the extraction root.",
        )
        self.assertEqual(accepted["findings"][0]["validation"]["limitations"], "")
        self.assertIsNone(accepted["findings"][0]["validation"]["counterEvidence"])
        self.assertEqual(accepted["findings"][0]["validation"]["method"], "")
        self.assertEqual(accepted["findings"][0]["validation"]["status"], "")
        self.assertEqual(accepted["findings"][0]["validation"]["summary"], "")
        self.assertEqual(accepted["findings"][0]["validation"]["disposition"], "")
        self.assertEqual(accepted["findings"][0]["validation"]["result"], "")
        self.assertIsNone(accepted["findings"][0]["attackPath"]["dataFlow"])
        self.assertEqual(accepted["findings"][0]["attackPath"]["dataflow"]["summary"], "")
        self.assertEqual(accepted["findings"][0]["attackPath"]["impact"]["level"], "")
        self.assertIsNone(accepted["findings"][0]["attackPath"]["likelihood"]["level"])
        self.assertIsNone(accepted["findings"][0]["attackPath"]["reachability"])
        self.assertEqual(accepted["findings"][0]["attackPath"]["summary"], "")
        self.assertIsNone(accepted["findings"][0]["root_cause"])
        self.assertEqual((self.scan_dir / "findings.json").read_bytes(), sealed_bytes)

    def test_sealed_rerun_rejects_malformed_canonical_root_cause(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["rootCause"] = {"summary": []}
        self.rewrite_sealed_artifact("findings.json", findings)
        sealed_bytes = (self.scan_dir / "findings.json").read_bytes()

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            r"rootCause\.summary",
        ):
            FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual((self.scan_dir / "findings.json").read_bytes(), sealed_bytes)

    def test_sealed_rerun_accepts_nullable_legacy_evidence_catalog(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["code_evidence"] = None
        self.rewrite_sealed_artifact("findings.json", findings)
        sealed_bytes = (self.scan_dir / "findings.json").read_bytes()

        _, accepted, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertIsNone(accepted["findings"][0]["code_evidence"])
        self.assertEqual((self.scan_dir / "findings.json").read_bytes(), sealed_bytes)

    def test_sealed_rerun_accepts_empty_legacy_root_cause(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["root_cause"] = ""
        self.rewrite_sealed_artifact("findings.json", findings)
        sealed_bytes = (self.scan_dir / "findings.json").read_bytes()

        _, accepted, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(accepted["findings"][0]["root_cause"], "")
        self.assertEqual((self.scan_dir / "findings.json").read_bytes(), sealed_bytes)

    def test_sealed_rerun_ignores_malformed_legacy_evidence_rows(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["code_evidence"] = [
            None,
            "legacy source",
            {},
            {"id": "", "code": "empty_id()"},
            {"id": "missing-code"},
            {"id": "empty-code", "code": ""},
            {"id": "legacy-source", "code": "legacy_source()"},
        ]
        self.rewrite_sealed_artifact("findings.json", findings)
        sealed_bytes = (self.scan_dir / "findings.json").read_bytes()

        _, accepted, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(accepted, findings)
        self.assertEqual((self.scan_dir / "findings.json").read_bytes(), sealed_bytes)

    def test_unsealed_scan_rejects_malformed_legacy_evidence_rows(self) -> None:
        self.findings["findings"][0]["code_evidence"] = [None]
        self.write_scan()

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            r"code_evidence\[0\]: expected an object",
        ):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_unsealed_scan_rejects_nullable_legacy_evidence_catalog(self) -> None:
        self.findings["findings"][0]["code_evidence"] = None
        self.write_scan()

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            "code_evidence: expected an array",
        ):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_unsealed_scan_rejects_legacy_scalar_finding_details(self) -> None:
        self.findings["findings"][0]["validation"] = {
            "assertions": "The destination escapes the extraction root."
        }
        self.write_scan()

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            "validation.assertions: expected schema type array",
        ):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_sealed_rerun_accepts_legacy_sequence_attack_path_details(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["attackPath"] = {
            "dataflow": ["archive entry path", "filesystem write"],
            "reachability": ["authenticated uploader"],
        }
        self.rewrite_sealed_artifact("findings.json", findings)
        sealed_bytes = (self.scan_dir / "findings.json").read_bytes()

        _, accepted, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(
            accepted["findings"][0]["attackPath"]["dataflow"],
            ["archive entry path", "filesystem write"],
        )
        self.assertEqual(
            accepted["findings"][0]["attackPath"]["reachability"],
            ["authenticated uploader"],
        )
        self.assertEqual((self.scan_dir / "findings.json").read_bytes(), sealed_bytes)

    def test_non_standard_json_numbers_are_rejected(self) -> None:
        self.findings["findings"][0]["validation"] = {"score": float("nan")}
        self.write_scan()

        with self.assertRaisesRegex(FINALIZER.ContractError, "invalid JSON.*NaN"):
            FINALIZER.finalize_scan(self.scan_dir)
        with self.assertRaisesRegex(FINALIZER.ContractError, "cannot encode canonical JSON"):
            FINALIZER._json_bytes({"score": float("nan")})

    def test_sealed_rerun_regenerates_reports_without_mutating_canonical_artifacts(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        canonical_before = {
            name: (self.scan_dir / name).read_bytes()
            for name in ("scan-manifest.json", "findings.json", "coverage.json")
        }
        (self.scan_dir / "report.md").write_text("# stale report\n", encoding="utf-8")

        FINALIZER.finalize_scan(self.scan_dir)

        canonical_after = {
            name: (self.scan_dir / name).read_bytes()
            for name in ("scan-manifest.json", "findings.json", "coverage.json")
        }
        self.assertEqual(canonical_before, canonical_after)
        self.assertNotIn("stale report", (self.scan_dir / "report.md").read_text(encoding="utf-8"))
        self.assertFalse((self.scan_dir / "report.html").exists())

    def test_failed_finalization_does_not_rewrite_semantic_artifacts(self) -> None:
        self.manifest["scan"]["target"]["snapshotDigest"] = "invalid"
        self.write_scan()
        findings = (self.scan_dir / "findings.json").read_bytes()
        coverage = (self.scan_dir / "coverage.json").read_bytes()
        report_markdown = (self.scan_dir / "report.md").read_bytes()

        with self.assertRaisesRegex(FINALIZER.ContractError, "schema pattern"):
            FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(findings, (self.scan_dir / "findings.json").read_bytes())
        self.assertEqual(coverage, (self.scan_dir / "coverage.json").read_bytes())
        self.assertEqual(report_markdown, (self.scan_dir / "report.md").read_bytes())

    def test_prepared_finalization_does_not_write_until_committed(self) -> None:
        self.findings["findings"][0]["findingId"] = "csf_wrong"
        self.coverage["openQuestions"] = ["  Which path is reachable?  "]
        self.write_scan()
        before = {
            name: (self.scan_dir / name).read_bytes()
            for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
        }

        prepared = FINALIZER._prepare_scan_finalization(self.scan_dir)

        self.assertEqual(
            before,
            {
                name: (self.scan_dir / name).read_bytes()
                for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
            },
        )
        FINALIZER._write_prepared_scan_finalization(prepared)
        manifest = self.read_json("scan-manifest.json")
        self.assertIn("sealedAt", manifest["scan"])

    def test_report_projection_rejects_symlink_output_without_sealing(self) -> None:
        self.write_scan()
        (self.scan_dir / "report.md").unlink()
        with tempfile.TemporaryDirectory() as external_dir:
            external_report = Path(external_dir) / "report.md"
            external_report.write_text("unchanged\n", encoding="utf-8")
            (self.scan_dir / "report.md").symlink_to(external_report)

            with self.assertRaisesRegex(FINALIZER.ContractError, "non-symlink path"):
                FINALIZER.finalize_scan(self.scan_dir)

            self.assertEqual(external_report.read_text(encoding="utf-8"), "unchanged\n")
            manifest = self.read_json("scan-manifest.json")
            self.assertNotIn("sealedAt", manifest["scan"])
            self.assertNotIn("artifacts", manifest["scan"])

    def test_report_semantics_are_schema_validated_before_projection(self) -> None:
        self.manifest["scan"]["threatModel"] = {"summary": ["not a string"]}
        self.write_scan()
        report_markdown = (self.scan_dir / "report.md").read_bytes()

        with self.assertRaisesRegex(FINALIZER.ContractError, "schema type string"):
            FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(report_markdown, (self.scan_dir / "report.md").read_bytes())
        manifest = self.read_json("scan-manifest.json")
        self.assertNotIn("sealedAt", manifest["scan"])
        self.assertNotIn("artifacts", manifest["scan"])

    def test_rejects_non_finite_json_numbers(self) -> None:
        self.write_scan()
        findings_path = self.scan_dir / "findings.json"
        raw = findings_path.read_text(encoding="utf-8").replace(
            '"attackPath": null',
            '"attackPath": {"likelihood": NaN}',
        )
        findings_path.write_text(raw, encoding="utf-8")

        with self.assertRaisesRegex(FINALIZER.ContractError, "non-finite JSON number"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_rerun_preserves_additional_sealed_artifact_records(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        extra_path = self.scan_dir / "exports" / "extra.json"
        extra_path.parent.mkdir(parents=True, exist_ok=True)
        extra_path.write_text("{}\n", encoding="utf-8")
        manifest = self.read_json("scan-manifest.json")
        manifest["scan"]["artifacts"].append(
            FINALIZER._artifact_record(self.scan_dir, "exports/extra.json", "application/json")
        )
        self.write_json("scan-manifest.json", manifest)
        sealed_manifest = (self.scan_dir / "scan-manifest.json").read_bytes()

        FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(sealed_manifest, (self.scan_dir / "scan-manifest.json").read_bytes())

    def test_seals_coverage_receipt_refs(self) -> None:
        receipt_ref = "artifacts/02_discovery/./work_ledger.jsonl"
        normalized_ref = "artifacts/02_discovery/work_ledger.jsonl"
        self.coverage["surfaces"][0]["receiptRefs"] = [receipt_ref]
        self.write_scan()
        receipt_path = self.scan_dir / receipt_ref
        receipt_path.parent.mkdir(parents=True)
        receipt_path.write_text('{"status":"reviewed"}\n', encoding="utf-8")

        FINALIZER.finalize_scan(self.scan_dir)

        manifest = self.read_json("scan-manifest.json")
        coverage = self.read_json("coverage.json")
        self.assertEqual(coverage["surfaces"][0]["receiptRefs"], [normalized_ref])
        self.assertIn(
            normalized_ref, [artifact["path"] for artifact in manifest["scan"]["artifacts"]]
        )
        receipt_path.write_text('{"status":"changed"}\n', encoding="utf-8")
        with self.assertRaisesRegex(FINALIZER.ContractError, "sealed artifact changed"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_verifies_legacy_aliased_receipt_ref(self) -> None:
        receipt_ref = "artifacts/02_discovery/work_ledger.jsonl"
        legacy_ref = "artifacts/02_discovery/./work_ledger.jsonl"
        self.coverage["surfaces"][0]["receiptRefs"] = [receipt_ref]
        self.write_scan()
        receipt_path = self.scan_dir / receipt_ref
        receipt_path.parent.mkdir(parents=True)
        receipt_path.write_text('{"status":"reviewed"}\n', encoding="utf-8")
        FINALIZER.finalize_scan(self.scan_dir)

        coverage = self.read_json("coverage.json")
        coverage["surfaces"][0]["receiptRefs"] = [legacy_ref]
        self.write_json("coverage.json", coverage)
        manifest = self.read_json("scan-manifest.json")
        for artifact in manifest["scan"]["artifacts"]:
            if artifact["path"] == "coverage.json":
                artifact["sha256"] = FINALIZER._sha256_file(self.scan_dir / "coverage.json")
            elif artifact["path"] == receipt_ref:
                artifact["path"] = legacy_ref
        self.write_json("scan-manifest.json", manifest)
        sealed_manifest = (self.scan_dir / "scan-manifest.json").read_bytes()

        FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(sealed_manifest, (self.scan_dir / "scan-manifest.json").read_bytes())

    def test_rejects_unsealed_coverage_receipt_ref_in_sealed_bundle(self) -> None:
        receipt_ref = "artifacts/02_discovery/work_ledger.jsonl"
        self.coverage["surfaces"][0]["receiptRefs"] = [receipt_ref]
        self.write_scan()
        receipt_path = self.scan_dir / receipt_ref
        receipt_path.parent.mkdir(parents=True)
        receipt_path.write_text('{"status":"reviewed"}\n', encoding="utf-8")
        FINALIZER.finalize_scan(self.scan_dir)
        manifest = self.read_json("scan-manifest.json")
        manifest["scan"]["artifacts"] = [
            artifact
            for artifact in manifest["scan"]["artifacts"]
            if artifact["path"] != receipt_ref
        ]
        self.write_json("scan-manifest.json", manifest)

        with self.assertRaisesRegex(FINALIZER.ContractError, "missing from sealed artifacts"):
            FINALIZER.finalize_scan(self.scan_dir)

        warnings: list[str] = []
        with self.assertRaisesRegex(FINALIZER.ContractError, "missing from sealed artifacts"):
            FINALIZER._prepare_scan_finalization(self.scan_dir, completion_warnings=warnings)
        self.assertEqual(warnings, [])

    def test_fingerprint_survives_line_movement_and_file_rename(self) -> None:
        renamed = copy.deepcopy(self.finding)
        renamed["locations"][0] = {
            "path": "src/archive/extract_entry.py",
            "startLine": 140,
            "endLine": 143,
            "role": "sink",
        }
        first = FINALIZER._fingerprint("target_sha256_example", self.finding)
        second = FINALIZER._fingerprint("target_sha256_example", renamed)
        self.assertEqual(first, second)

    def test_sibling_instances_get_distinct_fingerprints(self) -> None:
        sibling = copy.deepcopy(self.finding)
        sibling["identity"]["instance"] = "extract-symlink-entry"
        first = FINALIZER._fingerprint("target_sha256_example", self.finding)
        second = FINALIZER._fingerprint("target_sha256_example", sibling)
        self.assertNotEqual(first, second)

    def test_dirty_worktree_snapshot_does_not_change_logical_fingerprint(self) -> None:
        target = self.manifest["scan"]["target"]
        FINALIZER._validate_target(target)
        first = FINALIZER._fingerprint(target["targetId"], self.finding)
        target.pop("snapshotDigest")
        with self.assertRaisesRegex(FINALIZER.ContractError, "snapshotDigest"):
            FINALIZER._validate_target(target)
        target["snapshotDigest"] = (
            "codex-security-snapshot/v1:sha256:1111111111111111111111111111111111111111111111111111111111111111"
        )
        FINALIZER._validate_target(target)
        second = FINALIZER._fingerprint(target["targetId"], self.finding)
        self.assertEqual(first, second)

    def test_sarif_rule_identity_is_stable_across_occurrences(self) -> None:
        sibling = copy.deepcopy(self.finding)
        sibling["severity"] = {
            "level": "critical",
            "score": 9.4,
            "scoringSystem": "CVSS:3.1",
        }
        sibling["taxonomy"]["cwe"] = ["CWE-22", "CWE-59"]
        sibling["title"] = "Another occurrence"
        sibling["remediation"] = "Apply a different control."
        first = FINALIZER._sarif_rule(self.finding["ruleId"], [self.finding])
        second = FINALIZER._sarif_rule(sibling["ruleId"], [sibling])
        for key in ("id", "name", "shortDescription"):
            self.assertEqual(first[key], second[key])
        self.assertNotEqual(first["name"], self.finding["ruleId"])
        self.assertEqual(first["properties"]["security-severity"], "8.1")
        self.assertEqual(second["properties"]["security-severity"], "9.4")

    def test_sarif_adds_only_candidate_id_to_deep_result_presentation(self) -> None:
        finding = copy.deepcopy(self.finding)
        finding["findingId"] = "csf_example"
        finding["occurrenceId"] = "occ_example"
        finding["fingerprints"] = {"primary": "fingerprint"}
        finding["extensions"] = {
            "candidateId": "DSS-145",
            "reportId": "DSS-145-rogue-fw",
        }

        result = FINALIZER._sarif_result(finding, 0)

        baseline = FINALIZER._sarif_result({**finding, "extensions": {}}, 0)
        baseline["properties"]["candidateId"] = "DSS-145"
        self.assertEqual(result, baseline)
        self.assertIn(finding["summary"], result["message"]["text"])
        self.assertIn(finding["remediation"], result["message"]["text"])
        self.assertEqual(result["properties"]["candidateId"], "DSS-145")
        self.assertNotIn("reportId", result["properties"])
        self.assertNotIn("findingTitle", result["properties"])
        self.assertNotIn("writeupPath", result["properties"])

    def test_unsealed_findings_replace_authored_identity_fields(self) -> None:
        self.findings["findings"][0]["findingId"] = "csf_wrong"
        self.findings["findings"][0]["occurrenceId"] = "occ_wrong"
        self.findings["findings"][0]["fingerprints"] = {
            "algorithm": "codex-security/v0",
            "primary": "codex-security/v0:sha256:example",
        }
        self.write_scan()

        _, findings, _ = FINALIZER.finalize_scan(self.scan_dir)

        finding = findings["findings"][0]
        self.assertRegex(finding["findingId"], r"^csf_[a-f0-9]{24}$")
        self.assertRegex(finding["occurrenceId"], r"^occ_[a-f0-9]{24}$")
        self.assertEqual(finding["fingerprints"]["algorithm"], "codex-security/v1")
        self.assertNotEqual(finding["fingerprints"]["primary"], "codex-security/v0:sha256:example")

    def test_recovery_normalizes_severity_change_condition_lists(self) -> None:
        self.findings["findings"][0]["severity"]["changeConditions"] = [
            " Raise if the vulnerable path becomes internet-reachable. ",
            "Lower if the input is constrained before parsing.",
        ]
        self.write_scan()
        warnings: list[str] = []

        prepared = FINALIZER._prepare_scan_finalization(self.scan_dir, completion_warnings=warnings)

        finding = prepared[3]["findings"][0]
        self.assertEqual(
            finding["severity"]["changeConditions"],
            "Raise if the vulnerable path becomes internet-reachable. "
            "Lower if the input is constrained before parsing.",
        )
        self.assertEqual(warnings, ["Recovered finding 1: normalized severity change conditions."])
        self.assertEqual(prepared[4]["completeness"], "complete")

    def test_recovery_ranks_legacy_and_canonical_code_evidence_equally(self) -> None:
        canonical_evidence = {
            "id": "canonical-source",
            "label": "Canonical source",
            "path": "src/extract.py",
            "startLine": 41,
            "code": "canonical_source()",
            "explanation": "Canonical snippet.",
        }
        legacy_evidence = {"id": "legacy-source", "code": "legacy_source()"}
        for evidence_field, evidence in (
            ("codeEvidence", canonical_evidence),
            ("code_evidence", legacy_evidence),
        ):
            with self.subTest(evidence_field=evidence_field):
                first = copy.deepcopy(self.finding)
                first["summary"] = "FIRST"
                second = copy.deepcopy(self.finding)
                second["summary"] = "SECOND"
                second[evidence_field] = [copy.deepcopy(evidence)]
                second["root_cause"] = None
                self.findings["findings"] = [first, second]
                self.write_scan()
                warnings: list[str] = []

                prepared = FINALIZER._prepare_scan_finalization(
                    self.scan_dir, completion_warnings=warnings
                )

                self.assertEqual(prepared[3]["findings"][0]["summary"], "SECOND")
                self.assertIsNone(prepared[3]["findings"][0]["root_cause"])
                self.assertTrue(
                    any(
                        "retained stronger duplicate logical finding" in warning
                        for warning in warnings
                    )
                )

    def test_recovery_ranks_embedded_root_cause_evidence(self) -> None:
        for name, root_cause in (
            (
                "embedded",
                {
                    "summary": "Richer root cause.",
                    "codeEvidence": [{"id": "embedded-root", "code": "embedded_root()"}],
                },
            ),
            (
                "legacy-code",
                {"summary": "Richer root cause.", "code": "legacy_root()"},
            ),
        ):
            with self.subTest(name=name):
                first = copy.deepcopy(self.finding)
                first.pop("codeEvidence", None)
                first["summary"] = "FIRST"
                second = copy.deepcopy(first)
                second["summary"] = "SECOND"
                second["rootCause"] = root_cause
                self.findings["findings"] = [first, second]
                self.write_scan()
                warnings: list[str] = []

                prepared = FINALIZER._prepare_scan_finalization(
                    self.scan_dir, completion_warnings=warnings
                )

                self.assertEqual(prepared[3]["findings"][0]["summary"], "SECOND")
                self.assertTrue(
                    any(
                        "retained stronger duplicate logical finding" in warning
                        for warning in warnings
                    )
                )

    def test_recovery_rejects_malformed_severity_change_condition_lists(self) -> None:
        for change_conditions in ([], ["  "], ["Valid condition.", 1], ["\ud800"]):
            with self.subTest(change_conditions=repr(change_conditions)):
                self.findings["findings"][0]["severity"]["changeConditions"] = change_conditions
                self.write_scan()
                warnings: list[str] = []

                prepared = FINALIZER._prepare_scan_finalization(
                    self.scan_dir, completion_warnings=warnings
                )

                self.assertEqual(prepared[3]["findings"], [])
                self.assertEqual(prepared[4]["completeness"], "partial")
                self.assertEqual(len(warnings), 1)
                self.assertIn("severity.changeConditions", warnings[0])

    def test_unsealed_invalid_anchor_stays_strict_without_recovery(self) -> None:
        self.findings["findings"][0]["identity"]["anchor"] = "Invalid Anchor"
        self.write_scan()

        with self.assertRaisesRegex(FINALIZER.ContractError, "stable lowercase semantic slug"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_recovery_preserves_finding_with_malformed_optional_remediation_fields(self) -> None:
        for field, value in (
            ("remediationTests", "Reject unsafe archive paths."),
            ("remediationTests", [{"test": "Reject unsafe archive paths."}]),
            ("preventiveControls", "Validate every archive path."),
        ):
            with self.subTest(field=field, value=value):
                self.findings["findings"][0][field] = value
                self.write_scan()
                warnings: list[str] = []

                _, _, _, findings, coverage, _, _ = FINALIZER._prepare_scan_finalization(
                    self.scan_dir,
                    completion_warnings=warnings,
                )

                self.assertEqual(len(findings["findings"]), 1)
                self.assertNotIn(field, findings["findings"][0])
                self.assertEqual(coverage["completeness"], "complete")
                self.assertTrue(
                    any(warning.startswith(f"Skipped malformed {field}") for warning in warnings)
                )
                self.findings["findings"][0].pop(field)

    def test_recovery_keeps_valid_optional_remediation_fields(self) -> None:
        finding = self.findings["findings"][0]
        finding["remediationTests"] = ["Reject unsafe archive paths."]
        finding["preventiveControls"] = ["Validate every archive path."]
        self.write_scan()
        warnings: list[str] = []

        _, _, _, findings, _, _, _ = FINALIZER._prepare_scan_finalization(
            self.scan_dir,
            completion_warnings=warnings,
        )

        self.assertEqual(findings["findings"][0]["remediationTests"], finding["remediationTests"])
        self.assertEqual(
            findings["findings"][0]["preventiveControls"], finding["preventiveControls"]
        )
        self.assertFalse(warnings)

    def test_sealed_findings_keep_authored_identity_mismatches_strict(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        findings["findings"][0]["findingId"] = "csf_wrong"
        self.rewrite_sealed_artifact("findings.json", findings)

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            "findingId: does not match derived fingerprint identity",
        ):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_remote_url_credentials(self) -> None:
        self.manifest["scan"]["target"]["remote"] = "https://token@example.com/repo"
        self.write_scan()
        with self.assertRaisesRegex(FINALIZER.ContractError, "must not contain credentials"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_remote_url_query(self) -> None:
        self.manifest["scan"]["target"]["remote"] = "https://example.com/repo?token=secret"
        self.write_scan()
        with self.assertRaisesRegex(FINALIZER.ContractError, "must not contain credentials"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_repository_root_finding_location(self) -> None:
        self.findings["findings"][0]["locations"][0]["path"] = "."
        self.write_scan()
        with self.assertRaisesRegex(FINALIZER.ContractError, "safe repository-relative"):
            FINALIZER.finalize_scan(self.scan_dir, source_root=self.scan_dir)

    def test_allows_repository_root_scope(self) -> None:
        self.manifest["scan"]["scope"]["includePaths"] = ["."]
        self.coverage["includePaths"] = ["."]
        self.write_scan()

        FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(
            self.read_json("scan-manifest.json")["scan"]["scope"]["includePaths"], ["."]
        )

    def test_rejects_missing_coverage_receipt(self) -> None:
        self.coverage["surfaces"][0]["receiptRefs"] = ["artifacts/02_discovery/work_ledger.jsonl"]
        self.write_scan()
        with self.assertRaisesRegex(FINALIZER.ContractError, "inside the scan directory"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_coverage_receipt_refs_outside_artifacts(self) -> None:
        for receipt_ref in (
            "scan-manifest.json",
            "findings.json/.",
            "coverage.json",
            "report.md",
        ):
            with self.subTest(receipt_ref=receipt_ref):
                self.coverage["surfaces"][0]["receiptRefs"] = [receipt_ref]
                self.write_scan()
                with self.assertRaisesRegex(FINALIZER.ContractError, "under artifacts/"):
                    FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_symlink_receipt(self) -> None:
        receipt_ref = "artifacts/02_discovery/work_ledger.jsonl"
        self.coverage["surfaces"][0]["receiptRefs"] = [receipt_ref]
        self.write_scan()
        receipt_path = self.scan_dir / receipt_ref
        receipt_path.parent.mkdir(parents=True)
        target_path = receipt_path.with_name("real_work_ledger.jsonl")
        target_path.write_text('{"status":"reviewed"}\n', encoding="utf-8")
        receipt_path.symlink_to(target_path)
        with self.assertRaisesRegex(FINALIZER.ContractError, "non-symlink"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_external_symlink_canonical_document(self) -> None:
        self.write_scan()
        findings_path = self.scan_dir / "findings.json"
        with tempfile.TemporaryDirectory() as external_dir:
            external_path = Path(external_dir) / "findings.json"
            external_path.write_bytes(findings_path.read_bytes())
            findings_path.unlink()
            findings_path.symlink_to(external_path)
            with self.assertRaisesRegex(FINALIZER.ContractError, "inside the scan directory"):
                FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_complete_coverage_with_needs_follow_up_surface(self) -> None:
        self.coverage["surfaces"][0]["disposition"] = "needs_follow_up"
        self.write_scan()
        with self.assertRaisesRegex(FINALIZER.ContractError, "cannot have deferred work"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_complete_coverage_with_deferred_work(self) -> None:
        self.coverage["deferred"] = [
            {
                "id": "deferred_archive_review",
                "reason": "Archive extraction review was not completed.",
            }
        ]
        self.write_scan()
        with self.assertRaisesRegex(FINALIZER.ContractError, "cannot have deferred work"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_non_rfc3339_timestamps(self) -> None:
        for timestamp in ("2026-W22-7T18:09:00+00:00", "2026-05-31T18:09:00+0000"):
            with self.subTest(timestamp=timestamp):
                self.manifest["scan"]["startedAt"] = timestamp
                self.write_scan()
                with self.assertRaisesRegex(FINALIZER.ContractError, "RFC 3339 timestamp"):
                    FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_coverage_scope_mismatch(self) -> None:
        self.coverage["includePaths"] = ["other/"]
        self.write_scan()
        with self.assertRaisesRegex(FINALIZER.ContractError, "must match manifest scope"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_unsealed_contract_refs_are_replaced_with_canonical_refs(self) -> None:
        self.manifest["scan"]["coverageRef"] = "not-the-coverage.json"
        self.manifest["scan"]["findingsRef"] = "not-the-findings.json"
        self.write_scan()

        manifest, _, _ = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(manifest["scan"]["coverageRef"], "coverage.json")
        self.assertEqual(manifest["scan"]["findingsRef"], "findings.json")

    def test_sealed_contract_refs_remain_strict(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        manifest = self.read_json("scan-manifest.json")
        manifest["scan"]["coverageRef"] = "not-the-coverage.json"
        self.write_json("scan-manifest.json", manifest)

        with self.assertRaisesRegex(FINALIZER.ContractError, "expected 'coverage.json'"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_completion_binding_populates_unsealed_workbench_envelope(self) -> None:
        scan = self.manifest["scan"]
        self.manifest["documentType"] = "wrong.manifest"
        self.manifest["schemaVersion"] = "wrong"
        scan["id"] = "wrong-scan"
        scan["status"] = "running"
        scan["producer"] = {"name": "wrong-producer", "version": "wrong-version"}
        scan["startedAt"] = "wrong"
        scan["completedAt"] = "wrong"
        scan["coverageRef"] = "wrong-coverage.json"
        scan["findingsRef"] = "wrong-findings.json"
        scan["target"]["targetId"] = "wrong-target"
        scan["target"]["displayName"] = "wrong-name"
        scan["target"]["revision"] = "wrong-revision"
        scan["target"]["snapshotDigest"] = (
            "codex-security-snapshot/v1:sha256:"
            "1111111111111111111111111111111111111111111111111111111111111111"
        )
        scan["target"]["baseRevision"] = "stale-base"
        scan["target"]["headRevision"] = "stale-head"
        scan["scope"]["includePaths"] = ["wrong/"]
        scan["scope"]["excludePaths"] = ["wrong/"]
        self.findings["documentType"] = "wrong.findings"
        self.findings["schemaVersion"] = "wrong"
        self.findings["scanId"] = "wrong-scan"
        self.findings["findings"][0]["findingId"] = "csf_wrong"
        self.findings["findings"][0]["occurrenceId"] = "occ_wrong"
        self.coverage["documentType"] = "wrong.coverage"
        self.coverage["schemaVersion"] = "wrong"
        self.coverage["scanId"] = "wrong-scan"
        self.coverage["mode"] = "scoped_path"
        self.coverage["includePaths"] = ["wrong/"]
        self.coverage["excludePaths"] = ["wrong/"]
        self.write_scan()

        with mock.patch.dict(os.environ, {"CODEX_SECURITY_STARTED_AT": "not-a-timestamp"}):
            manifest, findings, coverage = FINALIZER.finalize_scan(
                self.scan_dir,
                expected_coverage_mode="repository",
                completion_binding=self.completion_binding(),
            )

        self.assertEqual(manifest["documentType"], "codex-security.scan-manifest")
        self.assertEqual(manifest["schemaVersion"], "1.0")
        self.assertEqual(manifest["scan"]["id"], "scan_001")
        self.assertEqual(manifest["scan"]["status"], "completed")
        self.assertEqual(
            manifest["scan"]["producer"],
            {"name": "codex-security-plugin", "version": "0.1.0"},
        )
        self.assertEqual(manifest["scan"]["startedAt"], "2026-05-31T18:00:00Z")
        self.assertEqual(manifest["scan"]["completedAt"], "2026-05-31T18:10:00Z")
        self.assertEqual(manifest["scan"]["sealedAt"], "2026-05-31T18:10:00Z")
        self.assertEqual(manifest["scan"]["coverageRef"], "coverage.json")
        self.assertEqual(manifest["scan"]["findingsRef"], "findings.json")
        self.assertEqual(manifest["scan"]["target"]["targetId"], "target_sha256_example")
        self.assertEqual(manifest["scan"]["target"]["displayName"], "example/repo")
        self.assertEqual(manifest["scan"]["target"]["revision"], "deadbeef")
        self.assertNotIn("baseRevision", manifest["scan"]["target"])
        self.assertNotIn("headRevision", manifest["scan"]["target"])
        self.assertEqual(manifest["scan"]["scope"], {"includePaths": ["src/"], "excludePaths": []})
        self.assertEqual(findings["documentType"], "codex-security.findings")
        self.assertEqual(findings["schemaVersion"], "1.0")
        self.assertEqual(findings["scanId"], "scan_001")
        self.assertRegex(findings["findings"][0]["findingId"], r"^csf_[a-f0-9]{24}$")
        self.assertRegex(findings["findings"][0]["occurrenceId"], r"^occ_[a-f0-9]{24}$")
        self.assertEqual(coverage["documentType"], "codex-security.coverage")
        self.assertEqual(coverage["schemaVersion"], "1.0")
        self.assertEqual(coverage["scanId"], "scan_001")
        self.assertEqual(coverage["mode"], "repository")
        self.assertEqual(coverage["includePaths"], ["src/"])
        self.assertEqual(coverage["excludePaths"], [])

    def test_completion_binding_rejects_sealed_wrong_producer_without_rewriting(self) -> None:
        self.write_scan()
        manifest, _, _ = FINALIZER.finalize_scan(self.scan_dir)
        binding = self.completion_binding()
        binding["startedAt"] = manifest["scan"]["startedAt"]
        binding["completedAt"] = manifest["scan"]["completedAt"]
        binding["producer"] = {"name": "wrong-producer", "version": "0.1.0"}
        canonical = {
            name: (self.scan_dir / name).read_bytes()
            for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
        }

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            "manifest.scan.producer: must match the workbench producer",
        ):
            FINALIZER.finalize_scan(
                self.scan_dir,
                expected_coverage_mode="repository",
                completion_binding=binding,
            )

        self.assertEqual(
            canonical,
            {name: (self.scan_dir / name).read_bytes() for name in canonical},
        )

    def test_completion_binding_preserves_required_unbound_diff_snapshot_digest(self) -> None:
        scan = self.manifest["scan"]
        target = scan["target"]
        target["kind"] = "git_diff"
        target["revision"] = "stale-revision"
        authored_snapshot_digest = target["snapshotDigest"]
        binding = self.completion_binding()
        binding["target"] = {
            "targetId": "target_sha256_example",
            "displayName": "example/repo",
            "baseRevision": "bound-base",
            "headRevision": "bound-head",
        }
        binding["allowedTargetKinds"] = ["git_diff"]
        self.write_scan()

        manifest, _, _ = FINALIZER.finalize_scan(
            self.scan_dir,
            expected_coverage_mode="repository",
            completion_binding=binding,
        )

        finalized_target = manifest["scan"]["target"]
        self.assertNotIn("revision", finalized_target)
        self.assertEqual(finalized_target["baseRevision"], "bound-base")
        self.assertEqual(finalized_target["headRevision"], "bound-head")
        self.assertEqual(finalized_target["snapshotDigest"], authored_snapshot_digest)

    def test_unsealed_open_questions_drop_only_invalid_optional_rows(self) -> None:
        self.coverage["openQuestions"] = [
            "  Which parser paths are reachable?  ",
            "   ",
            {
                "question": "  Can this reach a worker?  ",
                "followUpPrompt": "  Trace the worker path.  ",
            },
            {"question": "  Is auth enforced?  ", "followUpPrompt": "  "},
            {"question": ""},
            {"question": 7},
            42,
        ]
        self.write_scan()

        _, _, coverage = FINALIZER.finalize_scan(self.scan_dir)

        self.assertEqual(
            coverage["openQuestions"],
            [
                {"question": "Which parser paths are reachable?"},
                {
                    "question": "Can this reach a worker?",
                    "followUpPrompt": "  Trace the worker path.  ",
                },
                {"question": "Is auth enforced?"},
            ],
        )

    def test_unsealed_non_array_open_questions_are_removed(self) -> None:
        self.coverage["openQuestions"] = {"question": "not an array"}
        self.write_scan()

        _, _, coverage = FINALIZER.finalize_scan(self.scan_dir)

        self.assertNotIn("openQuestions", coverage)

    def test_sealed_coverage_mode_and_open_questions_remain_strict(self) -> None:
        self.coverage["openQuestions"] = [{"question": "Still valid before sealing."}]
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        coverage = self.read_json("coverage.json")
        coverage["mode"] = "scoped_path"
        coverage["openQuestions"] = ["invalid sealed row"]
        self.rewrite_sealed_artifact("coverage.json", coverage)

        with self.assertRaisesRegex(
            FINALIZER.ContractError,
            "coverage.mode: must match selected scan mode repository",
        ):
            FINALIZER.finalize_scan(self.scan_dir, expected_coverage_mode="repository")

        coverage["mode"] = "repository"
        self.rewrite_sealed_artifact("coverage.json", coverage)
        with self.assertRaisesRegex(FINALIZER.ContractError, "expected schema type object"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_duplicate_artifact_paths(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        manifest = self.read_json("scan-manifest.json")
        manifest["scan"]["artifacts"].append(copy.deepcopy(manifest["scan"]["artifacts"][0]))
        self.write_json("scan-manifest.json", manifest)
        with self.assertRaisesRegex(FINALIZER.ContractError, "duplicate artifact path"):
            FINALIZER.finalize_scan(self.scan_dir)

    def test_finalizes_no_findings_scan(self) -> None:
        self.findings["findings"] = []
        self.coverage["surfaces"][0]["disposition"] = "no_issue_found"
        self.write_scan()
        (self.scan_dir / "report.md").write_text(
            "# Security Review: example/repo\n\n## Findings\n\nNo findings.\n",
            encoding="utf-8",
        )
        FINALIZER.finalize_scan(self.scan_dir)
        findings = self.read_json("findings.json")
        self.assertEqual(findings["findings"], [])
        sarif = self.read_json("exports/results.sarif")
        self.assertEqual(sarif["runs"][0]["results"], [])

    def test_sarif_encodes_location_as_relative_uri(self) -> None:
        self.finding["locations"][0]["path"] = "src/archive handlers/extract.py"
        sarif_finding = copy.deepcopy(self.finding)
        sarif_finding["findingId"] = "csf_example"
        sarif_finding["occurrenceId"] = "occ_example"
        sarif_finding["fingerprints"] = {"primary": "fingerprint"}
        result = FINALIZER._sarif_result(sarif_finding, 0)
        location = result["locations"][0]["physicalLocation"]["artifactLocation"]
        uri = location["uri"]
        self.assertEqual(uri, "src/archive%20handlers/extract.py")
        self.assertNotIn("uriBaseId", location)

    def test_sarif_omits_unresolved_source_root_metadata(self) -> None:
        sarif = FINALIZER.build_sarif(self.manifest, {"findings": []})

        self.assertNotIn("originalUriBaseIds", sarif["runs"][0])

    def test_sarif_keeps_root_first_and_preserves_sink_and_evidence_locations(self) -> None:
        sarif_finding = copy.deepcopy(self.finding)
        sarif_finding["findingId"] = "csf_example"
        sarif_finding["occurrenceId"] = "occ_example"
        sarif_finding["fingerprints"] = {"primary": "fingerprint"}
        sarif_finding["locations"] = [
            {"path": "src/route.py", "startLine": 10, "role": "entrypoint/wrapper"},
            {"path": "src/control.py", "startLine": 20, "role": "root_control"},
            {"path": "src/write.py", "startLine": 30, "role": "sink"},
        ]
        sarif_finding["codeEvidence"] = [
            {
                "id": "template-sink",
                "label": "Template sink",
                "path": "src/template.html",
                "startLine": 44,
                "endLine": 45,
                "code": "{{ user_input|safe }}",
                "explanation": "The vulnerable template occurrence.",
            },
            {
                "id": "duplicate-sink",
                "label": "Duplicate sink",
                "path": "src/write.py",
                "startLine": 30,
                "code": "write(user_input)",
                "explanation": "Already present in locations.",
            },
        ]

        result = FINALIZER._sarif_result(sarif_finding, 0)

        self.assertEqual(
            result["locations"],
            [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/control.py"},
                        "region": {"startLine": 20, "endLine": 20},
                    },
                    "message": {"text": "root_control"},
                },
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/route.py"},
                        "region": {"startLine": 10, "endLine": 10},
                    },
                    "message": {"text": "entrypoint/wrapper"},
                },
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/write.py"},
                        "region": {"startLine": 30, "endLine": 30},
                    },
                    "message": {"text": "sink"},
                },
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/template.html"},
                        "region": {"startLine": 44, "endLine": 45},
                    },
                    "message": {"text": "evidence:template-sink"},
                },
            ],
        )
        self.assertNotIn("relatedLocations", result)

    def test_sarif_includes_legacy_code_evidence_locations(self) -> None:
        sarif_finding = copy.deepcopy(self.finding)
        sarif_finding["findingId"] = "csf_example"
        sarif_finding["occurrenceId"] = "occ_example"
        sarif_finding["fingerprints"] = {"primary": "fingerprint"}
        sarif_finding["codeEvidence"] = [
            {
                "id": "canonical-source",
                "label": "Canonical source",
                "path": "src/canonical.py",
                "startLine": 12,
                "code": "canonical_source()",
                "explanation": "Canonical evidence.",
            }
        ]
        sarif_finding["code_evidence"] = [
            {
                "id": "legacy-sink",
                "path": "src/legacy.py",
                "startLine": 37,
                "endLine": 39,
                "code": "legacy_sink()",
            }
        ]

        result = FINALIZER._sarif_result(sarif_finding, 0)

        locations = {
            location["physicalLocation"]["artifactLocation"]["uri"]: location
            for location in result["locations"]
        }
        self.assertEqual(
            locations["src/legacy.py"],
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/legacy.py"},
                    "region": {"startLine": 37, "endLine": 39},
                },
                "message": {"text": "evidence:legacy-sink"},
            },
        )

    def test_sarif_normalizes_invalid_legacy_code_evidence_bounds(self) -> None:
        sarif_finding = copy.deepcopy(self.finding)
        sarif_finding["findingId"] = "csf_example"
        sarif_finding["occurrenceId"] = "occ_example"
        sarif_finding["fingerprints"] = {"primary": "fingerprint"}
        sarif_finding["code_evidence"] = [
            {
                "id": "legacy-null-end",
                "path": "src/null_end.py",
                "startLine": 37,
                "endLine": None,
                "code": "null_end()",
            },
            {
                "id": "legacy-reversed-end",
                "path": "src/reversed_end.py",
                "startLine": 48,
                "endLine": 47,
                "code": "reversed_end()",
            },
            {
                "id": "legacy-text-end",
                "path": "src/text_end.py",
                "startLine": 59,
                "endLine": "60",
                "code": "text_end()",
            },
        ]

        result = FINALIZER._sarif_result(sarif_finding, 0)

        regions = {
            location["physicalLocation"]["artifactLocation"]["uri"]: location["physicalLocation"][
                "region"
            ]
            for location in result["locations"]
        }
        self.assertEqual(regions["src/null_end.py"], {"startLine": 37, "endLine": 37})
        self.assertEqual(regions["src/reversed_end.py"], {"startLine": 48, "endLine": 48})
        self.assertEqual(regions["src/text_end.py"], {"startLine": 59, "endLine": 59})

    def test_sarif_omits_invalid_legacy_code_evidence_locations(self) -> None:
        sarif_finding = copy.deepcopy(self.finding)
        sarif_finding["findingId"] = "csf_example"
        sarif_finding["occurrenceId"] = "occ_example"
        sarif_finding["fingerprints"] = {"primary": "fingerprint"}
        sarif_finding["code_evidence"] = [
            {
                "id": "legacy-zero-start",
                "path": "src/zero.py",
                "startLine": 0,
                "code": "zero_start()",
            },
            {
                "id": "legacy-negative-start",
                "path": "src/negative.py",
                "startLine": -1,
                "code": "negative_start()",
            },
            {
                "id": "legacy-unsafe-path",
                "path": "../outside.py",
                "startLine": 81,
                "code": "unsafe_path()",
            },
        ]

        result = FINALIZER._sarif_result(sarif_finding, 0)

        uris = {
            location["physicalLocation"]["artifactLocation"]["uri"]
            for location in result["locations"]
        }
        self.assertNotIn("src/zero.py", uris)
        self.assertNotIn("src/negative.py", uris)
        self.assertNotIn("../outside.py", uris)

    def test_sarif_only_emits_provenance_for_immutable_revision(self) -> None:
        sarif = FINALIZER.build_sarif(self.manifest, {"findings": []})
        self.assertNotIn("versionControlProvenance", sarif["runs"][0])

        self.manifest["scan"]["target"]["kind"] = "git_revision"
        sarif = FINALIZER.build_sarif(self.manifest, {"findings": []})
        self.assertEqual(
            sarif["runs"][0]["versionControlProvenance"],
            [{"repositoryUri": "https://github.com/example/repo", "revisionId": "deadbeef"}],
        )

    def test_sarif_emits_github_line_hash_when_source_is_available(self) -> None:
        source_root = self.scan_dir / "source"
        source_path = source_root / "src" / "extract.py"
        source_path.parent.mkdir(parents=True)
        source_path.write_text(
            "\n".join(f"line {index}" for index in range(1, 60)), encoding="utf-8"
        )
        sarif_finding = copy.deepcopy(self.finding)
        sarif_finding["findingId"] = "csf_example"
        sarif_finding["occurrenceId"] = "occ_example"
        sarif_finding["fingerprints"] = {"primary": "semantic-fingerprint"}
        result = FINALIZER._sarif_result(sarif_finding, 0, source_root)
        fingerprints = result["partialFingerprints"]
        self.assertEqual(fingerprints["codexSecurity/v1"], "semantic-fingerprint")
        self.assertEqual(fingerprints["primaryLocationLineHash"], "614150a715d5311d:1")

    def test_sarif_emits_github_line_hash_through_windows_backend(self) -> None:
        source_root = self.scan_dir / "source"
        source_path = source_root / "src" / "extract.py"
        source_path.parent.mkdir(parents=True)
        source_path.write_text(
            "\n".join(f"line {index}" for index in range(1, 60)), encoding="utf-8"
        )
        sarif_finding = copy.deepcopy(self.finding)
        sarif_finding["findingId"] = "csf_example"
        sarif_finding["occurrenceId"] = "occ_example"
        sarif_finding["fingerprints"] = {"primary": "semantic-fingerprint"}
        backend = mock.Mock()
        backend.open_read_fd.side_effect = lambda root, relative_path, _context: os.open(
            root / relative_path, os.O_RDONLY
        )

        with (
            mock.patch.object(FINALIZER.os, "supports_dir_fd", set()),
            mock.patch.object(FINALIZER, "_is_windows", return_value=True),
            mock.patch.object(FINALIZER, "_windows_scan_local_files", return_value=backend),
        ):
            result = FINALIZER._sarif_result(sarif_finding, 0, source_root)

        backend.open_read_fd.assert_called_once_with(
            source_root, "src/extract.py", "source file src/extract.py"
        )
        self.assertEqual(
            result["partialFingerprints"]["primaryLocationLineHash"],
            "614150a715d5311d:1",
        )

    def test_sarif_line_hash_uses_root_control_location(self) -> None:
        source_root = self.scan_dir / "source"
        entrypoint_path = source_root / "src" / "route.py"
        control_path = source_root / "src" / "control.py"
        entrypoint_path.parent.mkdir(parents=True)
        entrypoint_path.write_text("entrypoint\n", encoding="utf-8")
        control_path.write_text("root control\n", encoding="utf-8")
        sarif_finding = copy.deepcopy(self.finding)
        sarif_finding["findingId"] = "csf_example"
        sarif_finding["occurrenceId"] = "occ_example"
        sarif_finding["fingerprints"] = {"primary": "semantic-fingerprint"}
        sarif_finding["locations"] = [
            {"path": "src/route.py", "startLine": 1, "role": "entrypoint/wrapper"},
            {"path": "src/control.py", "startLine": 1, "role": "root_control"},
        ]

        result = FINALIZER._sarif_result(sarif_finding, 0, source_root)

        self.assertEqual(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/control.py",
        )
        self.assertEqual(
            result["partialFingerprints"]["primaryLocationLineHash"], "41499a4b14756ba2:1"
        )

    def test_sarif_line_hash_tolerates_non_utf8_source(self) -> None:
        source_root = self.scan_dir / "source"
        source_path = source_root / "src" / "extract.py"
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(b"\n" * 40 + b"invalid: \xff\n")
        sarif_finding = copy.deepcopy(self.finding)
        sarif_finding["findingId"] = "csf_example"
        sarif_finding["occurrenceId"] = "occ_example"
        sarif_finding["fingerprints"] = {"primary": "semantic-fingerprint"}
        result = FINALIZER._sarif_result(sarif_finding, 0, source_root)
        self.assertIn("primaryLocationLineHash", result["partialFingerprints"])

    def test_sarif_line_hash_skips_symlink_source(self) -> None:
        source_root = self.scan_dir / "source"
        source_path = source_root / "src" / "extract.py"
        source_path.parent.mkdir(parents=True)
        with tempfile.TemporaryDirectory() as external_dir:
            external_path = Path(external_dir) / "extract.py"
            external_path.write_text(
                "\n".join(f"line {index}" for index in range(1, 60)), encoding="utf-8"
            )
            source_path.symlink_to(external_path)
            sarif_finding = copy.deepcopy(self.finding)
            sarif_finding["findingId"] = "csf_example"
            sarif_finding["occurrenceId"] = "occ_example"
            sarif_finding["fingerprints"] = {"primary": "semantic-fingerprint"}
            result = FINALIZER._sarif_result(sarif_finding, 0, source_root)
        self.assertNotIn("primaryLocationLineHash", result["partialFingerprints"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
    def test_sarif_line_hash_skips_fifo_source_without_blocking(self) -> None:
        source_root = self.scan_dir / "source"
        source_root.mkdir()
        source_path = source_root / "named-pipe"
        os.mkfifo(source_path)
        results: list[object] = []

        thread = threading.Thread(
            target=lambda: results.append(FINALIZER._open_source_file(source_root, "named-pipe")),
            daemon=True,
        )
        thread.start()
        thread.join(1)
        blocked = thread.is_alive()
        if blocked:
            with source_path.open("w", encoding="utf-8"):
                pass
            thread.join(1)
        for handle in results:
            if handle is not None:
                handle.close()

        self.assertFalse(blocked)
        self.assertEqual(results, [None])

    def test_sarif_line_hash_skips_nul_source_path(self) -> None:
        source_root = self.scan_dir / "source"
        (source_root / "src").mkdir(parents=True)

        self.assertIsNone(FINALIZER._open_source_file(source_root, "src/bad\0.py"))

    def test_sarif_line_hash_uses_opened_source_file(self) -> None:
        source_root = self.scan_dir / "source"
        source_path = source_root / "src" / "extract.py"
        source_path.parent.mkdir(parents=True)
        source_path.write_text(
            "\n".join(f"inside {index}" for index in range(1, 60)), encoding="utf-8"
        )
        with tempfile.TemporaryDirectory() as external_dir:
            external_path = Path(external_dir) / "extract.py"
            external_path.write_text(
                "\n".join(f"outside {index}" for index in range(1, 60)), encoding="utf-8"
            )
            handle = FINALIZER._open_source_file(source_root, "src/extract.py")
            self.assertIsNotNone(handle)
            source_path.unlink()
            source_path.symlink_to(external_path)
            with handle:
                line_hashes = FINALIZER._github_line_hashes(handle)
            with external_path.open("r", encoding="utf-8") as external_handle:
                external_hashes = FINALIZER._github_line_hashes(external_handle)
        self.assertNotEqual(line_hashes[41], external_hashes[41])

    def test_sarif_line_hash_skips_source_read_error(self) -> None:
        source_root = self.scan_dir / "source"
        source_path = source_root / "src" / "extract.py"
        source_path.parent.mkdir(parents=True)
        source_path.write_text(
            "\n".join(f"line {index}" for index in range(1, 60)), encoding="utf-8"
        )
        sarif_finding = copy.deepcopy(self.finding)
        sarif_finding["findingId"] = "csf_example"
        sarif_finding["occurrenceId"] = "occ_example"
        sarif_finding["fingerprints"] = {"primary": "semantic-fingerprint"}
        with mock.patch.object(FINALIZER, "_github_line_hashes", side_effect=PermissionError):
            result = FINALIZER._sarif_result(sarif_finding, 0, source_root)
        self.assertNotIn("primaryLocationLineHash", result["partialFingerprints"])

    def test_sarif_line_hash_streams_source(self) -> None:
        source_path = self.scan_dir / "extract.py"
        source_path.write_text("line 1\nline 2\n", encoding="utf-8")
        with mock.patch.object(Path, "read_text", side_effect=AssertionError("not streamed")):
            with source_path.open("r", encoding="utf-8") as handle:
                line_hashes = FINALIZER._github_line_hashes(handle)
        self.assertEqual(line_hashes[1], "a4060029c94de37e:1")

    def test_sarif_line_hash_includes_lines_beyond_previous_limit(self) -> None:
        source = io.StringIO("line\n" * 100_001)

        self.assertIn(100_001, FINALIZER._github_line_hashes(source, {100_001}))

    def test_sarif_line_hashes_every_source_file(self) -> None:
        source_root = self.scan_dir / "source"
        source_dir = source_root / "src"
        source_dir.mkdir(parents=True)
        findings = []
        for index in range(2):
            relative_path = f"src/extract-{index}.py"
            (source_root / relative_path).write_text(" " * (6 * 1024 * 1024) + "x")
            finding = copy.deepcopy(self.finding)
            finding["findingId"] = f"csf_{index}"
            finding["occurrenceId"] = f"occ_{index}"
            finding["fingerprints"] = {"primary": f"fingerprint-{index}"}
            finding["locations"][0] = {"path": relative_path, "startLine": 1}
            findings.append(finding)

        sarif = FINALIZER.build_sarif(self.manifest, {"findings": findings}, source_root)

        results = sarif["runs"][0]["results"]
        for result in results:
            self.assertIn("primaryLocationLineHash", result["partialFingerprints"])

    def test_sarif_caches_line_hashes_per_source_file(self) -> None:
        source_root = self.scan_dir / "source"
        source_path = source_root / "src" / "extract.py"
        source_path.parent.mkdir(parents=True)
        source_path.write_text(
            "\n".join(f"line {index}" for index in range(1, 60)), encoding="utf-8"
        )
        findings = []
        for index in range(2):
            finding = copy.deepcopy(self.finding)
            finding["findingId"] = f"csf_{index}"
            finding["occurrenceId"] = f"occ_{index}"
            finding["fingerprints"] = {"primary": f"fingerprint-{index}"}
            finding["locations"][0]["startLine"] += index
            finding["locations"][0]["endLine"] += index
            findings.append(finding)

        with mock.patch.object(
            FINALIZER, "_github_line_hashes", wraps=FINALIZER._github_line_hashes
        ) as line_hashes:
            FINALIZER.build_sarif(self.manifest, {"findings": findings}, source_root)

        self.assertEqual(line_hashes.call_count, 1)


if __name__ == "__main__":
    unittest.main()
