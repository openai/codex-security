from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

PLUGIN_DIR = Path(__file__).resolve().parent.parent
EXAMPLE_DIR = PLUGIN_DIR / "examples" / "completed-scan"
SCHEMA_DIR = PLUGIN_DIR / "schemas"


def read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"{path}: expected an object")
    return payload


def validate_schema_node(value: Any, schema: dict[str, Any], context: str) -> None:
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(value), key=lambda error: list(error.absolute_path))
    if not errors:
        return
    error = errors[0]
    path = ".".join(str(part) for part in error.absolute_path)
    location = f"{context}.{path}" if path else context
    raise AssertionError(f"{location}: {error.message}") from error


class ScanContractExamplesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = read_json(EXAMPLE_DIR / "scan-manifest.json")
        self.findings = read_json(EXAMPLE_DIR / "findings.json")
        self.coverage = read_json(EXAMPLE_DIR / "coverage.json")

    def test_examples_match_schemas(self) -> None:
        for name, payload in (
            ("scan-manifest", self.manifest),
            ("findings", self.findings),
            ("coverage", self.coverage),
        ):
            schema = read_json(SCHEMA_DIR / f"{name}.schema.json")
            validate_schema_node(payload, schema, name)

    def test_schemas_are_valid_draft_2020_12(self) -> None:
        for schema_path in sorted(SCHEMA_DIR.glob("*.schema.json")):
            with self.subTest(schema=schema_path.name):
                Draft202012Validator.check_schema(read_json(schema_path))

    def test_deep_reducer_schema_accepts_standard_findings_without_coverage(self) -> None:
        common_schema = read_json(SCHEMA_DIR / "definitions" / "artifact-common.schema.json")
        scan_draft_schema = read_json(SCHEMA_DIR / "tools" / "scan-draft.schema.json")
        reducer_schema = read_json(SCHEMA_DIR / "tools" / "deep-reducer.schema.json")
        reduction_input = reducer_schema["$defs"]["reductionInput"]
        self.assertNotIn("coverage", reduction_input["properties"])
        self.assertEqual(set(reduction_input["required"]), {"scanId", "findings"})
        self.assertFalse(reduction_input["additionalProperties"])
        registry = Registry().with_resources(
            (schema["$id"], Resource.from_contents(schema))
            for schema in (common_schema, scan_draft_schema)
        )
        finding = {
            "ruleId": "cross-site-scripting.response",
            "identity": {"anchor": "response-output"},
            "title": "Unescaped response output",
            "summary": "Request input reaches a response.",
            "severity": {"level": "high"},
            "confidence": {
                "level": "high",
                "rationale": "Source evidence establishes reachability.",
            },
            "taxonomy": {"category": "cross-site-scripting", "cwe": ["CWE-79"]},
            "locations": [{"path": "src/app.py", "startLine": 1}],
            "remediation": "Escape the response.",
            "provenance": {"source": "local_plugin"},
        }
        coverage = {
            "surfaces": [{"label": "HTTP responses", "disposition": "reported"}],
            "explicitExclusions": [{"pattern": "docs/", "reason": "Documentation only."}],
        }

        Draft202012Validator.check_schema(reducer_schema)
        validator = Draft202012Validator(
            reducer_schema,
            registry=registry,
            format_checker=FormatChecker(),
        )
        request = {
            "scanId": "7fc17317-9594-49e0-b06a-d72fd7e14bba",
            "findings": [finding],
        }

        validator.validate(request)
        validator.validate(
            {
                **request,
                "complete": True,
                "handoffClaimToken": "2ea75b4f-f9b2-49b4-a5a9-2a8de8ca9047",
                "scope": {"summary": "HTTP responses"},
                "threatModel": {"summary": "Untrusted requests reach responses."},
            }
        )
        validator.validate({**request, "findings": []})
        self.assertFalse(validator.is_valid({**request, "coverage": coverage}))

        standard_validator = Draft202012Validator(
            scan_draft_schema, registry=registry, format_checker=FormatChecker()
        )
        standard_request = {
            **request,
            "coverage": {**coverage, "completeness": "complete", "deferred": []},
        }
        standard_validator.validate(standard_request)
        self.assertFalse(standard_validator.is_valid(request))
        self.assertFalse(standard_validator.is_valid({**request, "coverage": coverage}))
        for completeness in ("complete", "partial", "unknown"):
            with self.subTest(standard_completeness=completeness):
                standard_coverage_request = {
                    **standard_request,
                    "coverage": {
                        **standard_request["coverage"],
                        "completeness": completeness,
                    },
                }
                standard_validator.validate(standard_coverage_request)
                self.assertFalse(validator.is_valid(standard_coverage_request))
        self.assertFalse(
            standard_validator.is_valid(
                {
                    **standard_request,
                    "coverage": {**standard_request["coverage"], "completeness": "invalid"},
                }
            )
        )
        for missing_field in ("completeness", "surfaces", "explicitExclusions", "deferred"):
            with self.subTest(standard_missing_coverage_field=missing_field):
                self.assertFalse(
                    standard_validator.is_valid(
                        {
                            **standard_request,
                            "coverage": {
                                field: value
                                for field, value in standard_request["coverage"].items()
                                if field != missing_field
                            },
                        }
                    )
                )
        for extra_field in (
            "source_worker_id",
            "unknown_field",
            "resultPath",
            "consumedWorkerIds",
            "schemaVersion",
        ):
            with self.subTest(extra_field=extra_field):
                self.assertFalse(validator.is_valid({**request, extra_field: "not allowed"}))

        for missing_field in (
            "ruleId",
            "title",
            "summary",
            "severity",
            "confidence",
            "taxonomy",
            "locations",
            "remediation",
            "provenance",
        ):
            with self.subTest(missing_field=missing_field):
                incomplete_finding = {
                    field: value for field, value in finding.items() if field != missing_field
                }
                self.assertFalse(validator.is_valid({**request, "findings": [incomplete_finding]}))
                self.assertFalse(
                    standard_validator.is_valid(
                        {**standard_request, "findings": [incomplete_finding]}
                    )
                )

        for missing_field in ("scanId", "findings"):
            with self.subTest(missing_field=missing_field):
                self.assertFalse(
                    validator.is_valid(
                        {field: value for field, value in request.items() if field != missing_field}
                    )
                )
        self.assertFalse(validator.is_valid({"candidates": [], "merges": []}))

    def test_documents_refer_to_one_scan(self) -> None:
        scan = self.manifest["scan"]
        self.assertEqual(scan["id"], self.findings["scanId"])
        self.assertEqual(scan["id"], self.coverage["scanId"])
        self.assertEqual(scan["findingsRef"], "findings.json")
        self.assertEqual(scan["coverageRef"], "coverage.json")

    def test_manifest_lists_canonical_documents(self) -> None:
        paths = {artifact["path"] for artifact in self.manifest["scan"]["artifacts"]}
        self.assertEqual(
            paths,
            {
                "coverage.json",
                "findings.json",
            },
        )

    def test_manifest_artifacts_exist_with_recorded_hashes(self) -> None:
        for artifact in self.manifest["scan"]["artifacts"]:
            path = EXAMPLE_DIR / artifact["path"]
            self.assertTrue(path.is_file(), artifact["path"])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), artifact["sha256"])

    def test_manifest_requires_snapshot_signal_for_target_kind(self) -> None:
        schema = read_json(SCHEMA_DIR / "scan-manifest.schema.json")
        for kind, missing_field in (
            ("git_revision", "revision"),
            ("git_worktree", "snapshotDigest"),
            ("git_diff", "snapshotDigest"),
            ("directory_snapshot", "snapshotDigest"),
        ):
            with self.subTest(kind=kind):
                manifest = copy.deepcopy(self.manifest)
                target = manifest["scan"]["target"]
                target["kind"] = kind
                target.pop(missing_field, None)
                with self.assertRaisesRegex(AssertionError, missing_field):
                    validate_schema_node(manifest, schema, "scan-manifest")

    def test_manifest_rejects_unversioned_snapshot_digest(self) -> None:
        schema = read_json(SCHEMA_DIR / "scan-manifest.schema.json")
        manifest = copy.deepcopy(self.manifest)
        manifest["scan"]["target"]["snapshotDigest"] = "sha256:worktree-example"
        with self.assertRaisesRegex(AssertionError, "does not match"):
            validate_schema_node(manifest, schema, "scan-manifest")

    def test_manifest_rejects_invalid_timestamp(self) -> None:
        schema = read_json(SCHEMA_DIR / "scan-manifest.schema.json")
        manifest = copy.deepcopy(self.manifest)
        manifest["scan"]["startedAt"] = "2026-99-99T00:00:00Z"
        with self.assertRaisesRegex(AssertionError, "is not a 'date-time'"):
            validate_schema_node(manifest, schema, "scan-manifest")

    def test_manifest_rejects_credential_bearing_remote(self) -> None:
        schema = read_json(SCHEMA_DIR / "scan-manifest.schema.json")
        for remote in (
            "https://token@example.com/repo",
            "https://example.com/repo?token=secret",
            "https://example.com/repo#token",
        ):
            with self.subTest(remote=remote):
                manifest = copy.deepcopy(self.manifest)
                manifest["scan"]["target"]["remote"] = remote
                with self.assertRaisesRegex(AssertionError, "does not match"):
                    validate_schema_node(manifest, schema, "scan-manifest")

    def test_manifest_rejects_unsafe_artifact_path(self) -> None:
        schema = read_json(SCHEMA_DIR / "scan-manifest.schema.json")
        for path in ("../../secret.json", "/tmp/secret.json", "exports\\results.sarif"):
            with self.subTest(path=path):
                manifest = copy.deepcopy(self.manifest)
                manifest["scan"]["artifacts"].append(
                    {
                        "path": path,
                        "sha256": "0" * 64,
                        "mediaType": "application/json",
                    }
                )
                with self.assertRaisesRegex(AssertionError, "does not match"):
                    validate_schema_node(manifest, schema, "scan-manifest")

    def test_manifest_requires_one_record_for_each_canonical_document(self) -> None:
        schema = read_json(SCHEMA_DIR / "scan-manifest.schema.json")
        for path in ("findings.json", "coverage.json"):
            with self.subTest(path=path):
                manifest = copy.deepcopy(self.manifest)
                artifacts = manifest["scan"]["artifacts"]
                manifest["scan"]["artifacts"] = [
                    artifact for artifact in artifacts if artifact["path"] != path
                ]
                with self.assertRaisesRegex(AssertionError, "does not contain items matching"):
                    validate_schema_node(manifest, schema, "scan-manifest")

                manifest["scan"]["artifacts"] = artifacts + [copy.deepcopy(artifacts[0])]
                manifest["scan"]["artifacts"][-1]["path"] = path
                with self.assertRaisesRegex(AssertionError, "Too many items match"):
                    validate_schema_node(manifest, schema, "scan-manifest")

    def test_manifest_accepts_only_fixed_hardening_portfolio_path(self) -> None:
        schema = read_json(SCHEMA_DIR / "scan-manifest.schema.json")
        manifest = copy.deepcopy(self.manifest)
        manifest["scan"]["hardening"] = {"portfolioPath": "hardening/hardening.md"}
        validate_schema_node(manifest, schema, "scan-manifest")

        manifest["scan"]["hardening"]["portfolioPath"] = "../hardening.md"
        with self.assertRaisesRegex(AssertionError, "was expected"):
            validate_schema_node(manifest, schema, "scan-manifest")

    def test_coverage_rejects_unknown_completeness(self) -> None:
        schema = read_json(SCHEMA_DIR / "coverage.schema.json")
        coverage = copy.deepcopy(self.coverage)
        coverage["completeness"] = "probably-complete"
        with self.assertRaisesRegex(AssertionError, "is not one of"):
            validate_schema_node(coverage, schema, "coverage")

    def test_findings_accept_safe_writeup_and_reject_unsafe_path(self) -> None:
        schema = read_json(SCHEMA_DIR / "findings.schema.json")
        findings = copy.deepcopy(self.findings)
        findings["findings"][0]["writeup"] = {
            "reportPath": "findings/unsafe-archive/unsafe-archive.md"
        }
        validate_schema_node(findings, schema, "findings")

        findings["findings"][0]["writeup"]["reportPath"] = "../outside.md"
        with self.assertRaisesRegex(AssertionError, "does not match"):
            validate_schema_node(findings, schema, "findings")

    def test_findings_accept_code_evidence_call_stack_role(self) -> None:
        schema = read_json(SCHEMA_DIR / "findings.schema.json")
        common_schema = read_json(SCHEMA_DIR / "definitions" / "artifact-common.schema.json")
        draft_schema = read_json(SCHEMA_DIR / "tools" / "scan-draft.schema.json")
        registry = Registry().with_resource(
            common_schema["$id"], Resource.from_contents(common_schema)
        )
        draft_validator = Draft202012Validator(
            draft_schema, registry=registry, format_checker=FormatChecker()
        )
        findings = copy.deepcopy(self.findings)
        findings["findings"][0]["codeEvidence"] = [
            {
                "id": "request-input",
                "label": "Request field enters the handler",
                "path": "src/handler.py",
                "startLine": 12,
                "role": "user_input",
                "code": "value = request.json['value']",
                "explanation": "The request controls value before the handler forwards it.",
            }
        ]
        validate_schema_node(findings, schema, "findings")
        draft_finding = {
            key: value
            for key, value in findings["findings"][0].items()
            if key not in {"findingId", "occurrenceId", "fingerprints"}
        }
        draft = {
            "scanId": "7fc17317-9594-49e0-b06a-d72fd7e14bba",
            "findings": [draft_finding],
            "coverage": {
                "completeness": "complete",
                "surfaces": [],
                "explicitExclusions": [],
                "deferred": [],
            },
        }
        draft_validator.validate(draft)

        for field, replacement in (("code", "snippet"), ("explanation", None)):
            with self.subTest(missing=field):
                invalid_findings = copy.deepcopy(findings)
                evidence = invalid_findings["findings"][0]["codeEvidence"][0]
                value = evidence.pop(field)
                if replacement is not None:
                    evidence[replacement] = value
                with self.assertRaisesRegex(AssertionError, f"'{field}' is a required property"):
                    validate_schema_node(invalid_findings, schema, "findings")

                invalid_draft = copy.deepcopy(draft)
                invalid_draft["findings"][0]["codeEvidence"][0] = evidence
                self.assertFalse(draft_validator.is_valid(invalid_draft))

        findings["findings"][0]["codeEvidence"][0]["role"] = ""
        with self.assertRaisesRegex(AssertionError, "should be non-empty"):
            validate_schema_node(findings, schema, "findings")

    def test_coverage_rejects_receipt_ref_outside_artifacts(self) -> None:
        schema = read_json(SCHEMA_DIR / "coverage.schema.json")
        for ref in ("report.md", "artifacts/../report.md", "artifacts\\receipt.jsonl"):
            with self.subTest(ref=ref):
                coverage = copy.deepcopy(self.coverage)
                coverage["surfaces"][0]["receiptRefs"] = [ref]
                with self.assertRaisesRegex(AssertionError, "does not match"):
                    validate_schema_node(coverage, schema, "coverage")

    def test_coverage_rejects_complete_with_needs_follow_up_surface(self) -> None:
        schema = read_json(SCHEMA_DIR / "coverage.schema.json")
        coverage = copy.deepcopy(self.coverage)
        coverage["surfaces"][0]["disposition"] = "needs_follow_up"
        with self.assertRaisesRegex(AssertionError, "Too many items match"):
            validate_schema_node(coverage, schema, "coverage")

    def test_coverage_rejects_complete_with_deferred_work(self) -> None:
        schema = read_json(SCHEMA_DIR / "coverage.schema.json")
        coverage = copy.deepcopy(self.coverage)
        coverage["deferred"] = [
            {
                "id": "deferred_archive_review",
                "reason": "Archive extraction review was not completed.",
            }
        ]
        with self.assertRaisesRegex(AssertionError, "Too many items match"):
            validate_schema_node(coverage, schema, "coverage")

    def test_coverage_allows_partial_with_deferred_work(self) -> None:
        schema = read_json(SCHEMA_DIR / "coverage.schema.json")
        coverage = copy.deepcopy(self.coverage)
        coverage["completeness"] = "partial"
        coverage["surfaces"][0]["disposition"] = "needs_follow_up"
        coverage["deferred"] = [
            {
                "id": "deferred_archive_review",
                "reason": "Archive extraction review was not completed.",
            }
        ]
        validate_schema_node(coverage, schema, "coverage")


if __name__ == "__main__":
    unittest.main()
