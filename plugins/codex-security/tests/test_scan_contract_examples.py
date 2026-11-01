from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource
from workbench_test_support import saved_coverage

PLUGIN_DIR = Path(__file__).resolve().parent.parent
EXAMPLE_DIR = PLUGIN_DIR / "examples" / "legacy-completed-scan"
SCHEMA_DIR = PLUGIN_DIR / "schemas"


def read_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"{path}: expected an object")
    return payload


def example(name: str) -> dict[str, Any]:
    return read_object(EXAMPLE_DIR / f"{name}.json")


def schema_validator(name: str, *references: str) -> Draft202012Validator:
    def load(name: str) -> dict[str, Any]:
        return read_object(SCHEMA_DIR / f"{name}.schema.json")

    resources = [load(ref) for ref in references]
    registry = Registry().with_resources(
        (resource["$id"], Resource.from_contents(resource)) for resource in resources
    )
    return Draft202012Validator(load(name), registry=registry, format_checker=FormatChecker())


class ScanContractExamplesTest(unittest.TestCase):
    def assert_invalid(self, schema: str, payload: dict[str, Any], message: str) -> None:
        with self.assertRaises(ValidationError) as caught:
            schema_validator(schema).validate(payload)
        self.assertRegex(caught.exception.message, message)

    def test_examples_match_schemas(self) -> None:
        for name in ("scan-manifest", "findings", "coverage"):
            with self.subTest(name=name):
                schema_validator(name).validate(example(name))

    def test_schemas_are_valid_draft_2020_12(self) -> None:
        for schema_path in sorted(SCHEMA_DIR.glob("*.schema.json")):
            with self.subTest(schema=schema_path.name):
                Draft202012Validator.check_schema(read_object(schema_path))

    def test_deep_reducer_schema_accepts_standard_findings_without_coverage(self) -> None:
        validator = schema_validator(
            "tools/deep-reducer", "definitions/artifact-common", "tools/scan-draft"
        )
        reduction_input = validator.schema["$defs"]["reductionInput"]
        self.assertNotIn("reviewState", reduction_input["properties"])
        self.assertEqual(set(reduction_input["required"]), {"scanId", "findings"})
        self.assertFalse(reduction_input["additionalProperties"])
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

        Draft202012Validator.check_schema(validator.schema)
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
        self.assertFalse(validator.is_valid({**request, "reviewState": coverage}))

        standard_validator = schema_validator("tools/scan-draft", "definitions/artifact-common")
        standard_request = {
            **request,
            "reviewState": {**coverage, "deferred": []},
        }
        standard_validator.validate(standard_request)
        self.assertFalse(standard_validator.is_valid(request))
        self.assertFalse(standard_validator.is_valid({**request, "reviewState": coverage}))
        for missing_field in ("surfaces", "explicitExclusions", "deferred"):
            with self.subTest(standard_missing_coverage_field=missing_field):
                partial = dict(standard_request["reviewState"])
                del partial[missing_field]
                self.assertFalse(
                    standard_validator.is_valid({**standard_request, "reviewState": partial})
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

    def test_manifest_identifies_and_hashes_the_example_documents(self) -> None:
        scan = example("scan-manifest")["scan"]
        self.assertEqual(scan["id"], example("findings")["scanId"])
        self.assertEqual(scan["id"], example("coverage")["scanId"])
        self.assertEqual(scan["findingsRef"], "findings.json")
        self.assertEqual(scan["coverageRef"], "coverage.json")
        self.assertEqual(
            {item["path"] for item in scan["artifacts"]}, {"coverage.json", "findings.json"}
        )
        for artifact in scan["artifacts"]:
            path = EXAMPLE_DIR / artifact["path"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), artifact["sha256"])

    def test_manifest_requires_snapshot_signal_for_target_kind(self) -> None:
        for kind, missing_field in (
            ("git_revision", "revision"),
            ("git_worktree", "snapshotDigest"),
            ("git_diff", "snapshotDigest"),
            ("directory_snapshot", "snapshotDigest"),
        ):
            with self.subTest(kind=kind):
                manifest = example("scan-manifest")
                target = manifest["scan"]["target"]
                target["kind"] = kind
                target.pop(missing_field, None)
                self.assert_invalid("scan-manifest", manifest, missing_field)

    def test_manifest_rejects_unversioned_snapshot_digest(self) -> None:
        manifest = example("scan-manifest")
        manifest["scan"]["target"]["snapshotDigest"] = "sha256:worktree-example"
        self.assert_invalid("scan-manifest", manifest, "does not match")

    def test_manifest_rejects_invalid_timestamp(self) -> None:
        manifest = example("scan-manifest")
        manifest["scan"]["startedAt"] = "2026-99-99T00:00:00Z"
        self.assert_invalid("scan-manifest", manifest, "is not a 'date-time'")

    def test_manifest_rejects_credential_bearing_remote(self) -> None:
        for remote in (
            "https://token@example.com/repo",
            "https://example.com/repo?token=secret",
            "https://example.com/repo#token",
        ):
            with self.subTest(remote=remote):
                manifest = example("scan-manifest")
                manifest["scan"]["target"]["remote"] = remote
                self.assert_invalid("scan-manifest", manifest, "does not match")

    def test_manifest_rejects_unsafe_artifact_path(self) -> None:
        for path in ("../../secret.json", "/tmp/secret.json", "exports\\results.sarif"):
            with self.subTest(path=path):
                manifest = example("scan-manifest")
                manifest["scan"]["artifacts"].append(
                    {
                        "path": path,
                        "sha256": "0" * 64,
                        "mediaType": "application/json",
                    }
                )
                self.assert_invalid("scan-manifest", manifest, "does not match")

    def test_manifest_requires_one_record_for_each_canonical_document(self) -> None:
        for path in ("findings.json", "coverage.json"):
            with self.subTest(path=path):
                manifest = example("scan-manifest")
                artifacts = manifest["scan"]["artifacts"]
                manifest["scan"]["artifacts"] = [
                    artifact for artifact in artifacts if artifact["path"] != path
                ]
                self.assert_invalid("scan-manifest", manifest, "does not contain items matching")

                manifest["scan"]["artifacts"] = artifacts + [copy.deepcopy(artifacts[0])]
                manifest["scan"]["artifacts"][-1]["path"] = path
                self.assert_invalid("scan-manifest", manifest, "Too many items match")

    def test_manifest_accepts_only_fixed_hardening_portfolio_path(self) -> None:
        manifest = example("scan-manifest")
        manifest["scan"]["hardening"] = {"portfolioPath": "hardening/hardening.md"}
        schema_validator("scan-manifest").validate(manifest)

        manifest["scan"]["hardening"]["portfolioPath"] = "../hardening.md"
        self.assert_invalid("scan-manifest", manifest, "was expected")

    def test_findings_accept_safe_writeup_and_reject_unsafe_path(self) -> None:
        findings = example("findings")
        findings["findings"][0]["writeup"] = {
            "reportPath": "findings/unsafe-archive/unsafe-archive.md"
        }
        schema_validator("findings").validate(findings)

        findings["findings"][0]["writeup"]["reportPath"] = "../outside.md"
        self.assert_invalid("findings", findings, "does not match")

    def test_findings_accept_code_evidence_call_stack_role(self) -> None:
        draft_validator = schema_validator("tools/scan-draft", "definitions/artifact-common")
        findings = example("findings")
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
        schema_validator("findings").validate(findings)
        draft_finding = {
            key: value
            for key, value in findings["findings"][0].items()
            if key not in {"findingId", "occurrenceId", "fingerprints"}
        }
        draft = {
            "scanId": "7fc17317-9594-49e0-b06a-d72fd7e14bba",
            "findings": [draft_finding],
            "reviewState": saved_coverage(),
        }
        draft_validator.validate(draft)

        for field, replacement in (("code", "snippet"), ("explanation", None)):
            with self.subTest(missing=field):
                invalid_findings = copy.deepcopy(findings)
                evidence = invalid_findings["findings"][0]["codeEvidence"][0]
                value = evidence.pop(field)
                if replacement is not None:
                    evidence[replacement] = value
                self.assert_invalid(
                    "findings", invalid_findings, f"'{field}' is a required property"
                )

                invalid_draft = copy.deepcopy(draft)
                invalid_draft["findings"][0]["codeEvidence"][0] = evidence
                self.assertFalse(draft_validator.is_valid(invalid_draft))

        findings["findings"][0]["codeEvidence"][0]["role"] = ""
        self.assert_invalid("findings", findings, "should be non-empty")

    def test_coverage_rejects_receipt_ref_outside_artifacts(self) -> None:
        for ref in ("report.md", "artifacts/../report.md", "artifacts\\receipt.jsonl"):
            with self.subTest(ref=ref):
                coverage = example("coverage")
                coverage["surfaces"][0]["receiptRefs"] = [ref]
                self.assert_invalid("coverage", coverage, "does not match")

    def test_coverage_accepts_unresolved_work(self) -> None:
        coverage = example("coverage")
        coverage["surfaces"][0]["disposition"] = "needs_follow_up"
        coverage["deferred"] = [
            {
                "id": "deferred_archive_review",
                "reason": "Runtime verification remains unavailable.",
            }
        ]
        schema_validator("coverage").validate(coverage)


if __name__ == "__main__":
    unittest.main()
