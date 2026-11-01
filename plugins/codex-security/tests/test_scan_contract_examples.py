import hashlib
import json
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

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
    def assert_invalid(self, validator, document, message):
        with self.assertRaises(ValidationError) as caught:
            validator.validate(document)
        self.assertIn(message, caught.exception.message)

    def test_examples_match_schemas(self) -> None:
        for name in ("scan-manifest", "findings", "coverage"):
            with self.subTest(name=name):
                schema_validator(name).validate(example(name))

    def test_schemas_are_valid_draft_2020_12(self) -> None:
        for schema_path in sorted(SCHEMA_DIR.glob("*.schema.json")):
            with self.subTest(schema=schema_path.name):
                Draft202012Validator.check_schema(read_object(schema_path))

    def test_manifest_identifies_and_hashes_the_example_documents(self):
        scan = example("scan-manifest")["scan"]
        self.assertEqual(scan["findingsRef"], "findings.json")
        self.assertEqual(scan["coverageRef"], "coverage.json")
        self.assertEqual(
            {item["path"] for item in scan["artifacts"]}, {"findings.json", "coverage.json"}
        )
        for item in scan["artifacts"]:
            contents = (EXAMPLE_DIR / item["path"]).read_bytes()
            self.assertEqual(json.loads(contents)["scanId"], scan["id"])
            self.assertEqual(hashlib.sha256(contents).hexdigest(), item["sha256"])

    def test_deep_reducer_schema_accepts_standard_findings_without_coverage(self):
        reducer = schema_validator(
            "tools/deep-reducer", "definitions/artifact-common", "tools/scan-draft"
        )
        Draft202012Validator.check_schema(reducer.schema)
        standard = schema_validator("tools/scan-draft", "definitions/artifact-common")
        reduction_input = reducer.schema["$defs"]["reductionInput"]
        self.assertNotIn("reviewState", reduction_input["properties"])
        self.assertEqual(set(reduction_input["required"]), {"scanId", "findings"})
        self.assertIs(reduction_input["additionalProperties"], False)

        required_finding = {
            "ruleId": "cross-site-scripting.response",
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
        finding = {**required_finding, "identity": {"anchor": "response-output"}}
        request = {"scanId": "7fc17317-9594-49e0-b06a-d72fd7e14bba", "findings": [finding]}
        coverage = {
            "surfaces": [{"label": "HTTP responses", "disposition": "reported"}],
            "explicitExclusions": [{"pattern": "docs/", "reason": "Documentation only."}],
        }
        draft = {**request, "reviewState": {**coverage, "deferred": []}}
        standard.validate(draft)
        reducer.validate(request)
        reducer.validate({**request, "findings": []})
        reducer.validate(
            {
                **request,
                "complete": True,
                "handoffClaimToken": "2ea75b4f-f9b2-49b4-a5a9-2a8de8ca9047",
                "scope": {"summary": "HTTP responses"},
                "threatModel": {"summary": "Untrusted requests reach responses."},
            }
        )
        self.assertFalse(standard.is_valid(request))
        for field in ("surfaces", "explicitExclusions", "deferred"):
            with self.subTest(standard_missing_coverage_field=field):
                partial = draft["reviewState"].copy()
                del partial[field]
                self.assertFalse(standard.is_valid({**request, "reviewState": partial}), field)
        self.assertFalse(reducer.is_valid({**request, "reviewState": coverage}))
        for field in (
            "source_worker_id",
            "unknown_field",
            "resultPath",
            "consumedWorkerIds",
            "schemaVersion",
        ):
            with self.subTest(extra_field=field):
                self.assertFalse(reducer.is_valid({**request, field: "not allowed"}), field)
        for field in required_finding:
            with self.subTest(missing_field=field):
                partial = finding.copy()
                del partial[field]
                for validator, payload in ((reducer, request), (standard, draft)):
                    self.assertFalse(validator.is_valid({**payload, "findings": [partial]}), field)
        for field in ("scanId", "findings"):
            with self.subTest(missing_field=field):
                partial = request.copy()
                del partial[field]
                self.assertFalse(reducer.is_valid(partial), field)
        self.assertFalse(reducer.is_valid({"candidates": [], "merges": []}))

    def test_manifest_requires_snapshot_signal_for_target_kind(self):
        validator = schema_validator("scan-manifest")
        manifest = example("scan-manifest")
        scan = manifest["scan"]
        original = scan["target"]
        for kind, field in (
            ("git_revision", "revision"),
            ("git_worktree", "snapshotDigest"),
            ("git_diff", "snapshotDigest"),
            ("directory_snapshot", "snapshotDigest"),
        ):
            with self.subTest(kind=kind):
                scan["target"] = {**original, "kind": kind}
                del scan["target"][field]
                self.assert_invalid(validator, manifest, field)

    def test_manifest_rejects_unversioned_snapshot_digest(self):
        manifest = example("scan-manifest")
        manifest["scan"]["target"]["snapshotDigest"] = "sha256:worktree-example"
        self.assert_invalid(schema_validator("scan-manifest"), manifest, "does not match")

    def test_manifest_rejects_credential_bearing_remote(self):
        manifest = example("scan-manifest")
        for remote in (
            "https://token@example.com/repo",
            "https://example.com/repo?token=secret",
            "https://example.com/repo#token",
        ):
            with self.subTest(remote=remote):
                manifest["scan"]["target"]["remote"] = remote
                self.assert_invalid(schema_validator("scan-manifest"), manifest, "does not match")

    def test_manifest_rejects_invalid_timestamp(self):
        manifest = example("scan-manifest")
        manifest["scan"]["startedAt"] = "2026-99-99T00:00:00Z"
        self.assert_invalid(schema_validator("scan-manifest"), manifest, "is not a 'date-time'")

    def test_manifest_accepts_only_fixed_hardening_portfolio_path(self):
        validator = schema_validator("scan-manifest")
        manifest = example("scan-manifest")
        scan = manifest["scan"]
        scan["hardening"] = {"portfolioPath": "hardening/hardening.md"}
        validator.validate(manifest)
        scan["hardening"]["portfolioPath"] = "../hardening.md"
        self.assert_invalid(validator, manifest, "was expected")

    def test_manifest_rejects_unsafe_artifact_path(self):
        validator = schema_validator("scan-manifest")
        manifest = example("scan-manifest")
        scan = manifest["scan"]

        artifacts = scan["artifacts"]
        for path in ("../../secret.json", "/tmp/secret.json", "exports\\results.sarif"):
            with self.subTest(path=path):
                scan["artifacts"] = [*artifacts, {**artifacts[0], "path": path}]
                self.assert_invalid(validator, manifest, "does not match")

    def test_manifest_requires_one_record_for_each_canonical_document(self):
        validator = schema_validator("scan-manifest")
        manifest = example("scan-manifest")
        scan = manifest["scan"]
        artifacts = scan["artifacts"]
        for path in ("findings.json", "coverage.json"):
            with self.subTest(path=path):
                scan["artifacts"] = [item for item in artifacts if item["path"] != path]
                self.assert_invalid(validator, manifest, "does not contain items matching")
                scan["artifacts"] = [*artifacts, {**artifacts[0], "path": path}]
                self.assert_invalid(validator, manifest, "Too many items match")

    def test_findings_accept_safe_writeup_and_reject_unsafe_path(self):
        saved = schema_validator("findings")
        document = example("findings")
        finding = document["findings"][0]
        finding["writeup"] = {"reportPath": "findings/unsafe-archive/unsafe-archive.md"}
        saved.validate(document)
        finding["writeup"]["reportPath"] = "../outside.md"
        self.assert_invalid(saved, document, "does not match")

    def test_findings_accept_code_evidence_call_stack_role(self):
        saved = schema_validator("findings")
        standard = schema_validator("tools/scan-draft", "definitions/artifact-common")
        document = example("findings")
        finding = document["findings"][0]

        evidence = {
            "id": "request-input",
            "label": "Request field",
            "path": "src/handler.py",
            "startLine": 12,
            "role": "user_input",
            "code": "value = request.json['value']",
            "explanation": "Request input.",
        }
        draft_finding = {
            k: v
            for k, v in finding.items()
            if k not in {"findingId", "occurrenceId", "fingerprints"}
        }
        draft = {
            "scanId": "7fc17317-9594-49e0-b06a-d72fd7e14bba",
            "findings": [draft_finding],
            "reviewState": {"surfaces": [], "explicitExclusions": [], "deferred": []},
        }
        cases = ((saved, document, finding), (standard, draft, draft_finding))
        for validator, payload, entry in cases:
            entry["codeEvidence"] = [evidence]
            validator.validate(payload)
        for missing in ("code", "explanation"):
            with self.subTest(missing=missing):
                partial = evidence.copy()
                value = partial.pop(missing)
                if missing == "code":
                    partial["snippet"] = value
                for validator, payload, entry in cases:
                    entry["codeEvidence"] = [partial]
                    self.assert_invalid(validator, payload, f"'{missing}' is a required property")
        finding["codeEvidence"] = [{**evidence, "role": ""}]
        self.assert_invalid(saved, document, "should be non-empty")

    def test_coverage_accepts_unresolved_work(self):
        coverage = example("coverage")
        surface = coverage["surfaces"][0]
        surface["disposition"] = "needs_follow_up"
        coverage["deferred"] = [{"id": "deferred_archive_review", "reason": "Runtime unavailable."}]
        schema_validator("coverage").validate(coverage)

    def test_coverage_rejects_receipt_ref_outside_artifacts(self):
        coverage = example("coverage")
        surface = coverage["surfaces"][0]
        for ref in ("report.md", "artifacts/../report.md", "artifacts\\receipt.jsonl"):
            with self.subTest(ref=ref):
                surface["receiptRefs"] = [ref]
                self.assert_invalid(schema_validator("coverage"), coverage, "does not match")


if __name__ == "__main__":
    unittest.main()
