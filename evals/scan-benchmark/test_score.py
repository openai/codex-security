import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import ValidationError

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("benchmark_score", HERE / "score.py")
scorer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scorer)


def finding(expected, number=1):
    region = expected["findings"][0]["regions"][0]
    return {
        "findingId": f"csf_{number:024x}",
        "occurrenceId": f"occ_{number:024x}",
        "ruleId": "synthetic.test",
        "identity": {"anchor": "synthetic.test"},
        "fingerprints": {
            "algorithm": "codex-security/v1",
            "primary": "codex-security/v1:sha256:" + "0" * 64,
        },
        "title": "Arbitrary model wording",
        "summary": "Another wording",
        "severity": {"level": "high"},
        "confidence": {"level": "high", "rationale": "Synthetic test"},
        "taxonomy": {
            "category": "Arbitrary category wording",
            "cwe": expected["findings"][0]["cwe"],
        },
        "locations": [dict(region)],
        "codeEvidence": [
            {
                **region,
                "id": "sink",
                "label": "Sink",
                "code": "synthetic",
                "explanation": "Synthetic test",
            }
        ],
        "remediation": "Use the safe control",
        "provenance": {"source": "synthetic-test"},
    }


def coverage():
    return {
        "documentType": "codex-security.coverage",
        "schemaVersion": "1.0",
        "scanId": "synthetic",
        "mode": "deep_repository",
        "completeness": "complete",
        "inventoryStrategy": "repository",
        "includePaths": [],
        "excludePaths": [],
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
    }


def document(findings):
    return {
        "documentType": "codex-security.findings",
        "schemaVersion": "1.0",
        "scanId": "synthetic",
        "findings": findings,
    }


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.expected = scorer.read(HERE / "cases/path_traversal/expected.json")
        self.finding = finding(self.expected)

    def score(self, findings, **kwargs):
        return scorer.score(self.expected, findings, coverage(), **kwargs)

    def test_semantics_ignore_narrative_and_normalize_relative_paths(self):
        self.finding["locations"][0]["path"] = "./service.py"
        self.assertTrue(self.score([self.finding])["passed"])

    def test_missing_is_not_a_successful_empty_scan(self):
        self.assertEqual(self.score([])["missing"], ["unsafe"])
        self.assertFalse(self.score([])["passed"])

    def test_wrong_cwe_severity_and_evidence_do_not_receive_credit(self):
        for field in ("cwe", "severity", "evidence"):
            with self.subTest(field=field):
                bad = copy.deepcopy(self.finding)
                if field == "cwe":
                    bad["taxonomy"]["cwe"] = ["CWE-89"]
                elif field == "severity":
                    bad["severity"]["level"] = "low"
                else:
                    bad["codeEvidence"] = []
                result = self.score([bad])
                self.assertEqual(result["recall"], 0)
                self.assertEqual(len(result["unexpected"]), 1)

    def test_false_positive_on_safe_control_even_with_wrong_severity(self):
        bad = copy.deepcopy(self.finding)
        bad["locations"] = self.expected["findings"][1]["regions"]
        bad["severity"]["level"] = "low"
        result = self.score([self.finding, bad])
        self.assertEqual(len(result["absentViolations"]), 1)
        self.assertFalse(result["passed"])

    def test_duplicates_and_explicit_allowance(self):
        result = self.score([self.finding, finding(self.expected, 2)])
        self.assertEqual(result["duplicateRate"], 0.5)
        self.assertFalse(result["passed"])
        self.expected["findings"][0]["allowedDuplicates"] = 1
        self.assertTrue(self.score([self.finding, finding(self.expected, 2)])["passed"])

    def test_maximum_matching_preserves_required_over_optional(self):
        optional = copy.deepcopy(self.expected["findings"][0])
        optional.update(id="optional", presence="optional")
        self.expected["findings"].append(optional)
        self.assertTrue(self.score([self.finding])["passed"])
        second = copy.deepcopy(optional)
        second.update(id="second", presence="required")
        self.expected["findings"].append(second)
        result = self.score([self.finding])
        self.assertEqual(result["matchedRequired"], 1)
        self.assertFalse(result["passed"])

    def test_augmenting_path_finds_non_greedy_assignment(self):
        broad = copy.deepcopy(self.expected["findings"][0])
        narrow = copy.deepcopy(broad)
        broad["regions"][0].update(startLine=4, endLine=5)
        broad["evidenceRegions"] = []
        narrow["evidenceRegions"] = []
        other = copy.deepcopy(self.finding)
        other["locations"][0].update(startLine=4, endLine=4)
        assigned = scorer.assignment([self.finding, other], [broad, narrow])
        self.assertEqual(set(assigned.values()), {0, 1})

    def test_partial_or_wrong_mode_fails(self):
        for field, value in (("completeness", "partial"), ("mode", "repository")):
            incomplete = coverage()
            incomplete[field] = value
            self.assertFalse(scorer.score(self.expected, [self.finding], incomplete)["passed"])

    def test_validation_survival_is_unknown_without_candidates(self):
        self.assertIsNone(self.score([self.finding])["validationSurvival"])
        result = self.score([], candidates=[self.finding])
        self.assertEqual(result["validationSurvival"]["rate"], 0)
        self.assertIsNone(self.score([], candidates=[])["validationSurvival"]["rate"])

    def test_corpus_regions_are_real_source_lines(self):
        for case in (HERE / "cases").iterdir():
            expected = scorer.read(case / "expected.json")
            scorer.validate(expected, scorer.read(HERE / "expected.schema.json"))
            for expectation in expected["findings"]:
                for region in expectation["regions"] + expectation.get("evidenceRegions", []):
                    lines = (case / "repo" / region["path"]).read_text().splitlines()
                    self.assertLessEqual(region["startLine"], region["endLine"])
                    self.assertLessEqual(region["endLine"], len(lines))

    def make_results(self, root):
        for case in (HERE / "cases").iterdir():
            expected = scorer.read(case / "expected.json")
            directory = root / case.name
            directory.mkdir()
            (directory / "findings.json").write_text(json.dumps(document([finding(expected)])))
            (directory / "coverage.json").write_text(json.dumps(coverage()))

    def test_runner_canonical_artifacts_and_baseline_regression(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_results(root)
            baseline = scorer.run(root)
            self.assertTrue(baseline["passed"])
            path = root / "path_traversal/findings.json"
            path.write_text(json.dumps(document([])))
            report = scorer.run(root, baseline)
            self.assertEqual(report["regressions"], ["path_traversal"])
            self.assertFalse(report["passed"])
            incompatible = copy.deepcopy(baseline)
            incompatible["corpusVersion"] = 2
            with self.assertRaises(ValueError):
                scorer.run(root, incompatible)

    def test_missing_malformed_or_cross_scan_artifacts_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(FileNotFoundError):
                scorer.run(root)
            self.make_results(root)
            path = root / "path_traversal/findings.json"
            path.write_text(json.dumps({"findings": []}))
            with self.assertRaises(ValidationError):
                scorer.run(root)
            value = document([])
            value["scanId"] = "other"
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                scorer.run(root)

    def test_scoring_does_not_mutate_artifacts(self):
        inputs = (self.expected, [self.finding], coverage())
        original = copy.deepcopy(inputs)
        scorer.score(*inputs)
        self.assertEqual(inputs, original)

    def test_baseline_duplicate_and_coverage_regressions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_results(root)
            baseline = scorer.run(root)
            directory = root / "path_traversal"
            (directory / "findings.json").write_text(
                json.dumps(document([finding(self.expected), finding(self.expected, 2)]))
            )
            self.assertEqual(scorer.run(root, baseline)["regressions"], ["path_traversal"])
            (directory / "findings.json").write_text(json.dumps(document([finding(self.expected)])))
            partial = coverage()
            partial["completeness"] = "partial"
            (directory / "coverage.json").write_text(json.dumps(partial))
            self.assertEqual(scorer.run(root, baseline)["regressions"], ["path_traversal"])
            baseline["corpusDigest"] = "changed"
            with self.assertRaises(ValueError):
                scorer.run(root, baseline)

    def test_candidate_binding_and_validation_survival_in_runner(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_results(root)
            directory = root / "path_traversal"
            candidate = document([finding(self.expected)])
            (directory / "candidates.json").write_text(json.dumps(candidate))
            (directory / "findings.json").write_text(json.dumps(document([])))
            report = scorer.run(root)
            case = next(case for case in report["cases"] if case["caseId"] == "path_traversal")
            self.assertEqual(case["validationSurvival"]["rate"], 0)
            candidate["scanId"] = "other"
            (directory / "candidates.json").write_text(json.dumps(candidate))
            with self.assertRaises(ValueError):
                scorer.run(root)

    def test_command_exit_status(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_results(root)
            command = [sys.executable, str(HERE / "score.py"), str(root)]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            (root / "path_traversal/findings.json").write_text(json.dumps(document([])))
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
            (root / "path_traversal/findings.json").write_text(json.dumps({"findings": []}))
            malformed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(malformed.returncode, 2)
            self.assertIn("benchmark input error", malformed.stderr)
            self.assertNotIn("Traceback", malformed.stderr)
            (root / "path_traversal/findings.json").unlink()
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 2)


if __name__ == "__main__":
    unittest.main()
