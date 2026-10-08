from __future__ import annotations

import unittest

import test_finalize_scan_contract as fixtures

FINALIZER = fixtures.FINALIZER


class FinalizeScanPathsTest(unittest.TestCase):
    setUp = fixtures.FinalizeScanContractTest.setUp
    tearDown = fixtures.FinalizeScanContractTest.tearDown
    write_scan = fixtures.FinalizeScanContractTest.write_scan
    write_json = fixtures.FinalizeScanContractTest.write_json

    def test_rejects_remote_control_characters(self) -> None:
        for character in ("\0", "\t", "\n", "\r", "\x7f", "\x85", "\u2028", "\u2029"):
            with self.subTest(character=repr(character)):
                self.manifest["scan"]["target"]["remote"] = f"https://example.com{character}/repo"
                self.write_scan()
                with self.assertRaisesRegex(
                    FINALIZER.ContractError, "expected a sanitized canonical absolute URL"
                ):
                    FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_unsafe_code_evidence_paths(self) -> None:
        for path in ("../../outside.ts", "/outside.ts", r"C:\outside.ts"):
            with self.subTest(path=path):
                self.findings["findings"][0]["codeEvidence"] = [
                    {
                        "id": "source",
                        "label": "Source",
                        "path": path,
                        "startLine": 1,
                        "code": "source()",
                        "explanation": "Synthetic source evidence.",
                    }
                ]
                self.write_scan()
                with self.assertRaisesRegex(
                    FINALIZER.ContractError,
                    r"codeEvidence\[0\]\.path: expected a safe repository-relative POSIX path",
                ):
                    FINALIZER.finalize_scan(self.scan_dir)

    def test_rejects_unsafe_deferred_paths(self) -> None:
        self.coverage["completeness"] = "partial"
        for path in ("../../outside.ts", "/outside.ts", r"C:\outside.ts"):
            with self.subTest(path=path):
                self.coverage["deferred"] = [
                    {"id": "review", "reason": "Review is incomplete.", "paths": [path]}
                ]
                self.write_scan()
                with self.assertRaisesRegex(
                    FINALIZER.ContractError,
                    r"deferred\[0\]\.paths\[0\]: expected a safe repository-relative POSIX path",
                ):
                    FINALIZER.finalize_scan(self.scan_dir)

    def test_accepts_safe_code_evidence_and_deferred_paths(self) -> None:
        self.findings["findings"][0]["codeEvidence"] = [
            {
                "id": "source",
                "label": "Source",
                "path": "src/extract.py",
                "startLine": 41,
                "code": "source()",
                "explanation": "Repository-relative evidence.",
            }
        ]
        self.coverage["completeness"] = "partial"
        for path in (".", "src", "src/extract.py", "src/a:b.py"):
            with self.subTest(path=path):
                self.coverage["deferred"] = [
                    {"id": "review", "reason": "Review is incomplete.", "paths": [path]}
                ]
                self.write_scan()
                _, findings, coverage = FINALIZER.finalize_scan(self.scan_dir)
                self.assertEqual(
                    findings["findings"][0]["codeEvidence"][0]["path"], "src/extract.py"
                )
                self.assertEqual(coverage["deferred"][0]["paths"], [path])


if __name__ == "__main__":
    unittest.main()
