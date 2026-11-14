from __future__ import annotations

import copy
import unittest

import test_finalize_scan_contract as fixtures

FINALIZER = fixtures.FINALIZER


class FinalizeCandidateReceiptsTest(unittest.TestCase):
    setUp = fixtures.FinalizeScanContractTest.setUp
    tearDown = fixtures.FinalizeScanContractTest.tearDown
    write_scan = fixtures.FinalizeScanContractTest.write_scan
    write_json = fixtures.FinalizeScanContractTest.write_json
    read_json = fixtures.FinalizeScanContractTest.read_json

    def test_unverified_disposition_retains_owned_candidate_evidence(self) -> None:
        original = copy.deepcopy(self.coverage)
        for disposition in (
            {},
            {"disposition": None},
            {"disposition": "unknown"},
            {"disposition": []},
        ):
            with self.subTest(disposition=disposition):
                self.coverage = copy.deepcopy(original)
                self.coverage["deferred"] = []
                surface = self.coverage["surfaces"][0]
                surface.pop("disposition")
                surface.update(
                    **disposition,
                    candidateId="candidate-review",
                    sourceWorkerId="worker-current",
                    receiptRefs=[],
                    candidate={"evidence": "Saved candidate evidence remains available."},
                )
                self.write_scan()
                source_bytes = (self.scan_dir / "coverage.json").read_bytes()
                prepared = FINALIZER._prepare_scan_finalization(
                    self.scan_dir, recover_unsealed=True
                )
                self.assertEqual((self.scan_dir / "coverage.json").read_bytes(), source_bytes)
                self.assertEqual(prepared.coverage["surfaces"][0]["disposition"], "needs_follow_up")
                self.assertEqual(len(prepared.coverage["deferred"]), 1)
                pending = prepared.coverage["deferred"][0]
                self.assertEqual(pending["candidateId"], surface["candidateId"])
                self.assertEqual(pending["sourceWorkerId"], surface["sourceWorkerId"])
                self.assertEqual(pending["surfaceIds"], [surface["id"]])
                self.assertEqual(pending["candidate"], surface["candidate"])
                self.assertIn("the review disposition could not be verified", pending["reason"])
                _, _, published = FINALIZER._write_prepared_scan_finalization(prepared)
                self.assertEqual(FINALIZER.finalize_scan(self.scan_dir)[2], published)

    def test_recovered_receipt_decision_retains_owned_pending_evidence(self) -> None:
        original = copy.deepcopy(self.coverage)
        for disposition in ("rejected", "not_applicable"):
            for previous_owner in (None, "worker-current", "worker-other"):
                with self.subTest(disposition=disposition, previous_owner=previous_owner):
                    self.coverage = copy.deepcopy(original)
                    self.coverage["completeness"] = "partial"
                    surface = self.coverage["surfaces"][0]
                    surface.update(
                        candidateId="candidate-review",
                        sourceWorkerId="worker-current",
                        disposition=disposition,
                        receiptRefs=["artifacts/review/missing-receipt.txt"],
                        candidate={"evidence": "Saved candidate evidence remains available."},
                    )
                    previous = None
                    if previous_owner is not None:
                        previous = {
                            "id": surface["id"],
                            "candidateId": "candidate-review",
                            "sourceWorkerId": previous_owner,
                            "reason": "Independent authored proof gap.",
                            "candidate": {"evidence": "Independent saved candidate evidence."},
                            "surfaceIds": [surface["id"]],
                        }
                        self.coverage["deferred"].append(copy.deepcopy(previous))
                    self.write_scan()
                    prepared = FINALIZER._prepare_scan_finalization(
                        self.scan_dir, recover_unsealed=True
                    )
                    warnings = prepared.warnings
                    recovered = prepared.coverage
                    self.assertEqual(recovered["surfaces"][0]["disposition"], "needs_follow_up")
                    pending = next(
                        row
                        for row in recovered["deferred"]
                        if row.get("sourceWorkerId") == "worker-current"
                    )
                    self.assertEqual(pending["surfaceIds"], [surface["id"]])
                    if previous_owner == "worker-current":
                        self.assertEqual(pending, previous)
                    else:
                        self.assertEqual(pending["candidate"], surface["candidate"])
                        self.assertIn(warnings[0], pending["reason"])
                    if previous is not None:
                        self.assertIn(previous, recovered["deferred"])
                    self.assertEqual(
                        len({row["id"] for row in recovered["deferred"]}),
                        len(recovered["deferred"]),
                    )
                    self.assertTrue(
                        any(
                            warning.startswith("Skipped malformed coverage receipt")
                            for warning in warnings
                        )
                    )

    def test_projected_surface_recovers_into_legacy_candidate_gap(self) -> None:
        self.coverage["completeness"] = "partial"
        surface = self.coverage["surfaces"][0]
        surface.update(
            candidateId="worker-attempt-1-candidate-digest",
            provenance={"workerId": "worker", "attempt": 1, "candidateId": "candidate-review"},
            disposition="rejected",
            receiptRefs=["artifacts/missing.txt"],
        )
        previous = {
            "id": "saved-review",
            "candidateId": "candidate-review",
            "sourceWorkerId": "worker",
            "reason": "Original validation is still missing.",
        }
        self.coverage["deferred"] = [previous]
        self.write_scan()
        prepared = FINALIZER._prepare_scan_finalization(self.scan_dir, recover_unsealed=True)
        self.assertEqual(prepared.coverage["surfaces"][0]["disposition"], "needs_follow_up")
        self.assertEqual(prepared.coverage["deferred"], [previous])

    def test_receipt_recovery_preserves_closed_generic_task_identities(self) -> None:
        original = copy.deepcopy(self.coverage)
        for disposition in ("rejected", "not_applicable"):
            for valid_receipt in (False, True):
                with self.subTest(disposition=disposition, valid_receipt=valid_receipt):
                    self.coverage = copy.deepcopy(original)
                    surface = self.coverage["surfaces"][0]
                    surface.update(
                        candidateId="candidate-review",
                        disposition=disposition,
                        candidate={"evidence": "Retain original candidate evidence."},
                        receiptRefs=["artifacts/review/receipt.txt"],
                    )
                    closures = [
                        {"id": surface["id"], "reason": "Source review completed."},
                        {"id": "other-closed-review", "reason": "Another review completed."},
                    ]
                    self.coverage["resolvedDeferred"] = copy.deepcopy(closures)
                    self.write_scan()
                    receipt = self.scan_dir / "artifacts/review/receipt.txt"
                    receipt.parent.mkdir(parents=True, exist_ok=True)
                    if valid_receipt:
                        receipt.write_text("Synthetic verified review receipt.\n")
                    elif receipt.exists():
                        receipt.unlink()
                    prepared = FINALIZER._prepare_scan_finalization(
                        self.scan_dir, recover_unsealed=True
                    )
                    recovered = prepared.coverage
                    self.assertEqual(recovered.get("resolvedDeferred"), closures)
                    candidate_rows = [
                        row
                        for row in recovered["deferred"]
                        if row.get("candidateId") == surface["candidateId"]
                    ]
                    self.assertEqual(bool(candidate_rows), not valid_receipt)
                    if candidate_rows:
                        self.assertNotIn(candidate_rows[0]["id"], {row["id"] for row in closures})
                        self.assertEqual(candidate_rows[0]["candidate"], surface["candidate"])

    def test_parent_receipt_recovery_keeps_independent_valid_closures(self) -> None:
        original = copy.deepcopy(self.coverage)
        for malformed in (None, "duplicate", "missing-reason", "already-active"):
            for valid_receipt in (False, True):
                with self.subTest(malformed=malformed, valid_receipt=valid_receipt):
                    self.coverage = copy.deepcopy(original)
                    surface = self.coverage["surfaces"][0]
                    surface.update(
                        candidateId="review/auth",
                        disposition="rejected",
                        receiptRefs=["artifacts/receipt.txt"],
                    )
                    closures = [
                        {"id": "review/auth", "reason": "Candidate review completed."},
                        {"id": "independent-review", "reason": "Independent review completed."},
                    ]
                    if malformed == "duplicate":
                        closures.append(copy.deepcopy(closures[1]))
                    elif malformed == "missing-reason":
                        closures[0].pop("reason")
                    elif malformed == "already-active":
                        self.coverage["completeness"] = "partial"
                        self.coverage["deferred"] = [
                            {"id": "independent-review", "reason": "Still active."}
                        ]
                    self.coverage["resolvedDeferred"] = closures
                    self.write_scan()
                    receipt = self.scan_dir / "artifacts/receipt.txt"
                    receipt.parent.mkdir(exist_ok=True)
                    if valid_receipt:
                        receipt.write_bytes(b"Synthetic completed review evidence.")
                    else:
                        receipt.unlink(missing_ok=True)
                    source_bytes = (self.scan_dir / "coverage.json").read_bytes()
                    prepared = FINALIZER._prepare_scan_finalization(
                        self.scan_dir, recover_unsealed=True
                    )
                    self.assertEqual((self.scan_dir / "coverage.json").read_bytes(), source_bytes)
                    # Task IDs remain independent of the reopened candidate's semantic ID.
                    expected = None if malformed else closures
                    self.assertEqual(prepared.coverage.get("resolvedDeferred"), expected)
                    _, _, published = FINALIZER._write_prepared_scan_finalization(prepared)
                    _, _, sealed = FINALIZER.finalize_scan(self.scan_dir)
                    self.assertEqual(sealed, published)
                    self.assertEqual(sealed.get("resolvedDeferred"), expected)
                    pending = [
                        row for row in sealed["deferred"] if row.get("candidateId") == "review/auth"
                    ]
                    self.assertEqual(len(pending), int(not valid_receipt))
                    self.assertEqual(FINALIZER.finalize_scan(self.scan_dir)[2], sealed)
