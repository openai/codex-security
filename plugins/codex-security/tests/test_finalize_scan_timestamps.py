from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from unittest import mock

import test_finalize_scan_contract as fixtures

FINALIZER = fixtures.FINALIZER
CANONICAL_FILES = fixtures.CANONICAL_FILES


class FinalizeScanTimestampsTest(unittest.TestCase):
    setUp = fixtures.FinalizeScanContractTest.setUp
    tearDown = fixtures.FinalizeScanContractTest.tearDown
    write_scan = fixtures.FinalizeScanContractTest.write_scan
    write_json = fixtures.FinalizeScanContractTest.write_json
    read_json = fixtures.FinalizeScanContractTest.read_json
    scan_file_bytes = fixtures.FinalizeScanContractTest.scan_file_bytes

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
        completed_datetime = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
        self.assertGreaterEqual(completed_datetime, before)
        self.assertLessEqual(completed_datetime, datetime.now(timezone.utc))
        self.assertEqual(manifest["scan"]["sealedAt"], completed_at)

    def test_headless_finalization_rejects_invalid_authoritative_start(self) -> None:
        self.write_scan()

        with mock.patch.dict(os.environ, {"CODEX_SECURITY_STARTED_AT": "not-a-timestamp"}):
            with self.assertRaisesRegex(FINALIZER.ContractError, "RFC 3339 timestamp"):
                FINALIZER.finalize_scan(self.scan_dir)

        self.assertNotIn("sealedAt", self.read_json("scan-manifest.json")["scan"])

    def test_preserves_rfc3339_fractional_timestamps_when_sealing(self) -> None:
        for fraction in ("", ".1", ".12", ".123", ".1234", ".12345", ".123456", ".1234567"):
            for offset in ("z", "+02:00", "-07:30"):
                timestamp = f"2024-02-29t18:09:00{fraction}{offset}"
                with self.subTest(timestamp=timestamp):
                    self.manifest["scan"]["startedAt"] = timestamp
                    self.manifest["scan"]["completedAt"] = timestamp
                    self.write_scan()

                    manifest, _, _ = FINALIZER.finalize_scan(self.scan_dir)

                    for field in ("startedAt", "completedAt", "sealedAt"):
                        self.assertEqual(manifest["scan"][field], timestamp)
                    before = self.scan_file_bytes(*CANONICAL_FILES)
                    FINALIZER.finalize_scan(self.scan_dir)
                    self.assertEqual(self.scan_file_bytes(*CANONICAL_FILES), before)

    def test_rejects_non_rfc3339_timestamps(self) -> None:
        for timestamp in (
            "2026-W22-7T18:09:00+00:00",
            "2026-05-31T18:09:00+0000",
            "2026-02-29T18:09:00.123456789Z",
            "2026-05-31T24:09:00.1Z",
            "2026-05-31T18:60:00.1Z",
            "2026-05-31T18:09:61.1Z",
            "2026-05-31T18:09:00.123456789+24:00",
            "2026-05-31T18:09:00.123456789-24:00",
            "2026-05-31T18:09:00.Z",
            "2026-05-31T18:09:00,123Z",
            "2026-05-31T18:09:00.1",
            "2026-05-31T18:09:00.\u0661Z",
            "2026-05-31T18:09:00.123\u0664Z",
        ):
            with self.subTest(timestamp=timestamp):
                self.manifest["scan"]["startedAt"] = timestamp
                self.write_scan()
                with self.assertRaisesRegex(FINALIZER.ContractError, "RFC 3339 timestamp"):
                    FINALIZER.finalize_scan(self.scan_dir)
