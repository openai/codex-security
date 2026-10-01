from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import test_finalize_scan_contract as fixtures

FINALIZER = fixtures.FINALIZER


class ThreatModelProjectionTest(unittest.TestCase):
    setUp = fixtures.FinalizeScanContractTest.setUp
    tearDown = fixtures.FinalizeScanContractTest.tearDown
    write_scan = fixtures.FinalizeScanContractTest.write_scan
    write_json = fixtures.FinalizeScanContractTest.write_json
    read_json = fixtures.FinalizeScanContractTest.read_json

    def test_saves_and_exports_markdown_threat_model_without_changing_authored_body(self) -> None:
        body = "# Service Model\n\n| Asset | Owner |\n| --- | --- |\n| Queue | Service |\n\n```text\nA -> B\n```\n"
        model = {
            "format": "markdown",
            "content": body,
            "origin": "provided",
            "scope": {"includePaths": ["."], "excludePaths": ["vendor/"]},
        }
        self.manifest["scan"]["threatModel"] = model
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        document = (self.scan_dir / "threatmodel.md").read_bytes()
        self.assertTrue(document.startswith(body.encode()))
        self.assertIn(b"Model origin: provided", document)
        self.assertIn(b"Model scope: .", document)
        self.assertIn(b"Scan scope: src/", document)
        self.assertIn(b"Revision: deadbeef", document)
        snapshot_digest = self.manifest["scan"]["target"]["snapshotDigest"]
        self.assertIn(f"Snapshot: {snapshot_digest}".encode(), document)
        self.assertNotIn(b"provisional", document)
        self.assertIn(body, (self.scan_dir / "report.md").read_text())
        before = (self.scan_dir / "scan-manifest.json").read_bytes()
        (self.scan_dir / "threatmodel.md").write_text("stale convenience document")
        self.assertEqual(FINALIZER.build_threat_model_export(self.scan_dir), document)
        self.assertEqual((self.scan_dir / "scan-manifest.json").read_bytes(), before)
        description = FINALIZER.describe_threat_model(self.scan_dir)
        self.assertEqual(description["threatModel"], model)
        self.assertFalse(description["provenance"]["provisional"])
        self.assertEqual(description["provenance"]["snapshotDigest"], snapshot_digest)
        self.assertIsNone(description["path"])

    def test_rejects_blank_markdown_before_sealing(self) -> None:
        for content in ("", " \n\t"):
            with self.subTest(content=content):
                self.manifest["scan"]["threatModel"] = {"format": "markdown", "content": content}
                self.write_scan()
                with self.assertRaises(FINALIZER.ContractError):
                    FINALIZER.finalize_scan(self.scan_dir)
                self.assertNotIn("sealedAt", self.read_json("scan-manifest.json")["scan"])

    def test_exports_legacy_structured_model_extensions(self) -> None:
        for extensions in (
            {"format": "markdown"},
            {"format": "markdown", "content": " \n"},
            {"scope": "Repository-wide", "origin": "legacy-import"},
            {"scope": {"includePaths": 42}, "origin": {"tool": "legacy"}},
            {"scope": {"includePaths": ["src"], "excludePaths": 42, "summary": []}},
        ):
            with self.subTest(extensions=extensions):
                model = {"summary": "Existing structured model.", **extensions}
                self.manifest["scan"]["threatModel"] = model
                self.write_scan()
                FINALIZER.finalize_scan(self.scan_dir)
                self.assertEqual(self.read_json("scan-manifest.json")["scan"]["threatModel"], model)
                self.assertIn(
                    b"Existing structured model.",
                    FINALIZER.build_threat_model_export(self.scan_dir),
                )
                self.assertEqual(
                    FINALIZER.build_findings_export(self.scan_dir, "json"),
                    (self.scan_dir / "findings.json").read_bytes(),
                )

    def test_markdown_content_takes_precedence_over_a_summary_extension(self) -> None:
        self.manifest["scan"]["threatModel"] = {
            "format": "markdown",
            "content": "# Full model\n\nSource-backed detail.\n",
            "summary": "A shorter summary.",
        }
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        document = FINALIZER.build_threat_model_export(self.scan_dir)
        self.assertTrue(document.startswith(b"# Full model\n\nSource-backed detail.\n"))
        self.assertNotIn(b"A shorter summary.", document)

    def test_failed_projection_update_does_not_expose_the_previous_model(self) -> None:
        self.manifest["scan"]["threatModel"] = {"summary": "Original queue boundaries."}
        self.write_scan()
        FINALIZER.write_threat_model_projection_if_possible(self.scan_dir, self.manifest)
        self.manifest["scan"]["threatModel"] = {"summary": "Updated queue boundaries."}
        self.write_scan()
        with (
            unittest.mock.patch.object(
                FINALIZER,
                "write_scan_local_bytes",
                side_effect=OSError("Synthetic locked document"),
            ),
            unittest.mock.patch("sys.stderr", new_callable=io.StringIO),
        ):
            self.assertIsNotNone(
                FINALIZER.write_threat_model_projection_if_possible(self.scan_dir, self.manifest)
            )
        self.assertIsNone(FINALIZER.describe_threat_model(self.scan_dir)["path"])
        self.assertIn("Original queue", (self.scan_dir / "threatmodel.md").read_text())
        self.assertIn(b"Updated queue", FINALIZER.build_threat_model_export(self.scan_dir))

    def test_exports_provisional_model_without_sealing_or_collapsing_summary_markdown(self) -> None:
        body = "A summary.\n\n- First boundary\n- Second boundary\n\n```text\nA -> B\n```"
        self.manifest["scan"]["threatModel"] = {"summary": body, "assets": ["Stored records"]}
        self.manifest["scan"]["status"] = "running"
        self.write_scan()
        before = (self.scan_dir / "scan-manifest.json").read_bytes()
        document = FINALIZER.build_threat_model_export(self.scan_dir).decode()
        self.assertIn(body, document)
        self.assertIn("## Assets\n\n- Stored records", document)
        self.assertIn("Model scope: not recorded", document)
        self.assertIn("provisional", document)
        self.assertEqual((self.scan_dir / "scan-manifest.json").read_bytes(), before)
        self.assertFalse((self.scan_dir / "threatmodel.md").exists())

    def test_missing_threat_model_does_not_create_placeholder(self) -> None:
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        self.assertFalse((self.scan_dir / "threatmodel.md").exists())
        with self.assertRaisesRegex(FINALIZER.ContractError, "No saved threat model"):
            FINALIZER.build_threat_model_export(self.scan_dir)

    def test_blank_legacy_summary_keeps_assets_and_remains_exportable(self) -> None:
        self.manifest["scan"]["threatModel"] = {
            "summary": " \n\t",
            "assets": ["Stored records"],
        }
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        FINALIZER.finalize_scan(self.scan_dir)
        for document in (
            (self.scan_dir / "report.md").read_text(),
            FINALIZER.build_threat_model_export(self.scan_dir).decode(),
        ):
            self.assertIn("No explicit canonical threat-model summary was recorded.", document)
            self.assertIn("- Stored records", document)
        self.assertEqual(
            FINALIZER.build_findings_export(self.scan_dir, "json"),
            (self.scan_dir / "findings.json").read_bytes(),
        )

    def test_scan_manifest_does_not_fall_back_to_an_unrelated_policy_model(self) -> None:
        self.write_scan()
        self.write_json(
            "policy-draft.json",
            {
                "documentType": "codex-security.policy-draft",
                "threatModel": {"summary": "A separate policy model."},
            },
        )
        FINALIZER.finalize_scan(self.scan_dir)
        self.assertFalse((self.scan_dir / "threatmodel.md").exists())
        with self.assertRaisesRegex(FINALIZER.ContractError, "No saved threat model"):
            FINALIZER.describe_threat_model(self.scan_dir)
        with self.assertRaisesRegex(FINALIZER.ContractError, "No saved threat model"):
            FINALIZER.build_threat_model_export(self.scan_dir)
        (self.scan_dir / "scan-manifest.json").unlink()
        self.assertIn(
            b"A separate policy model.", FINALIZER.build_threat_model_export(self.scan_dir)
        )

    def test_threat_model_write_failure_preserves_canonical_content(self) -> None:
        self.manifest["scan"]["threatModel"] = {"summary": "Queue ownership and boundaries."}
        self.write_scan()
        with tempfile.TemporaryDirectory() as outside:
            destination = Path(outside) / "keep.md"
            destination.write_text("unchanged")
            (self.scan_dir / "threatmodel.md").symlink_to(destination)
            with unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                FINALIZER.finalize_scan(self.scan_dir)
            self.assertIn("automatic threat model save failed", stderr.getvalue().lower())
            self.assertEqual(destination.read_text(), "unchanged")
        self.assertIn("sealedAt", self.read_json("scan-manifest.json")["scan"])
        self.assertIn(b"Queue ownership", FINALIZER.build_threat_model_export(self.scan_dir))

    @unittest.skipIf(os.name == "nt", "POSIX permission modes")
    def test_model_files_remain_private_and_editable_under_restrictive_umask(self) -> None:
        self.manifest["scan"]["threatModel"] = {"summary": "Queue ownership and boundaries."}
        self.write_scan()
        with tempfile.TemporaryDirectory() as external:
            exported = Path(external).resolve() / "threatmodel.md"
            previous_umask = os.umask(0o600)
            try:
                warning = FINALIZER.write_threat_model_projection_if_possible(
                    self.scan_dir, self.manifest
                )
                self.assertIsNone(warning)
                FINALIZER.write_export_output(
                    self.scan_dir,
                    exported,
                    "md",
                    FINALIZER.build_threat_model_export(self.scan_dir),
                )
            finally:
                os.umask(previous_umask)
            for path in (self.scan_dir / "threatmodel.md", exported):
                with self.subTest(path=path):
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    content = path.read_text()
                    self.assertIn("Queue ownership", content)
                    path.write_text(content + "\nOwner edits remain possible.\n")

    def test_threat_model_export_validates_existing_scan_seal(self) -> None:
        self.manifest["scan"]["threatModel"] = {"summary": "Queue ownership and boundaries."}
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        (self.scan_dir / "findings.json").write_text("{}")
        with self.assertRaisesRegex(FINALIZER.ContractError, "sealed artifact changed"):
            FINALIZER.build_threat_model_export(self.scan_dir)

    def test_projection_preserves_existing_sealed_threat_model(self) -> None:
        self.manifest["scan"]["threatModel"] = {"summary": "Canonical queue boundaries."}
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        original = b"# Historical model\n\nRetained sealed evidence.\n"
        document = self.scan_dir / "threatmodel.md"
        document.write_bytes(original)
        manifest = self.read_json("scan-manifest.json")
        manifest["scan"]["artifacts"].append(
            FINALIZER._artifact_record(self.scan_dir, "threatmodel.md", "text/markdown")
        )
        self.write_json("scan-manifest.json", manifest)
        sealed_manifest = (self.scan_dir / "scan-manifest.json").read_bytes()

        FINALIZER.finalize_scan(self.scan_dir)
        self.assertEqual(document.read_bytes(), original)
        written = subprocess.run(
            [
                sys.executable,
                str(Path(FINALIZER.__file__)),
                "--scan-dir",
                str(self.scan_dir),
                "--write-threat-model",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertEqual(document.read_bytes(), original)
        self.assertEqual((self.scan_dir / "scan-manifest.json").read_bytes(), sealed_manifest)
        self.assertEqual(
            FINALIZER.build_findings_export(self.scan_dir, "json"),
            (self.scan_dir / "findings.json").read_bytes(),
        )
        self.assertIn(
            b"Canonical queue boundaries.", FINALIZER.build_threat_model_export(self.scan_dir)
        )

    def test_malformed_model_is_reported_without_discarding_saved_content(self) -> None:
        self.manifest["scan"]["threatModel"] = {"summary": "Queue boundaries.", "assets": [None]}
        self.write_scan()
        original = (self.scan_dir / "scan-manifest.json").read_bytes()
        with self.assertRaisesRegex(
            FINALIZER.ContractError, r"threatModel.assets\[0\]: expected a string"
        ):
            FINALIZER.build_threat_model_export(self.scan_dir)
        with unittest.mock.patch("sys.stderr", new_callable=io.StringIO):
            warning = FINALIZER.write_threat_model_projection_if_possible(self.scan_dir)
        self.assertIn("threatModel.assets[0]: expected a string", warning)
        self.assertEqual((self.scan_dir / "scan-manifest.json").read_bytes(), original)
        self.assertFalse((self.scan_dir / "threatmodel.md").exists())

    def test_exports_legacy_documents_without_reformatting_or_mutating_them(self) -> None:
        body = "# Existing Model\n\n    Preserve indentation.\n"
        for filename in (
            "threatmodel.md",
            "THREAT_MODEL.md",
            "artifacts/01_context/threat_model.md",
            "threat_model.md",
        ):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                source = Path(directory).resolve()
                path = source / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
                self.assertEqual(FINALIZER.build_threat_model_export(source), body.encode())
                self.assertEqual(path.read_text(), body)
                self.assertEqual(FINALIZER.describe_threat_model(source)["path"], str(path))

    def test_malformed_canonical_model_does_not_export_a_stale_legacy_document(self) -> None:
        body = "# Earlier model\n\nEarlier service boundaries.\n"
        for filename in ("scan-manifest.json", "policy-draft.json"):
            for model in (None, "invalid model", []):
                with (
                    self.subTest(filename=filename, model=model),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    source = Path(directory).resolve()
                    scan = {"threatModel": model}
                    manifest = (
                        {"scan": scan}
                        if filename == "scan-manifest.json"
                        else {"documentType": "codex-security.policy-draft", **scan}
                    )
                    path = source / filename
                    original = json.dumps(manifest)
                    path.write_text(original)
                    legacy = source / "threatmodel.md"
                    legacy.write_text(body)
                    for read_model in (
                        FINALIZER.describe_threat_model,
                        FINALIZER.build_threat_model_export,
                    ):
                        with self.assertRaisesRegex(
                            FINALIZER.ContractError, "threatModel: expected an object"
                        ):
                            read_model(source)
                    self.assertEqual(path.read_text(), original)
                    self.assertEqual(legacy.read_text(), body)
                    current = manifest["scan"] if filename == "scan-manifest.json" else manifest
                    del current["threatModel"]
                    path.write_text(json.dumps(manifest))
                    self.assertEqual(FINALIZER.build_threat_model_export(source), body.encode())

    def test_policy_models_share_projection_and_offline_export(self) -> None:
        manifest = {
            "documentType": "codex-security.policy-draft",
            "repository": "/example/project",
            "scope": "services/queue",
            "revision": "abc123",
            "status": "threat_model_ready",
            "threatModel": {
                "format": "markdown",
                "content": "# Queue\n\nRetain this body.\n",
                "scope": {"includePaths": ["services/queue"]},
                "origin": "generated",
            },
        }
        self.write_json("policy-draft.json", manifest)
        script = Path(FINALIZER.__file__)
        saved = subprocess.run(
            [sys.executable, str(script), "--scan-dir", str(self.scan_dir), "--write-threat-model"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(saved.returncode, 0, saved.stderr)
        self.assertIn("provisional", (self.scan_dir / "threatmodel.md").read_text())
        manifest["status"] = "completed"
        self.write_json("policy-draft.json", manifest)
        exported = subprocess.run(
            [
                sys.executable,
                str(script),
                "--scan-dir",
                str(self.scan_dir),
                "--export-artifact",
                "threat-model",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(exported.returncode, 0, exported.stderr)
        self.assertTrue(exported.stdout.startswith(manifest["threatModel"]["content"]))
        self.assertNotIn("provisional", exported.stdout)
        self.assertIn("Source: policy", exported.stdout)
        destination = self.scan_dir / "exports" / "threatmodel.md"
        exported_with_metadata = subprocess.run(
            [
                sys.executable,
                str(script),
                "--scan-dir",
                str(self.scan_dir),
                "--export-artifact",
                "threat-model",
                "--export-output",
                str(destination),
                "--export-metadata",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(exported_with_metadata.returncode, 0, exported_with_metadata.stderr)
        metadata = json.loads(exported_with_metadata.stdout)
        self.assertEqual(metadata["path"], str(destination))
        self.assertEqual(metadata["threatModel"], manifest["threatModel"])
        self.assertFalse(metadata["provenance"]["provisional"])
        self.assertEqual(destination.read_text(), exported.stdout)

    def test_legacy_document_preserves_available_result_context(self) -> None:
        body = "# Existing model\n\nReview the recorded service boundaries.\n"
        self.write_scan()
        FINALIZER.finalize_scan(self.scan_dir)
        legacy_path = self.scan_dir / "artifacts" / "01_context" / "threat_model.md"
        legacy_path.parent.mkdir(parents=True)
        legacy_path.write_text(body)
        description = FINALIZER.describe_threat_model(self.scan_dir)
        self.assertEqual(description["provenance"]["source"], "scan")
        self.assertEqual(description["provenance"]["scanId"], self.manifest["scan"]["id"])
        self.assertEqual(description["provenance"]["scanScope"], self.manifest["scan"]["scope"])
        self.assertFalse(description["provenance"]["provisional"])
        self.assertNotIn("scope", description["threatModel"])
        self.assertEqual(FINALIZER.build_threat_model_export(self.scan_dir), body.encode())

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve()
            (source / "policy-draft.json").write_text(
                json.dumps(
                    {
                        "documentType": "codex-security.policy-draft",
                        "repository": "/example/project",
                        "scope": "services/queue",
                        "revision": "abc123",
                    }
                )
            )
            (source / "THREAT_MODEL.md").write_text(body)
            description = FINALIZER.describe_threat_model(source)
            self.assertEqual(description["provenance"]["source"], "policy")
            self.assertEqual(description["provenance"]["revision"], "abc123")
            self.assertFalse(description["provenance"]["provisional"])
            self.assertEqual(FINALIZER.build_threat_model_export(source), body.encode())

    def test_threat_model_export_rejects_canonical_overwrite(self) -> None:
        self.manifest["scan"]["threatModel"] = {"summary": "Queue boundaries."}
        self.write_scan()
        for filename in ("scan-manifest.json", "report.md", "threatmodel.md"):
            with self.subTest(filename=filename):
                with self.assertRaisesRegex(FINALIZER.ContractError, "cannot overwrite"):
                    FINALIZER.write_export_output(
                        self.scan_dir, self.scan_dir / filename, "md", b"model"
                    )
        destination = self.scan_dir / "exports" / "threatmodel.md"
        FINALIZER.write_export_output(self.scan_dir, destination, "md", b"model")
        self.assertEqual(destination.read_bytes(), b"model")
