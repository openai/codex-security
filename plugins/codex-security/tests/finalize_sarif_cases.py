from __future__ import annotations

import io
import os
import tempfile
import threading
from pathlib import Path
from unittest import mock, skipUnless

import pytest
from workbench_test_support import load_script, windows_file_backend

FINALIZER = load_script("finalize_scan_contract")
EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "examples" / "completed-scan"
CANONICAL_FILES = ("scan-manifest.json", "findings.json", "coverage.json")


class FinalizerSarifCases:
    def test_sarif_encodes_location_as_relative_uri(self) -> None:
        self.finding["locations"][0]["path"] = "src/archive handlers/extract.py"
        sarif_finding = self.sarif_finding("fingerprint")
        result = FINALIZER._sarif_result(sarif_finding, 0)
        location = result["locations"][0]["physicalLocation"]["artifactLocation"]
        uri = location["uri"]
        self.assertEqual(uri, "src/archive%20handlers/extract.py")
        self.assertNotIn("uriBaseId", location)

    def test_sarif_omits_unresolved_source_root_metadata(self) -> None:
        sarif = FINALIZER.build_sarif(self.manifest, {"findings": []})

        self.assertNotIn("originalUriBaseIds", sarif["runs"][0])

    def test_sarif_keeps_root_first_and_preserves_sink_and_evidence_locations(self) -> None:
        sarif_finding = self.sarif_finding("fingerprint")
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

    @pytest.mark.cross_platform
    def test_sarif_includes_legacy_code_evidence_locations(self) -> None:
        sarif_finding = self.sarif_finding("fingerprint")
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
            locations["src/canonical.py"]["physicalLocation"]["region"],
            {"startLine": 12, "endLine": 12},
        )
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

    @pytest.mark.cross_platform
    def test_sarif_normalizes_invalid_legacy_code_evidence_bounds(self) -> None:
        sarif_finding = self.sarif_finding("fingerprint")
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

    @pytest.mark.cross_platform
    def test_sarif_omits_invalid_legacy_code_evidence_locations(self) -> None:
        sarif_finding = self.sarif_finding("fingerprint")
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
        source_root = self.write_line_hash_source()
        sarif_finding = self.sarif_finding("semantic-fingerprint")
        result = self.sarif_result(sarif_finding, source_root)
        fingerprints = result["partialFingerprints"]
        self.assertEqual(fingerprints["codexSecurity/v1"], "semantic-fingerprint")
        self.assertEqual(fingerprints["primaryLocationLineHash"], "614150a715d5311d:1")

    def test_sarif_emits_github_line_hash_through_windows_backend(self) -> None:
        source_root = self.write_line_hash_source()
        sarif_finding = self.sarif_finding("semantic-fingerprint")
        backend = windows_file_backend()

        with (
            mock.patch.object(FINALIZER.os, "supports_dir_fd", set()),
            mock.patch.object(FINALIZER, "_is_windows", return_value=True),
            mock.patch.object(FINALIZER, "_windows_scan_local_files", return_value=backend),
        ):
            result = self.sarif_result(sarif_finding, source_root)

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
        sarif_finding = self.sarif_finding("semantic-fingerprint")
        sarif_finding["locations"] = [
            {"path": "src/route.py", "startLine": 1, "role": "entrypoint/wrapper"},
            {"path": "./src//control.py", "startLine": 1, "role": "root_control"},
        ]

        result = self.sarif_result(sarif_finding, source_root)

        self.assertEqual(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "./src//control.py",
        )
        self.assertEqual(
            result["partialFingerprints"]["primaryLocationLineHash"], "41499a4b14756ba2:1"
        )

    def test_sarif_line_hash_tolerates_non_utf8_source(self) -> None:
        source_root = self.scan_dir / "source"
        source_path = source_root / "src" / "extract.py"
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(b"\n" * 40 + b"invalid: \xff\n")
        sarif_finding = self.sarif_finding("semantic-fingerprint")
        result = self.sarif_result(sarif_finding, source_root)
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
            sarif_finding = self.sarif_finding("semantic-fingerprint")
            result = self.sarif_result(sarif_finding, source_root)
        self.assertNotIn("primaryLocationLineHash", result["partialFingerprints"])

    @skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
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
        source_root = self.write_line_hash_source()
        sarif_finding = self.sarif_finding("semantic-fingerprint")
        with mock.patch.object(FINALIZER, "_github_line_hashes", side_effect=PermissionError):
            result = self.sarif_result(sarif_finding, source_root)
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
            finding = self.sarif_finding(f"fingerprint-{index}", str(index))
            finding["locations"][0] = {"path": relative_path, "startLine": 1}
            findings.append(finding)

        sarif = FINALIZER.build_sarif(self.manifest, {"findings": findings}, source_root)

        results = sarif["runs"][0]["results"]
        for result in results:
            self.assertIn("primaryLocationLineHash", result["partialFingerprints"])

    def test_sarif_keeps_captured_hash_when_source_root_changes(self) -> None:
        read_hashes = FINALIZER._github_line_hashes_for_source
        for change in ("disappear", "retarget"):
            with self.subTest(change=change):
                source_root = self.write_line_hash_source()
                moved_root = source_root.with_name(f"moved-source-{change}")

                def read_then_move(
                    *args, source_root=source_root, moved_root=moved_root, change=change
                ):
                    hashes = read_hashes(*args)
                    source_root.rename(moved_root)
                    if change == "retarget":
                        replacement = self.scan_dir / "replacement"
                        (replacement / "src").mkdir(parents=True)
                        (replacement / "src" / "extract.py").write_text(
                            "replacement source\n" * 41, encoding="utf-8"
                        )
                        source_root.symlink_to(replacement, target_is_directory=True)
                    return hashes

                with mock.patch.object(
                    FINALIZER, "_github_line_hashes_for_source", side_effect=read_then_move
                ) as source_reads:
                    result = self.sarif_result(
                        self.sarif_finding("semantic-fingerprint"), source_root
                    )

                self.assertEqual(
                    result["partialFingerprints"]["primaryLocationLineHash"], "614150a715d5311d:1"
                )
                self.assertEqual(source_reads.call_count, 1)

    def test_sarif_does_not_retry_source_root_that_appears_after_capture(self) -> None:
        source_root = self.scan_dir / "source"
        sarif_rule = FINALIZER._sarif_rule

        def create_source_then_render_rule(*args):
            self.write_line_hash_source()
            return sarif_rule(*args)

        with mock.patch.object(
            FINALIZER, "_sarif_rule", side_effect=create_source_then_render_rule
        ):
            result = self.sarif_result(self.sarif_finding("semantic-fingerprint"), source_root)

        self.assertNotIn("primaryLocationLineHash", result["partialFingerprints"])

    def test_sarif_caches_line_hashes_per_source_file(self) -> None:
        source_root = self.write_line_hash_source()
        findings = []
        for index in range(2):
            finding = self.sarif_finding(f"fingerprint-{index}", str(index))
            finding["locations"][0]["startLine"] += index
            finding["locations"][0]["endLine"] += index
            findings.append(finding)

        with mock.patch.object(
            FINALIZER, "_github_line_hashes", wraps=FINALIZER._github_line_hashes
        ) as line_hashes:
            FINALIZER.build_sarif(self.manifest, {"findings": findings}, source_root)

        self.assertEqual(line_hashes.call_count, 1)
