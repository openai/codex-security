from __future__ import annotations

import copy

import test_finalize_scan_contract as finalization


def test_sealed_rerun_and_exports_preserve_shared_legacy_writeups() -> None:
    fixture = finalization.FinalizeScanContractTest()
    fixture.setUp()
    try:
        fixture.coverage["mode"] = "deep_repository"
        fixture.findings["findings"][0]["writeup"] = {"reportPath": "findings/shared/shared.md"}
        observation = copy.deepcopy(fixture.findings["findings"][0])
        observation["identity"]["anchor"] = "distinct-informational-observation"
        observation["severity"] = {"level": "informational"}
        observation["writeup"] = {"reportPath": "findings/observation/observation.md"}
        fixture.findings["findings"].append(observation)
        for finding in fixture.findings["findings"]:
            report = fixture.scan_dir / finding["writeup"]["reportPath"]
            report.parent.mkdir(parents=True)
            report.write_text("# Synthetic evidence\n")
        fixture.write_scan()
        finalization.FINALIZER.finalize_scan(fixture.scan_dir)
        findings = fixture.read_json("findings.json")
        # Older producers permitted informational observations to share a writeup.
        findings["findings"][1]["writeup"] = {"reportPath": "findings/shared/shared.md"}
        fixture.rewrite_sealed_artifact("findings.json", findings)
        before = {
            path.relative_to(fixture.scan_dir): path.read_bytes()
            for path in fixture.scan_dir.rglob("*")
            if path.is_file()
        }

        _, accepted, _ = finalization.FINALIZER.finalize_scan(fixture.scan_dir)
        fixture.assertEqual(accepted, findings)
        for export_format in ("json", "csv", "sarif"):
            fixture.assertTrue(
                finalization.FINALIZER.build_findings_export(fixture.scan_dir, export_format)
            )
        after = {
            path.relative_to(fixture.scan_dir): path.read_bytes()
            for path in fixture.scan_dir.rglob("*")
            if path.is_file()
        }
        fixture.assertEqual(after, before)

    finally:
        fixture.tearDown()
