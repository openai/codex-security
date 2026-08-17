import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

describe("bundled scan report and source limits", () => {
  test("refreshes only unsealed report projections", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const program = [
      "import json, os, pathlib, stat, sys",
      "from contextlib import ExitStack",
      "from unittest.mock import Mock, patch",
      "sys.path.insert(0, sys.argv[1])",
      "import finalize_scan_contract as finalizer",
      "scan_dir, schema_dir = pathlib.Path('saved-scan'), pathlib.Path('selected-schemas')",
      "findings, coverage = {}, {}",
      "metadata = os.stat_result((stat.S_IFREG, 7, 11, 1, 0, 0, 0, 0, 0, 0))",
      "directory = os.stat_result((stat.S_IFDIR, 1, 11, 1, 0, 0, 0, 0, 0, 0))",
      "other_directory = os.stat_result((stat.S_IFDIR, 2, 11, 1, 0, 0, 0, 0, 0, 0))",
      "def check_report(paths, entries, outcome, *, missing=False, separate_parent=False):",
      "    manifest = {'scan': {'artifacts': [{'path': path} for path in paths]}}",
      "    reader = Mock(return_value=(manifest, findings, coverage, b'canonical'))",
      "    project, writer = Mock(return_value=b'projected report\\n'), Mock()",
      "    opened, closed = Mock(return_value=42), Mock()",
      "    def inspect(path, *, follow_symlinks=True):",
      "        if path == scan_dir / 'report.md':",
      "            if missing: raise FileNotFoundError",
      "            return metadata",
      "        return other_directory if separate_parent and path == scan_dir / 'artifacts' else directory",
      "    with ExitStack() as stack:",
      "        for owner, name, replacement in [(finalizer, '_require_scan_directory', lambda path: path), (finalizer, '_read_sealed_scan', reader), (finalizer, '_generate_report_projection', project), (finalizer, 'write_scan_local_bytes', writer), (pathlib.Path, 'stat', inspect), (finalizer.os, 'listdir', lambda path: entries), (finalizer, 'open_scan_local_file_descriptor', opened), (finalizer.os, 'fstat', lambda descriptor: metadata), (finalizer.os, 'close', closed)]:",
      "            stack.enter_context(patch.object(owner, name, replacement))",
      "        if outcome == 'ambiguous':",
      "            try: finalizer.write_report_projection(scan_dir, schema_dir)",
      "            except finalizer.ContractError as exc: assert 'ambiguous sealed artifact alias' in str(exc)",
      "            else: raise AssertionError('ambiguous alias was accepted')",
      "        else: finalizer.write_report_projection(scan_dir, schema_dir)",
      "    reader.assert_called_once_with(scan_dir, schema_dir, 'report projection')",
      "    assert opened.call_count == closed.call_count",
      "    if outcome == 'write':",
      "        project.assert_called_once_with(manifest, findings, coverage)",
      "        writer.assert_called_once_with(scan_dir, 'report.md', b'projected report\\n')",
      "    else:",
      "        project.assert_not_called(); writer.assert_not_called()",
      "check_report(['findings.json', 'coverage.json'], [], 'write', missing=True)",
      "check_report(['./report.md'], [], 'preserve')",
      "check_report(['REPORT.md'], ['REPORT.md'], 'preserve')",
      "check_report(['REPORT.md'], ['report.md'], 'preserve')",
      "check_report(['findings.json', 'coverage.json'], ['report.md', 'findings.json', 'coverage.json'], 'write')",
      "check_report(['REPORT.md'], ['REPORT.md', 'report.md'], 'write')",
      "check_report(['findings.json'], ['Report.md', 'findings.json'], 'write')",
      "check_report(['artifacts/report.md'], ['report.md'], 'write', separate_parent=True)",
      "check_report(['artifacts/report.md'], ['report.md'], 'ambiguous')",
      "check_report(['REPORT.md'], [], 'ambiguous')",
      "with patch.object(finalizer, 'write_report_projection') as report_only, patch.object(finalizer, 'finalize_scan') as full_finalizer, patch.object(finalizer, 'build_findings_export') as export, patch.object(finalizer, 'build_sarif_projection') as sarif, patch.object(sys, 'argv', ['finalizer', '--scan-dir', str(scan_dir), '--schema-dir', str(schema_dir), '--report-only']):",
      "    assert finalizer.main() == 0",
      "    report_only.assert_called_once_with(scan_dir, schema_dir)",
      "    full_finalizer.assert_not_called(); export.assert_not_called(); sarif.assert_not_called()",
      "fingerprints = {'algorithm': finalizer.FINGERPRINT_ALGORITHM, 'primary': 'derived'}",
      "finding = {'findingId': 'finding', 'occurrenceId': 'occurrence', 'fingerprints': {**fingerprints, 'future': 'preserved'}}",
      "with patch.object(finalizer, '_derived_finding_identity_rows', return_value=[('finding', finding, 'finding', 'occurrence', fingerprints)]):",
      "    finalizer._validate_derived_finding_identities({}, {})",
      "    assert finding['fingerprints']['future'] == 'preserved'",
      "print(json.dumps({'reportOnly': True, 'sealedReportPreserved': True, 'sealedAliasPreserved': True, 'distinctEntriesRegenerated': True, 'ambiguousAliasRejected': True, 'knownFingerprintsOnly': True}))",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts")],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      reportOnly: true,
      sealedReportPreserved: true,
      sealedAliasPreserved: true,
      distinctEntriesRegenerated: true,
      ambiguousAliasRejected: true,
      knownFingerprintsOnly: true,
    });
  });

  test("accepts large reports, schemas, source files, and late source lines", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const program = [
      "import io, json, pathlib, sys, tempfile",
      "sys.path.insert(0, sys.argv[1])",
      "import finalize_scan_contract as finalizer",
      "import workbench_source_excerpt as excerpts",
      "document = finalizer._contract_json_bytes('scan-manifest.json', {'metadata': 'x' * (16 * 1024 * 1024)})",
      "nested = 0",
      "for _ in range(258): nested = [nested]",
      "finalizer._require_safe_json_value(nested, 'nested')",
      "with tempfile.TemporaryDirectory() as directory:",
      "    schema = pathlib.Path(directory) / 'large.schema.json'",
      "    schema.write_text(json.dumps({'type': 'object', 'description': 'x' * (4 * 1024 * 1024), 'allOf': [{'type': 'object'}] * 129}))",
      "    finalizer.validate_against_schema({'safe': True}, schema)",
      "    source = b'x' * (1024 * 1024 + 1)",
      "    excerpts.git_bytes = lambda *args: source",
      "    target = pathlib.Path(directory).resolve()",
      "    excerpt = excerpts.scanned_source_text({'target_revision': 'deadbeef', 'target_snapshot_digest': None}, target, 'large.py')",
      "    hashes = finalizer._github_line_hashes(io.StringIO('line\\n' * 100001), {100001})",
      "    print(json.dumps({'documentBytes': len(document), 'sourceBytes': len(excerpt), 'lateSourceLine': 100001 in hashes, 'unsafePathRejected': excerpts.safe_source_path(target, '../outside') is None}))",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts")],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toMatchObject({
      documentBytes: expect.any(Number),
      sourceBytes: 1024 * 1024 + 1,
      lateSourceLine: true,
      unsafePathRejected: true,
    });
  });

  test("preserves bounded remediation tests and preventive controls", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const program = [
      "import json, sys",
      "sys.path.insert(0, sys.argv[1])",
      "from finding_preview import bounded_finding_details",
      "diagnostics = {'rootCause': {'summary': 'Missing authorization check.'}, 'validation': {'summary': 'An untrusted request reaches the protected resource.'}, 'attackPath': {'narrative': 'The request bypasses the authorization boundary.'}, 'codeEvidence': [{'id': 'evidence', 'label': 'Missing check', 'path': 'example.py', 'startLine': 1, 'code': 'return resource', 'explanation': 'No authorization check runs.'}], 'evidence': 'The protected resource was exposed.', 'evidenceExcerpt': 'return resource'}",
      "details = {'remediationTests': [f'test-{index}' for index in range(40)], 'preventiveControls': [f'control-{index}' for index in range(40)]}",
      "large = {**diagnostics, 'preventiveControls': ['x' * 900 for _ in range(20)], 'remediationTests': ['Verify authorization.'], 'writeup': {'reportPath': 'findings/example/example.md'}, 'provenance': {'source': 'scan'}, 'severity': {'level': 'high', 'rationale': 'Verified impact'}, 'status': 'open', 'taxonomy': {'category': 'injection', 'cwe': ['CWE-79']}}",
      "code_evidence = [{'id': f'evidence-{index}', 'label': 'example', 'path': 'example.py', 'startLine': 1, 'code': 'c' * 1500, 'explanation': 'e' * 1500} for index in range(4)]",
      "rich = {'rootCause': {'summary': 'r' * 2000}, 'validation': {'summary': 'v' * 3000}, 'attackPath': {'narrative': 'a' * 4000}, 'codeEvidence': code_evidence, 'evidenceExcerpt': 'e' * 8000, 'identity': {'anchor': 'finding'}, 'preventiveControls': ['Centralize authorization.'], 'remediationTests': ['Verify authorization.']}",
      "boundary = {**diagnostics, 'remediationTests': ['x'] * 4000, 'preventiveControls': ['Keep authorization centralized.']}",
      "unicode_boundary = {**diagnostics, 'remediationTests': ['😀'] * 2000, 'preventiveControls': ['🛡'] * 2000}",
      "empty_controls = {**diagnostics, 'remediationTests': ['x'] * 4000, 'preventiveControls': []}",
      "empty_tests = {**diagnostics, 'remediationTests': [], 'preventiveControls': ['control'] * 4000}",
      "oversized_metadata = {**diagnostics, 'confidence': {'level': 'high', 'rationale': 'x' * 17000}, 'remediationTests': ['Verify authorization.'], 'preventiveControls': ['Centralize authorization.']}",
      "oversized_guidance = {'rootCause': {'summary': 'root'}, 'validation': {'summary': 'validation'}, 'attackPath': {'narrative': 'attack'}, 'codeEvidence': [{'id': 'evidence', 'label': 'evidence', 'path': 'example.py', 'startLine': 1, 'code': 'x', 'explanation': 'evidence'}], 'evidence': 'legacy', 'evidenceExcerpt': 'excerpt', 'remediationTests': ['x' * 7800], 'preventiveControls': ['y' * 7930]}",
      "nested_boundary = {'remediationTests': ['x'] * 3937, 'rootCause': {'summary': 'r' * 178, 'detail': {'x': {'y': 'z'}}}}",
      "projections = {key: bounded_finding_details(value) for key, value in {'details': details, 'large': large, 'rich': rich, 'boundary': boundary, 'unicodeBoundary': unicode_boundary, 'emptyControls': empty_controls, 'emptyTests': empty_tests, 'oversizedMetadata': oversized_metadata, 'oversizedGuidance': oversized_guidance, 'nestedBoundary': nested_boundary}.items()}",
      "print(json.dumps({'projections': projections, 'bytes': {key: len(json.dumps(value, separators=(',', ':')).encode()) for key, value in projections.items()}}))",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts")],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    const { projections, bytes } = JSON.parse(
      new TextDecoder().decode(result.stdout),
    ) as {
      projections: {
        details: Record<string, unknown>;
        large: Record<string, unknown>;
        rich: Record<string, unknown>;
        boundary: { remediationTests: string[]; preventiveControls: string[] };
        unicodeBoundary: {
          remediationTests: string[];
          preventiveControls: string[];
        };
        emptyControls: {
          remediationTests: string[];
          preventiveControls: string[];
        };
        emptyTests: {
          remediationTests: string[];
          preventiveControls: string[];
        };
        oversizedMetadata: {
          remediationTests: string[];
          preventiveControls: string[];
        };
        oversizedGuidance: {
          remediationTests: string[];
          preventiveControls: string[];
        };
        nestedBoundary: {
          remediationTests: string[];
          rootCause: { summary: string };
        };
      };
      bytes: Record<string, number>;
    };
    expect(projections.details).toEqual({
      preventiveControls: Array.from(
        { length: 40 },
        (_, index) => `control-${index}`,
      ),
      remediationTests: Array.from(
        { length: 40 },
        (_, index) => `test-${index}`,
      ),
    });
    expect(projections.large).toMatchObject({
      writeup: { reportPath: "findings/example/example.md" },
      provenance: { source: "scan" },
      remediationTests: ["Verify authorization."],
      severity: { level: "high", rationale: "Verified impact" },
      status: "open",
      taxonomy: { category: "injection", cwe: ["CWE-79"] },
    });
    expect(projections.rich).toMatchObject({
      identity: { anchor: "finding" },
      preventiveControls: ["Centralize authorization."],
      remediationTests: ["Verify authorization."],
    });
    for (const finding of [
      projections.large,
      projections.rich,
      projections.boundary,
      projections.unicodeBoundary,
      projections.emptyControls,
      projections.emptyTests,
      projections.oversizedMetadata,
      projections.oversizedGuidance,
    ]) {
      expect(finding).toMatchObject({
        rootCause: { summary: expect.any(String) },
        validation: { summary: expect.any(String) },
        attackPath: { narrative: expect.any(String) },
        codeEvidence: expect.arrayContaining([
          expect.objectContaining({
            id: expect.any(String),
            path: "example.py",
          }),
        ]),
      });
    }
    for (const finding of [
      projections.large,
      projections.boundary,
      projections.unicodeBoundary,
      projections.emptyControls,
      projections.emptyTests,
    ]) {
      expect(finding).toMatchObject({
        evidence: "The protected resource was exposed.",
        evidenceExcerpt: "return resource",
      });
    }
    expect(projections.rich).toHaveProperty("evidenceExcerpt");
    expect(projections.oversizedGuidance).toMatchObject({
      evidence: "legacy",
      evidenceExcerpt: "excerpt",
    });
    expect(
      projections.boundary.remediationTests.every((value) => value !== ""),
    ).toBe(true);
    expect(projections.boundary.preventiveControls).toEqual([
      "Keep authorization centralized.",
    ]);
    expect(projections.unicodeBoundary.remediationTests.length).toBeGreaterThan(
      0,
    );
    expect(
      projections.unicodeBoundary.preventiveControls.every(
        (value) => value === "🛡",
      ),
    ).toBe(true);
    expect(
      projections.unicodeBoundary.preventiveControls.length,
    ).toBeGreaterThan(0);
    expect(projections.emptyControls.preventiveControls).toEqual([]);
    expect(projections.emptyControls.remediationTests.length).toBeGreaterThan(
      20,
    );
    expect(projections.emptyTests.remediationTests).toEqual([]);
    expect(projections.emptyTests.preventiveControls.length).toBeGreaterThan(
      20,
    );
    expect(projections.nestedBoundary.rootCause.summary).toContain("r");
    expect(Object.values(bytes).every((value) => value <= 16_000)).toBe(true);
  });
});
