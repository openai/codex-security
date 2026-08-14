import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

describe("bundled scan report and source limits", () => {
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
      "details = {'remediationTests': [f'test-{index}' for index in range(40)], 'preventiveControls': [f'control-{index}' for index in range(40)]}",
      "large = {'preventiveControls': ['x' * 900 for _ in range(20)], 'remediationTests': ['Verify authorization.'], 'writeup': {'reportPath': 'findings/example/example.md'}, 'provenance': {'source': 'scan'}, 'severity': {'level': 'high', 'rationale': 'Verified impact'}, 'status': 'open', 'taxonomy': {'category': 'injection', 'cwe': ['CWE-79']}}",
      "code_evidence = [{'id': f'evidence-{index}', 'label': 'example', 'path': 'example.py', 'startLine': 1, 'code': 'c' * 1500, 'explanation': 'e' * 1500} for index in range(4)]",
      "rich = {'rootCause': {'summary': 'r' * 2000}, 'validation': {'summary': 'v' * 3000}, 'attackPath': {'narrative': 'a' * 4000}, 'codeEvidence': code_evidence, 'evidenceExcerpt': 'e' * 8000, 'identity': {'anchor': 'finding'}, 'preventiveControls': ['Centralize authorization.'], 'remediationTests': ['Verify authorization.']}",
      "boundary = {'remediationTests': ['x'] * 4000, 'preventiveControls': ['Keep authorization centralized.']}",
      "unicode_boundary = {'remediationTests': ['😀'] * 2000, 'preventiveControls': ['🛡'] * 2000}",
      "nested_boundary = {'remediationTests': ['x'] * 3937, 'rootCause': {'summary': 'r' * 178, 'detail': {'x': {'y': 'z'}}}}",
      "projections = {key: bounded_finding_details(value) for key, value in {'details': details, 'large': large, 'rich': rich, 'boundary': boundary, 'unicodeBoundary': unicode_boundary, 'nestedBoundary': nested_boundary}.items()}",
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
    expect(projections.nestedBoundary.rootCause.summary).toContain("r");
    expect(Object.values(bytes).every((value) => value <= 16_000)).toBe(true);
  });
});
