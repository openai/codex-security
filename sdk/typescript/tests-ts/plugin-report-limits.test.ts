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
});
