import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("bundled finding previews normalize details without changing stored findings", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  const original = {
    attackPath: { likelihood: "medium" },
    code_evidence: [{ id: "source", code: "synthetic_source()" }],
    rootCause: { summary: "Synthetic root cause." },
  };
  const program = [
    "import json, sys",
    "sys.path.insert(0, sys.argv[1])",
    "from finding_preview import bounded_finding_details",
    "original = json.loads(sys.stdin.read())",
    "projected = bounded_finding_details(original)",
    "print(json.dumps({'projected': projected, 'original': original}))",
  ].join("\n");
  const result = Bun.spawnSync(
    [python!, "-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts")],
    {
      stdin: new TextEncoder().encode(JSON.stringify(original)),
      stdout: "pipe",
      stderr: "pipe",
    },
  );

  expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
  expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
    projected: {
      ...original,
      attackPath: { likelihood: { level: "medium" } },
    },
    original,
  });
});
