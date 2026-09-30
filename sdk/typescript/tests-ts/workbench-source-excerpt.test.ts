import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

describe("workbench source excerpts", () => {
  test("does not read HEAD for mutable or unknown diff targets", () => {
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();

    const program = [
      "import json, sys",
      "from pathlib import Path",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_source_excerpt as source_excerpt",
      "calls = []",
      "source_excerpt.safe_source_path = lambda target, path: target / path",
      "def fake_git_bytes(target, *args):",
      "    calls.append(list(args))",
      "    return b'committed source\\n'",
      "source_excerpt.git_bytes = fake_git_bytes",
      "def read(kind):",
      "    scan = {'mode': 'diff', 'diff_target_kind': kind, 'target_revision': 'abc123', 'target_snapshot_digest': None}",
      "    return source_excerpt.scanned_source_text(scan, Path('/repo'), 'src/app.py')",
      "results = {kind or 'unknown': read(kind) for kind in ('working_tree', None, 'commit', 'range')}",
      "print(json.dumps({'results': results, 'calls': calls}))",
    ].join("\n");
    const result = Bun.spawnSync(
      [
        python!,
        "-I",
        "-B",
        "-c",
        program,
        join(PLUGIN_ROOT, "scripts"),
      ],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      results: {
        working_tree: null,
        unknown: null,
        commit: "committed source\n",
        range: "committed source\n",
      },
      calls: [
        ["cat-file", "blob", "abc123:src/app.py"],
        ["cat-file", "blob", "abc123:src/app.py"],
      ],
    });
  });
});
