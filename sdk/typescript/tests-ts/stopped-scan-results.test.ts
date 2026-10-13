import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";

// Recovery semantics live in the Python suite. Keep the selected interpreter boundary here.
test("selected Python publishes an ordinary stopped scan checkpoint", () => {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const root = mkdtempSync(join(tmpdir(), "codex-security-stopped-scan-"));
  try {
    const fixture = fileURLToPath(
      new URL(
        "../../../plugins/codex-security/tests/fixtures/runtime/stopped_scan.py",
        import.meta.url,
      ),
    );
    const result = spawnSync(python!, ["-I", "-B", fixture, root], {
      encoding: "utf8",
    });
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      findingCount: 1,
      progressStatus: "failed",
      artifactFindingCount: 1,
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}, 30_000);
