import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("repository and scoped inventories exclude a directory and retain a similar prefix", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "scan-exclusions-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repo = join(root, "repo");
  for (const dir of ["src", "examples/nested", "examples-other"]) {
    await mkdir(join(repo, dir), { recursive: true });
    await writeFile(join(repo, dir, "app.py"), "print('fixture')\n");
  }
  const scopes = join(root, "scopes.json");
  await writeFile(scopes, '["."]');
  for (const command of ["generate-in-scope-files", "make-repo-scope-input"]) {
    const out = join(root, command + ".txt");
    const helper = join(
      import.meta.dirname,
      "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
    );
    const output = execFileSync(
      process.execPath,
      [
        helper,
        command,
        "--repo",
        repo,
        "--out",
        out,
        ...(command === "generate-in-scope-files"
          ? ["--scope", "."]
          : ["--scopes-file", scopes]),
      ],
      {
        encoding: "utf8",
        env: { ...process.env, CODEX_SECURITY_EXCLUDE_PATHS: '["examples"]' },
      },
    );
    assert.match(output, /2 (in-scope files|scoped paths)/);
    const content = await readFile(out, "utf8");
    assert.match(content, /src\/app.py/);
    assert.match(content, /examples-other\/app.py/);
    assert.doesNotMatch(content, /examples\/nested/);
  }
});
