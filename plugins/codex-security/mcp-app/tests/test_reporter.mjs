import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";

const packageJson = JSON.parse(
  await readFile(new URL("../package.json", import.meta.url), "utf8"),
);

for (const { blocked, fail } of [
  { blocked: undefined, fail: false },
  { blocked: "directory", fail: false },
  { blocked: "file", fail: false },
  { blocked: undefined, fail: true },
  { blocked: "directory", fail: true },
]) {
  const root = await mkdtemp(join(tmpdir(), "codex-security-mcp-report-"));
  try {
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({
        scripts: { "test:mcp": packageJson.scripts["test:mcp"] },
      }),
    );
    await mkdir(join(root, "scripts"));
    await copyFile(
      new URL("../scripts/test_reporter.mjs", import.meta.url),
      join(root, "scripts", "test_reporter.mjs"),
    );
    await mkdir(join(root, "tests"));
    if (blocked === "directory") {
      await writeFile(join(root, "reports"), "synthetic blocker");
    } else if (blocked === "file") {
      await mkdir(join(root, "reports", "junit.xml"), { recursive: true });
    }
    const probe = join(root, "tests", "test_probe.mjs");
    await writeFile(
      probe,
      fail ? 'throw new Error("synthetic test failure");\n' : "",
    );
    const child = spawnSync(process.execPath, ["--run", "test:mcp"], {
      cwd: root,
      env: {
        ...process.env,
        NODE_TEST_CONTEXT: undefined,
        PATH: `${dirname(process.execPath)}${delimiter}${process.env.PATH ?? ""}`,
      },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(child.error, undefined);
    assert.equal(child.status, fail ? 1 : 0, child.stderr);
    assert.match(child.stdout, fail ? /not ok 1/ : /ok 1/);
    if (blocked) {
      assert.match(
        child.stderr,
        /Could not write the optional MCP test report/,
      );
      if (blocked === "directory") {
        assert.equal(
          await readFile(join(root, "reports"), "utf8"),
          "synthetic blocker",
        );
      }
    } else {
      const xml = await readFile(join(root, "reports", "junit.xml"), "utf8");
      assert.match(xml, /<testcase /);
      assert.equal(xml.includes("<failure "), fail);
      assert.doesNotMatch(
        child.stderr,
        /Could not write the optional MCP test report/,
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
