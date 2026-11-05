import { readJson, writeJson } from "./support/json.ts";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { delimiter, dirname, join } from "node:path";

const packageJson = await readJson(import.meta.dirname, "../package.json");

for (const { blocked, fail } of [
  { blocked: undefined, fail: false },
  { blocked: "directory", fail: false },
  { blocked: "file", fail: false },
  { blocked: undefined, fail: true },
  { blocked: "directory", fail: true },
]) {
  const root = await temporaryDirectory("codex-security-mcp-report-");
  try {
    await writeJson(join(root, "package.json"), {
      scripts: {
        "test:mcp": packageJson.scripts["test:mcp"],
      },
    });
    await mkdir(join(root, "scripts"));
    await copyFile(
      new URL("../scripts/test_reporter.mts", import.meta.url),
      join(root, "scripts", "test_reporter.mts"),
    );
    await mkdir(join(root, "tests"));
    if (blocked === "directory") {
      await writeFile(join(root, "reports"), "synthetic blocker");
    } else if (blocked === "file") {
      await mkdir(join(root, "reports", "junit.xml"), { recursive: true });
    }
    await writeFile(
      join(root, "tests", "test_probe.ts"),
      `const fail: boolean = ${fail};
if (fail) throw new Error("synthetic test failure");
`,
    );
    for (const file of ["test_probe.js", "test_removed.js"]) {
      await writeFile(
        join(root, "tests", file),
        'throw new Error("stale JavaScript test executed");\n',
      );
    }
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
