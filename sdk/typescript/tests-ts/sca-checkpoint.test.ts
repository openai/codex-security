import * as fs from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { initialOsvScanResult } from "../src/sca-osv.js";
import { renderScaReport } from "../src/sca-report.js";
import { dependencyScanResult, saveDependencyScan } from "../src/sca.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const { create, cleanup } = createTemporaryDirectories();
afterEach(cleanup);

async function checkpoint() {
  const outputDir = await create("sca-checkpoint-");
  return dependencyScanResult(
    initialOsvScanResult(outputDir),
    { path: "synthetic", revision: null, dirty: false },
    outputDir,
  );
}

test("replaces an existing dependency report when its reader finishes", async () => {
  const result = await checkpoint();
  const report = join(result.outputDir, "report.md");
  await fs.writeFile(report, "previous checkpoint");
  await using reader = await fs.open(report, "r");
  const rename = fs.rename;
  using install = spyOn(fs, "rename").mockImplementation(async (from, to) => {
    try {
      await rename(from, to);
    } finally {
      if (to === report) await reader.close();
    }
  });

  await saveDependencyScan(result);

  expect(install).toHaveBeenCalled();
  expect(await fs.readFile(report, "utf8")).toBe(renderScaReport(result));
  expect((await fs.readdir(result.outputDir)).sort()).toEqual([
    "report.md",
    "sca-result.json",
  ]);
});

test("cleans staged dependency reports when replacement fails", async () => {
  const result = await checkpoint();
  const report = join(result.outputDir, "report.md");
  await fs.mkdir(report);
  await fs.writeFile(join(report, "previous"), "keep");

  await expect(saveDependencyScan(result)).rejects.toThrow();

  expect(await fs.readFile(join(report, "previous"), "utf8")).toBe("keep");
  expect((await fs.readdir(result.outputDir)).sort()).toEqual([
    "report.md",
    "sca-result.json",
  ]);
});
