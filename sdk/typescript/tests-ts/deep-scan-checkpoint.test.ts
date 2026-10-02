import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import {
  compositionCheckpointFromWorkbench,
  decodeDeepScanCheckpoint,
  newDeepScanCheckpoint,
  loadDeepScanCheckpointSummary,
} from "../src/deep-scan-checkpoint.js";

test("current checkpoint decode retains extension fields", () => {
  const document = {
    ...newDeepScanCheckpoint("2026-01-01T00:00:00Z"),
    extension: { retain: 1 },
  };
  expect(decodeDeepScanCheckpoint(document)).toBe(document);
});

test.each([1, 2])(
  "live version %i requires its original runtime",
  (version) => {
    expect(() => decodeDeepScanCheckpoint({ version })).toThrow(
      "original version",
    );
  },
);

test("saved historical summaries remain readable without reviving old execution", () => {
  expect(compositionCheckpointFromWorkbench({})).toBeNull();
  const historical = {
    ...newDeepScanCheckpoint("2026-01-01T00:00:00Z"),
    version: 2,
    terminalReason: "capped",
  };
  expect(
    compositionCheckpointFromWorkbench({ compositionCheckpoint: historical }),
  ).toMatchObject({ version: 2, terminalReason: "capped" });
});

test.each([
  "empty",
  "no-leaf",
  "missing-root",
  "linked-parent",
  "dangling-parent",
  "linked-root",
  "parent-file",
  "malformed",
])("optional checkpoint preserves path errors for %s", async (layout) => {
  const temporary = await mkdtemp(join(tmpdir(), "checkpoint-path-"));
  const scanDir = join(temporary, "scan");
  try {
    if (layout !== "missing-root") await mkdir(scanDir, { mode: 0o700 });
    if (layout === "linked-root") {
      const target = join(temporary, "target");
      await mkdir(target, { mode: 0o700 });
      await rm(scanDir, { recursive: true });
      await symlink(target, scanDir, "junction");
    } else if (layout !== "empty" && layout !== "missing-root") {
      await mkdir(join(scanDir, "artifacts"), { mode: 0o700 });
      const parent = join(scanDir, "artifacts/deep-scan");
      if (layout === "linked-parent" || layout === "dangling-parent") {
        const target = join(temporary, "target");
        if (layout === "linked-parent") await mkdir(target, { mode: 0o700 });
        await symlink(target, parent, "junction");
      } else if (layout === "parent-file") {
        await writeFile(parent, "synthetic file");
      } else {
        await mkdir(parent, { mode: 0o700 });
        if (layout === "malformed")
          await writeFile(join(parent, "checkpoint.json"), "{");
      }
    }
    if (layout === "empty" || layout === "no-leaf") {
      expect(await loadDeepScanCheckpointSummary(scanDir)).toBeNull();
    } else {
      await expect(loadDeepScanCheckpointSummary(scanDir)).rejects.toThrow();
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
