import { test, expect, spyOn, afterEach } from "bun:test";
import type { BigIntStats, Stats } from "node:fs";
import { mkdir, rename, writeFile, type FileHandle } from "node:fs/promises";
import { join } from "node:path";
import { readScanFile } from "../src/contract.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

for (const [name, originalId, replacementId] of [
  ["distinct exactly represented identities", 100n, 101n],
  ["distinct identities with equal Number values", 2n ** 60n, 2n ** 60n + 1n],
  ["an unchanged large identity", 2n ** 60n, 2n ** 60n],
] as const) {
  test(`checked scan file preserves ${name}`, async () => {
    const title = `checked scan file preserves ${name}`;
    if (runTestInSubprocess(import.meta.path, title)) return;
    const root = await temporaryDirectory();
    const scanDir = join(root, "scan");
    await mkdir(scanDir, { mode: 0o700 });
    const path = join(scanDir, "document.json");
    await writeFile(path, "original data");
    const files = await import("node:fs/promises");
    const originalLstat = files.lstat;
    const originalRealpath = files.realpath;
    const originalOpen = files.open;
    let replaced = false;
    const handles: FileHandle[] = [];
    const withIdentity = (metadata: Stats | BigIntStats, identity: bigint) => {
      Object.defineProperty(metadata, "ino", {
        value: typeof metadata.ino === "bigint" ? identity : Number(identity),
      });
      return metadata;
    };
    const inspecting = spyOn(files, "lstat").mockImplementation((async (
      ...args: Parameters<typeof originalLstat>
    ) => {
      const metadata = await originalLstat(...args);
      return args[0] === path
        ? withIdentity(metadata, replaced ? replacementId : originalId)
        : metadata;
    }) as typeof originalLstat);
    const resolving = spyOn(files, "realpath").mockImplementation((async (
      ...args: Parameters<typeof originalRealpath>
    ) => {
      const canonical = await originalRealpath(...args);
      if (args[0] === path && !replaced && originalId !== replacementId) {
        await rename(path, `${path}.original`);
        await writeFile(path, "replacement data");
        replaced = true;
      }
      return canonical;
    }) as typeof originalRealpath);
    const opening = spyOn(files, "open").mockImplementation(async (...args) => {
      const file = await originalOpen(...args);
      if (args[0] === path) {
        handles.push(file);
        const originalStat = file.stat.bind(file);
        spyOn(file, "stat").mockImplementation((async (
          ...options: Parameters<typeof originalStat>
        ) =>
          withIdentity(
            await originalStat(...options),
            replaced ? replacementId : originalId,
          )) as typeof originalStat);
      }
      return file;
    });
    try {
      if (originalId === replacementId) {
        expect(
          (await readScanFile(scanDir, "document.json", "fixture")).toString(),
        ).toBe("original data");
      } else {
        await expect(
          readScanFile(scanDir, "document.json", "fixture"),
        ).rejects.toThrow("expected the checked regular file");
        expect(replaced).toBe(true);
      }
      expect(handles).toHaveLength(1);
      expect(handles[0]!.fd).toBe(-1);
    } finally {
      inspecting.mockRestore();
      resolving.mockRestore();
      opening.mockRestore();
    }
  });
}
