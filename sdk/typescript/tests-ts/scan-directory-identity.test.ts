import { afterEach, expect, spyOn, test } from "bun:test";
import {
  chmod,
  cp,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
  type FileHandle,
} from "node:fs/promises";
import type { BigIntStats, Stats } from "node:fs";
import { join } from "node:path";
import { loadContract, readScanFile } from "../src/contract.js";
import { ContractValidationError } from "../src/errors.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-directory-identity-",
);
afterEach(cleanup);
const scenarios = [
  "initial-root",
  "accepted-root",
  "between-documents",
  "parent-before-leaf",
  "parent-retains-leaf",
] as const;
const identities = [
  ["small-distinct", 100n, 101n],
  ["rounded-distinct", 2n ** 60n, 2n ** 60n + 1n],
  ["unchanged", 2n ** 60n, 2n ** 60n],
] as const;

for (const [kind, originalId, replacementId] of identities) {
  // Without a swap, the hooks all read the same root or parent directory.
  const cases =
    kind === "unchanged"
      ? (["initial-root", "parent-retains-leaf"] as const)
      : scenarios;
  for (const scenario of cases) {
    const title = `checked scan directory ${scenario} preserves ${kind} identities`;
    test(title, async () => {
      if (runTestInSubprocess(import.meta.path, title)) return;
      const root = await temporaryDirectory();
      const scanDir = join(root, "scan");
      const isParent = scenario.startsWith("parent-");
      const swappedPath = isParent ? join(scanDir, "artifacts") : scanDir;
      const replacementPath = join(root, "replacement");
      const backupPath = join(root, "original");
      const leaf = join(swappedPath, "document.json");
      if (isParent) {
        await mkdir(swappedPath, { recursive: true, mode: 0o700 });
        await chmod(scanDir, 0o700);
        await mkdir(replacementPath, { mode: 0o700 });
        await writeFile(leaf, "original data");
        await writeFile(
          join(replacementPath, "document.json"),
          "replacement data",
        );
      } else {
        await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
          recursive: true,
        });
        await cp(
          join(PLUGIN_ROOT, "examples", "completed-scan"),
          replacementPath,
          { recursive: true },
        );
        await chmod(scanDir, 0o700);
        await chmod(replacementPath, 0o700);
        for (const [directory, name] of [
          [scanDir, "original contract"],
          [replacementPath, "replacement contract"],
        ]) {
          const path = join(directory!, "scan-manifest.json");
          const manifest = JSON.parse(await readFile(path, "utf8"));
          manifest.scan.target.displayName = name;
          await writeFile(path, JSON.stringify(manifest));
        }
      }
      const files = await import("node:fs/promises");
      const originalLstat = files.lstat;
      const originalRealpath = files.realpath;
      const originalOpen = files.open;
      const runtime = await import("../src/runtime.js");
      const originalAncestry = runtime.requireSecureOutputAncestry;
      const originalDirectory = await originalLstat(swappedPath, {
        bigint: true,
      });
      const replacementDirectory = await originalLstat(replacementPath, {
        bigint: true,
      });
      expect(originalDirectory.ino).not.toBe(replacementDirectory.ino);
      const originalLeaf = isParent
        ? await originalLstat(leaf, { bigint: true })
        : undefined;
      let swapped = false;
      const handles: FileHandle[] = [];
      const restoreCloses: Array<() => void> = [];
      const swap = async () => {
        if (swapped || kind === "unchanged") return;
        await rename(swappedPath, backupPath);
        await rename(replacementPath, swappedPath);
        if (scenario === "parent-retains-leaf") {
          await rm(leaf);
          await rename(join(backupPath, "document.json"), leaf);
        }
        swapped = true;
      };
      const withIdentity = (metadata: Stats | BigIntStats) => {
        Object.defineProperty(metadata, "ino", {
          value:
            typeof metadata.ino === "bigint"
              ? swapped
                ? replacementId
                : originalId
              : Number(swapped ? replacementId : originalId),
        });
        return metadata;
      };
      const inspecting = spyOn(files, "lstat").mockImplementation((async (
        ...args: Parameters<typeof originalLstat>
      ) => {
        if (scenario === "parent-before-leaf" && args[0] === leaf) await swap();
        const metadata = await originalLstat(...args);
        return args[0] === swappedPath ? withIdentity(metadata) : metadata;
      }) as typeof originalLstat);
      const resolving = spyOn(files, "realpath").mockImplementation((async (
        ...args: Parameters<typeof originalRealpath>
      ) => {
        const canonical = await originalRealpath(...args);
        if (
          (scenario === "initial-root" && args[0] === scanDir) ||
          (scenario === "parent-retains-leaf" && args[0] === leaf)
        )
          await swap();
        return canonical;
      }) as typeof originalRealpath);
      const ancestry = spyOn(
        runtime,
        "requireSecureOutputAncestry",
      ).mockImplementation(async (...args) => {
        await originalAncestry(...args);
        if (scenario === "accepted-root" && args[0] === scanDir) await swap();
      });
      const opening = spyOn(files, "open").mockImplementation(
        async (...args) => {
          const handle = await originalOpen(...args);
          handles.push(handle);
          if (
            scenario === "between-documents" &&
            args[0] === join(scanDir, "scan-manifest.json")
          ) {
            const close = handle.close.bind(handle);
            const closing = spyOn(handle, "close").mockImplementation(
              async () => {
                await close();
                await swap();
              },
            );
            restoreCloses.push(() => closing.mockRestore());
          }
          return handle;
        },
      );
      let value: string | undefined;
      let error: unknown;
      try {
        try {
          value = isParent
            ? (
                await readScanFile(
                  scanDir,
                  "artifacts/document.json",
                  "fixture",
                )
              ).toString()
            : (
                await loadContract(scanDir, {
                  pluginRoot: PLUGIN_ROOT,
                  expectedScanId: "scan_example_001",
                })
              ).manifest.scan.target.displayName;
        } catch (caught) {
          error = caught;
        }
        const finalDirectory = await originalLstat(swappedPath, {
          bigint: true,
        });
        const finalLeaf = isParent
          ? await originalLstat(leaf, { bigint: true })
          : undefined;
        expect(swapped).toBe(kind !== "unchanged");
        for (const handle of handles) expect(handle.fd).toBe(-1);
        if (isParent || scenario === "between-documents")
          expect(handles.length).toBeGreaterThan(0);
        if (kind === "unchanged") {
          expect(finalDirectory.ino).toBe(originalDirectory.ino);
          expect(error).toBeUndefined();
          expect(value).toBe(isParent ? "original data" : "original contract");
        } else {
          expect(finalDirectory.ino).toBe(replacementDirectory.ino);
          expect(error).toBeInstanceOf(ContractValidationError);
        }
        if (scenario === "parent-retains-leaf")
          expect(finalLeaf?.ino).toBe(originalLeaf?.ino);
      } finally {
        inspecting.mockRestore();
        resolving.mockRestore();
        opening.mockRestore();
        ancestry.mockRestore();
        for (const restore of restoreCloses) restore();
      }
    });
  }
}
