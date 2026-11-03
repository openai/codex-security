import { afterEach, expect, spyOn, test } from "bun:test";
import { chmodSync, mkdirSync, renameSync, writeFileSync } from "node:fs";
import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type {
  ScanReadFile,
  ScanReadRoot,
} from "../../../plugins/codex-security/native/scan-read-binding.mjs";
import { loadContract, readScanFile } from "../src/contract.js";
import { ContractValidationError } from "../src/errors.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { scanReadBinding } from "./support/scan-read-binding.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-directory-identity-",
);
afterEach(cleanup);

function observeRoot(onOpen: (root: ScanReadRoot) => void) {
  const binding = scanReadBinding();
  const open = binding.openScanReadRoot;
  return spyOn(binding, "openScanReadRoot").mockImplementation((path) => {
    const root = open(path);
    onOpen(root);
    return root;
  });
}

test.each(["after opening the root", "between documents"] as const)(
  "keeps the scan bound to the same directory %s",
  async (when) => {
    const title = `keeps the scan bound to the same directory ${when}`;
    if (runTestInSubprocess(import.meta.path, title)) return;
    const root = await temporaryDirectory();
    const scan = join(root, "scan");
    const replacement = join(root, "replacement");
    await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scan, {
      recursive: true,
    });
    chmodSync(scan, 0o700);
    await cp(scan, replacement, { recursive: true });
    const manifestPath = join(replacement, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    const originalName = manifest.scan.target.displayName;
    manifest.scan.target.displayName = "replacement";
    await writeFile(manifestPath, JSON.stringify(manifest));

    let attempted = false;
    let held: ScanReadRoot | undefined;
    const swap = () => {
      attempted = true;
      const move = () => renameSync(scan, join(root, "original"));
      if (process.platform === "win32") expect(move).toThrow();
      else {
        move();
        renameSync(replacement, scan);
      }
    };
    const opening = observeRoot((reader) => {
      held = reader;
      if (when === "after opening the root") return swap();
      const open = reader.openFile.bind(reader);
      let readManifest = false;
      spyOn(reader, "openFile").mockImplementation((name) => {
        if (name === "scan-manifest.json") readManifest = true;
        if (name === "findings.json" && !attempted) {
          expect(readManifest).toBe(true);
          swap();
        }
        return open(name);
      });
    });
    try {
      const result = loadContract(scan, { pluginRoot: PLUGIN_ROOT });
      if (process.platform === "win32") {
        expect((await result).manifest.scan.target.displayName).toBe(
          originalName,
        );
      } else
        await expect(result).rejects.toBeInstanceOf(ContractValidationError);
      expect(attempted).toBe(true);
      expect(() => held!.verify()).toThrow(/closed/i);
    } finally {
      opening.mockRestore();
    }
  },
);

const parentSwaps =
  process.platform === "win32"
    ? ["replacement"]
    : ["replacement", "retained leaf"];
test.each(parentSwaps)(
  "reads the held leaf across a parent rename: %s",
  async (kind) => {
    const title = `reads the held leaf across a parent rename: ${kind}`;
    if (runTestInSubprocess(import.meta.path, title)) return;
    const scan = await temporaryDirectory();
    const parent = join(scan, "artifacts");
    const moved = join(scan, "moved");
    const leaf = join(parent, "report.md");
    await mkdir(parent);
    await writeFile(leaf, "original");
    let held: ScanReadFile | undefined;
    const opening = observeRoot((reader) => {
      const open = reader.openFile.bind(reader);
      spyOn(reader, "openFile").mockImplementation((name) => {
        const file = open(name);
        if (file === null) throw new Error("Missing fixture");
        held = file;
        const move = () => renameSync(parent, moved);
        if (process.platform === "win32") expect(move).toThrow();
        else {
          move();
          mkdirSync(parent);
          if (kind === "retained leaf")
            renameSync(join(moved, "report.md"), leaf);
          else writeFileSync(leaf, "replacement");
        }
        return file;
      });
    });
    try {
      const bytes = await readScanFile(scan, "artifacts/report.md", "report");
      expect(bytes.toString()).toBe("original");
      expect(() => held!.read(1)).toThrow(/closed/i);
    } finally {
      opening.mockRestore();
    }
    if (process.platform === "win32") {
      renameSync(parent, moved);
      mkdirSync(parent);
      writeFileSync(leaf, "replacement");
    }
    const current = await readScanFile(scan, "artifacts/report.md", "report");
    expect(current.toString()).toBe(
      kind === "retained leaf" ? "original" : "replacement",
    );
  },
);
