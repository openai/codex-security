import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadScanReadBinding,
  type ScanReadFile,
  type ScanReadRoot,
} from "./scan-read-binding.mjs";

export function scanReadProof(): Record<string, boolean> {
  const native = loadScanReadBinding();
  const fixture = realpathSync.native(
    mkdtempSync(join(tmpdir(), "codex-security-scan-read-")),
  );
  const pathBytes = (path: string) =>
    Buffer.from(path, process.platform === "win32" ? "utf16le" : "utf8");
  const scan = join(fixture, "scan");
  const artifacts = join(scan, "artifacts");
  const outside = join(fixture, "outside");
  const payload = Buffer.from("saved scan artifact\n");
  const roots: ScanReadRoot[] = [];
  const files: ScanReadFile[] = [];
  const openRoot = (path: string) => {
    const root = native.openScanReadRoot(pathBytes(path));
    roots.push(root);
    return root;
  };
  const openFile = (root: ScanReadRoot, path: string) => {
    const file = root.openFile(path);
    assert(file, `Expected ${path}`);
    files.push(file);
    return file;
  };
  const chunks = (file: ScanReadFile) => {
    const result: Buffer[] = [];
    for (;;) {
      const chunk = file.read(3);
      assert(chunk.length <= 3);
      if (chunk.length === 0) break;
      result.push(chunk);
    }
    return Buffer.concat(result);
  };
  try {
    mkdirSync(artifacts, { recursive: true, mode: 0o700 });
    mkdirSync(outside, { mode: 0o700 });
    writeFileSync(join(artifacts, "receipt.json"), payload);
    writeFileSync(join(outside, "receipt.json"), "outside scan");
    const root = openRoot(scan);
    assert.deepEqual(chunks(openFile(root, "artifacts/receipt.json")), payload);
    assert.equal(root.openFile("missing.json"), null);
    assert.equal(root.openFile("missing/receipt.json"), null);
    assert.throws(() => root.openFile("artifacts"), /regular|directory/i);
    for (const path of [
      "../outside/receipt.json",
      "/receipt.json",
      "artifacts\\receipt.json",
    ]) {
      assert.throws(() => root.openFile(path), /relative/i);
    }
    root.verify();
    for (const file of files) file.close();

    const held = openFile(root, "artifacts/receipt.json");
    const moved = join(scan, "moved-artifacts");
    if (process.platform === "win32") {
      assert.throws(() => renameSync(artifacts, moved));
      root.close();
      assert.throws(() => renameSync(scan, join(fixture, "moved-scan")));
      assert.throws(() => renameSync(artifacts, moved));
      assert.deepEqual(chunks(held), payload);
      held.close();
      renameSync(artifacts, moved);
      renameSync(moved, artifacts);
    } else {
      renameSync(artifacts, moved);
      symlinkSync(outside, artifacts, "dir");
      assert.deepEqual(chunks(held), payload);
      assert.throws(() => root.openFile("artifacts/receipt.json"));
      held.close();
      rmSync(artifacts);
      renameSync(moved, artifacts);
    }
    assert.throws(() => held.read(1), /closed/i);
    held.close();
    root.close();
    root.close();
    assert.throws(() => root.verify(), /closed/i);
    assert.throws(() => root.openFile("artifacts/receipt.json"), /closed/i);

    // A junction needs no symlink privilege and exercises the Windows reparse path.
    const link = join(scan, "linked");
    symlinkSync(
      outside,
      link,
      process.platform === "win32" ? "junction" : "dir",
    );
    const linkedRoot = openRoot(scan);
    assert.throws(() => linkedRoot.openFile("linked/receipt.json"));
    assert.throws(() => openRoot(link));
    linkedRoot.close();
    rmSync(link, { recursive: true });

    if (process.platform !== "win32") {
      const fifo = join(scan, "fifo");
      const created = spawnSync(
        "/bin/sh",
        ["-c", 'exec mkfifo "$1"', "scan-read-proof", fifo],
        { env: { ...process.env, PATH: "/usr/bin:/bin" }, encoding: "utf8" },
      );
      assert.equal(created.error, undefined);
      assert.equal(created.status, 0, created.stderr);
      // A missing O_NONBLOCK would hang inside openFile before checking its type.
      const fifoRead = spawnSync(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          `
            import assert from "node:assert/strict";
            const { loadScanReadBinding } = await import(process.argv[1]);
            const root = loadScanReadBinding().openScanReadRoot(Buffer.from(process.argv[2]));
            try {
              assert.throws(() => root.openFile("fifo"), /regular/i);
            } finally {
              root.close();
            }
          `,
          new URL("./scan-read-binding.mjs", import.meta.url).href,
          scan,
        ],
        { encoding: "utf8", timeout: 10_000 },
      );
      assert.equal(fifoRead.error, undefined);
      assert.equal(fifoRead.status, 0, fifoRead.stderr);

      // APFS cannot create this invalid-UTF-8 filename.
      if (process.platform === "linux") {
        const rawRootPath = Buffer.concat([
          Buffer.from(`${fixture}/raw-`),
          Buffer.from([255]),
        ]);
        mkdirSync(rawRootPath, { mode: 0o700 });
        writeFileSync(
          Buffer.concat([rawRootPath, Buffer.from("/receipt.json")]),
          payload,
        );
        const rawRoot = native.openScanReadRoot(rawRootPath);
        roots.push(rawRoot);
        assert.deepEqual(chunks(openFile(rawRoot, "receipt.json")), payload);
        rawRoot.close();
      }

      const fileLink = join(artifacts, "linked.json");
      symlinkSync("receipt.json", fileLink);
      const linkedFileRoot = openRoot(scan);
      assert.throws(() => linkedFileRoot.openFile("artifacts/linked.json"));
      linkedFileRoot.close();
      rmSync(fileLink);
      const alias = join(fixture, "alias");
      symlinkSync(scan, alias, "dir");
      assert.throws(() => openRoot(join(alias, "artifacts")), /canonical/i);

      const replacedRoot = openRoot(scan);
      const movedScan = join(fixture, "moved-scan");
      renameSync(scan, movedScan);
      mkdirSync(scan, { mode: 0o700 });
      writeFileSync(join(scan, "replacement.json"), "replacement");
      assert.throws(() => replacedRoot.verify(), /changed/i);
      assert.throws(
        () => replacedRoot.openFile("replacement.json"),
        /changed/i,
      );
      replacedRoot.close();
    }
    return {
      nestedChunkedReads: true,
      missingFiles: true,
      rejectsLinksAndNonRegularFiles: true,
      holdsOpenedFilesAcrossReplacement: true,
      verifiesHeldRoot: true,
      closesFilesAndRoots: true,
    };
  } finally {
    for (const file of files) file.close();
    for (const root of roots) root.close();
    rmSync(fixture, { recursive: true, force: true });
  }
}
