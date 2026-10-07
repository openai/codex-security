import assert from "node:assert/strict";
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, win32 } from "node:path";
import { setImmediate } from "node:timers/promises";
import { privateDirectoryProof } from "./proof-windows-acl.mjs";
import { wideProcessProof } from "./proof-windows-wide.mjs";
import { windowsFileSystem } from "./windows-files.mjs";
import {
  loadWindowsBinding,
  windowsFlags as flags,
  type WindowsHandle,
} from "./windows-binding.mjs";

assert.equal(process.platform, "win32", "Windows proof requires Windows");
const native = loadWindowsBinding();
const shareAll =
  flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE | flags.FILE_SHARE_DELETE;
const directoryFlags =
  flags.FILE_FLAG_BACKUP_SEMANTICS | flags.FILE_FLAG_OPEN_REPARSE_POINT;
const readWrite = flags.GENERIC_READ | flags.GENERIC_WRITE;
const pathBytes = (path: string) =>
  Buffer.from(win32.toNamespacedPath(path), "utf16le");
const checked = <T extends { error: number }>(result: T): T => {
  assert.equal(result.error, 0, `Win32 error ${result.error}`);
  return result;
};
const success = (error: number) => checked({ error });

function open(
  path: string | Buffer,
  access = readWrite | flags.DELETE | flags.FILE_READ_ATTRIBUTES,
  share = shareAll,
  disposition: number = flags.OPEN_EXISTING,
  attributes: number = flags.FILE_ATTRIBUTE_NORMAL,
): WindowsHandle {
  const result = checked(
    native.openWindowsFile(
      typeof path === "string" ? pathBytes(path) : path,
      access,
      share,
      disposition,
      attributes,
    ),
  );
  assert(result.handle);
  return result.handle;
}

function samePath(actual: Buffer, expected: string): void {
  assert.equal(
    win32.normalize(actual.toString("utf16le")).toLowerCase(),
    win32.toNamespacedPath(expected).toLowerCase(),
  );
}

function remove(path: string): void {
  const result = native.openWindowsFile(
    pathBytes(path),
    flags.DELETE,
    shareAll,
    flags.OPEN_EXISTING,
    directoryFlags,
  );
  if (result.error === 2 || result.error === 3) return;
  const handle = checked(result).handle!;
  try {
    success(handle.setDisposition(true));
  } finally {
    success(handle.close());
  }
}

function handleProof(root: string) {
  const held = new Set<WindowsHandle>();
  const rawPaths: string[] = [];
  const keep = (handle: WindowsHandle) => {
    held.add(handle);
    return handle;
  };
  const close = (handle: WindowsHandle) => {
    success(handle.close());
    held.delete(handle);
  };
  try {
    const path = join(root, "data");
    const file = keep(open(path, undefined, undefined, flags.CREATE_NEW));
    const payload = Buffer.from("handle I/O 🔐\n");
    const input = Buffer.concat([
      Buffer.from("ignore"),
      payload,
      Buffer.from("tail"),
    ]);
    assert.equal(
      checked(file.write(input, 6, payload.length)).value,
      payload.length,
    );
    assert.equal(checked(file.fileType()).value, 1);
    assert.equal(
      checked(file.attributes()).attributes & flags.FILE_ATTRIBUTE_DIRECTORY,
      0,
    );
    const reader = keep(open(path, flags.GENERIC_READ));
    const buffer = Buffer.alloc(payload.length + 6, 0x7e);
    assert.equal(
      checked(reader.read(buffer, 3, payload.length)).value,
      payload.length,
    );
    assert.deepEqual(buffer.subarray(3, -3), payload);
    assert.deepEqual(buffer.subarray(0, 3), Buffer.from("~~~"));
    assert.deepEqual(buffer.subarray(-3), Buffer.from("~~~"));
    assert.equal(checked(reader.read(buffer, 0, 1)).value, 0);
    close(reader);
    samePath(checked(file.finalPath(0)).path, path);
    samePath(checked(file.finalPath(flags.FILE_NAME_OPENED)).path, path);

    const identity = checked(file.identity());
    assert.match(identity.volume, /^\d+$/u);
    assert.equal(identity.fileId.length, 16);
    const link = join(root, "hard-link");
    linkSync(path, link);
    const second = keep(open(link));
    assert.deepEqual(checked(second.identity()), identity);
    close(second);
    assert.equal(
      native.openWindowsFile(
        pathBytes(path),
        flags.GENERIC_READ,
        0,
        flags.OPEN_EXISTING,
        0,
      ).error,
      32,
    );
    assert.equal(
      native.openWindowsFile(
        pathBytes(join(root, "missing")),
        flags.GENERIC_READ,
        shareAll,
        flags.OPEN_EXISTING,
        0,
      ).error,
      2,
    );
    for (const [offset, length] of [
      [-1, 1],
      [0, -1],
      [0.5, 1],
      [0, NaN],
      [0, Infinity],
      [0, 2 ** 32],
      [buffer.length, 1],
    ]) {
      assert.throws(() => file.read(buffer, offset!, length!));
      assert.throws(() => file.write(buffer, offset!, length!));
    }
    for (const invalid of [
      Buffer.from([0x41]),
      Buffer.from("bad\0path", "utf16le"),
    ]) {
      assert.throws(() =>
        native.openWindowsFile(invalid, 0, 0, flags.OPEN_EXISTING, 0),
      );
    }
    assert.throws(() =>
      native.openWindowsFile(
        pathBytes(path),
        readWrite,
        shareAll,
        flags.OPEN_EXISTING,
        flags.FILE_FLAG_OVERLAPPED,
      ),
    );
    const readOnly = keep(open(path, flags.GENERIC_READ));
    assert.equal(readOnly.write(buffer, 0, 1).error, 5);
    close(readOnly);
    close(file);
    success(file.close());
    assert.equal(file.read(buffer, 0, 1).error, 6);
    assert.equal(file.write(buffer, 0, 1).error, 6);

    const ancestor = join(root, "ancestor");
    const scan = join(ancestor, "scan");
    const child = join(scan, "child");
    for (const directory of [ancestor, scan, child]) {
      success(native.createWindowsDirectories(pathBytes(directory)));
    }
    const directories = [ancestor, scan, child].map((directory) =>
      keep(
        open(
          directory,
          flags.GENERIC_READ,
          flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE,
          flags.OPEN_EXISTING,
          directoryFlags,
        ),
      ),
    );
    for (const directory of [ancestor, scan, child]) {
      assert.equal(
        native.openWindowsFile(
          pathBytes(directory),
          flags.DELETE,
          shareAll,
          flags.OPEN_EXISTING,
          directoryFlags,
        ).error,
        32,
      );
      assert.throws(() => renameSync(directory, directory + "-moved"));
    }
    for (const handle of directories.reverse()) close(handle);
    renameSync(ancestor, ancestor + "-moved");
    const target = join(root, "target");
    mkdirSync(target);
    writeFileSync(join(target, "sentinel"), "target unchanged");
    symlinkSync(target, ancestor, "junction");
    const junction = keep(
      open(
        ancestor,
        flags.FILE_READ_ATTRIBUTES,
        shareAll,
        flags.OPEN_EXISTING,
        directoryFlags,
      ),
    );
    const attributes = checked(junction.attributes());
    assert(attributes.attributes & flags.FILE_ATTRIBUTE_REPARSE_POINT);
    assert(attributes.attributes & flags.FILE_ATTRIBUTE_DIRECTORY);
    assert.equal(attributes.reparseTag, 0xa0000003);
    const files = windowsFileSystem(native);
    const junctionEntry = files
      .entriesWithTypes(pathBytes(root))
      .find((entry) =>
        entry.name.equals(Buffer.from(basename(ancestor), "utf16le")),
      );
    assert(junctionEntry?.isDirectory());
    assert.equal(junctionEntry?.isSymbolicLink(), true);
    const junctionStat = files.stat(pathBytes(ancestor), false);
    assert(junctionStat.isDirectory());
    assert(junctionStat.isReparsePoint());
    assert(!junctionStat.isSymbolicLink());
    const targetStat = files.stat(pathBytes(ancestor));
    assert(targetStat.isDirectory());
    assert(!targetStat.isReparsePoint());
    samePath(
      checked(junction.finalPath(flags.FILE_NAME_OPENED)).path,
      ancestor,
    );
    const followed = keep(
      open(
        ancestor,
        flags.FILE_READ_ATTRIBUTES,
        shareAll,
        flags.OPEN_EXISTING,
        flags.FILE_FLAG_BACKUP_SEMANTICS,
      ),
    );
    samePath(checked(followed.finalPath(0)).path, target);
    assert(
      !(
        checked(followed.attributes()).attributes &
        flags.FILE_ATTRIBUTE_REPARSE_POINT
      ),
    );
    close(followed);
    close(junction);
    remove(ancestor);
    assert.equal(
      readFileSync(join(target, "sentinel"), "utf8"),
      "target unchanged",
    );

    const source = join(root, "source");
    const moved = join(root, "moved-source");
    const destination = join(root, "destination");
    const exact = keep(open(source, undefined, undefined, flags.CREATE_NEW));
    const exactPayload = Buffer.from("exact handle");
    assert.equal(
      checked(exact.write(exactPayload, 0, exactPayload.length)).value,
      exactPayload.length,
    );
    const exactIdentity = checked(exact.identity());
    renameSync(source, moved);
    writeFileSync(source, "replacement source");
    writeFileSync(destination, "old destination");
    assert([80, 183].includes(exact.rename(pathBytes(destination), false)));
    success(exact.rename(pathBytes(destination), true));
    assert.equal(readFileSync(destination, "utf8"), "exact handle");
    assert.equal(readFileSync(source, "utf8"), "replacement source");
    assert(!existsSync(moved));
    assert.deepEqual(checked(exact.identity()), exactIdentity);
    samePath(checked(exact.finalPath(0)).path, destination);
    renameSync(destination, moved);
    writeFileSync(destination, "replacement destination");
    success(exact.setDisposition(true));
    close(exact);
    assert(!existsSync(moved));
    assert.equal(readFileSync(destination, "utf8"), "replacement destination");

    let longDirectory = root;
    for (let index = 0; index < 5; index++) {
      longDirectory = join(longDirectory, `part-${index}-${"x".repeat(55)}`);
      success(native.createWindowsDirectories(pathBytes(longDirectory)));
    }
    const rawDirectory = join(longDirectory, "directory-\udfff");
    success(native.createWindowsDirectories(pathBytes(rawDirectory)));
    rawPaths.push(rawDirectory);
    const rawPath = join(rawDirectory, "file-\ud800");
    // A lossy UTF-8 round trip would collide with this different filename.
    const replacement = join(longDirectory, "directory-\ufffd");
    mkdirSync(replacement);
    writeFileSync(join(replacement, "file-\ufffd"), "replacement sentinel");
    const raw = keep(open(rawPath, undefined, undefined, flags.CREATE_NEW));
    rawPaths.push(rawPath);
    assert.equal(
      checked(raw.write(exactPayload, 0, exactPayload.length)).value,
      exactPayload.length,
    );
    const finalName = checked(raw.finalPath(flags.FILE_NAME_OPENED)).path;
    assert(finalName.length / 2 > 260);
    assert(
      finalName.includes(
        Buffer.from("directory-\udfff\\file-\ud800", "utf16le"),
      ),
    );
    const reopened = keep(open(finalName));
    assert.deepEqual(checked(reopened.identity()), checked(raw.identity()));
    const rawContents = Buffer.alloc(exactPayload.length);
    assert.equal(
      checked(reopened.read(rawContents, 0, rawContents.length)).value,
      rawContents.length,
    );
    assert.deepEqual(rawContents, exactPayload);
    close(reopened);
    close(raw);
    assert.equal(
      readFileSync(join(replacement, "file-\ufffd"), "utf8"),
      "replacement sentinel",
    );
    return {
      handleReadWriteAndEof: true,
      exact128BitIdentity: true,
      numericMissingSharingAndClosedErrors: true,
      ancestorReplacementBlockedUntilClose: true,
      junctionMetadataAndFinalNames: true,
      exactHandleRenameAndDeleteAfterNameReplacement: true,
      rawUtf16AndLongPaths: true,
      invalidFfiRepresentationsRejected: true,
    };
  } finally {
    for (const handle of held) handle.close();
    for (const path of rawPaths.reverse()) remove(path);
  }
}

async function ownershipProof(root: string): Promise<boolean> {
  assert(global.gc, "Run the Windows proof with --expose-gc");
  const path = join(root, "garbage-collected-handle");
  open(path, readWrite, 0, flags.CREATE_NEW);
  await setImmediate();
  global.gc();
  await setImmediate();
  const reopened = open(path, readWrite, 0);
  success(reopened.close());
  return true;
}

const root = realpathSync.native(
  mkdtempSync(join(tmpdir(), "codex-security-windows-")),
);
try {
  console.log(
    JSON.stringify(
      {
        node: process.version,
        platform: process.platform,
        architecture: process.arch,
        nodeApi: 8,
        handles: handleProof(root),
        privateDirectories: privateDirectoryProof(root, native),
        wideProcessAndPaths: wideProcessProof(root),
        garbageCollectionClosesHandle: await ownershipProof(root),
        fixture: basename(root),
      },
      null,
      2,
    ),
  );
} finally {
  rmSync(root, { recursive: true, force: true });
}
