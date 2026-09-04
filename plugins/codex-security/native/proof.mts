import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  lstatSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { randomUUID } from "node:crypto";
import { basename, join, relative } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { loadBinding, readDescriptor } from "./binding.mjs";
import { constants as osConstants } from "node:os";

const native = loadBinding();
const errno = osConstants.errno;
class NativeError extends Error {
  constructor(readonly errno: number) {
    super(`Native operation failed: errno ${errno}`);
  }
}
function checked<T extends { errno: number }>(result: T): T {
  if (result.errno !== 0) throw new NativeError(result.errno);
  return result;
}
const bytes = (path: string | Buffer) =>
  typeof path === "string" ? Buffer.from(path) : path;
const openAt = (fd: number, path: string | Buffer, flags: number, mode = 0) =>
  checked(native.openAt(fd, bytes(path), flags, mode)).value;
const mkdirAt = (fd: number, path: string | Buffer, mode: number) => {
  checked(native.makeDirectoryAt(fd, bytes(path), mode));
};
const renameAt = (
  oldFd: number,
  oldPath: string | Buffer,
  newFd: number,
  newPath: string | Buffer,
) => {
  checked(native.renameAt(oldFd, bytes(oldPath), newFd, bytes(newPath)));
};
const unlinkAt = (fd: number, path: string | Buffer) => {
  checked(native.unlinkAt(fd, bytes(path)));
};
const duplicate = (fd: number) => checked(native.duplicate(fd)).value;
const fileLock = (fd: number, unlock = false, nonblocking = false) => {
  checked(native.fileLock(fd, unlock, nonblocking));
};
const statAt = (fd: number, path: string | Buffer) =>
  checked(native.statAt(fd, bytes(path)));
const readLinkAt = (fd: number, path: string | Buffer) =>
  checked(native.readLinkAt(fd, bytes(path))).value;
const rawPath = (parent: string, name: Buffer) =>
  Buffer.concat([Buffer.from(parent + "/"), name]);
// APFS requires valid UTF-8 names; Linux also exercises undecodable bytes.
const fixtureName = (prefix: string, byte: number) =>
  process.platform === "darwin"
    ? Buffer.from(`${prefix}-é`)
    : Buffer.from([prefix.charCodeAt(0), byte]);

function realpathProof(root: string) {
  const directory = join(root, "realpath");
  mkdirSync(directory);
  const canonical = realpathSync.native(Buffer.from(directory), {
    encoding: "buffer",
  });
  const path = (name: string | Buffer) =>
    Buffer.concat([canonical, Buffer.from("/"), bytes(name)]);
  const resolve = (name: string | Buffer) =>
    realpathSync.native(path(name), { encoding: "buffer" });
  mkdirSync(path("nested/target"), { recursive: true });
  writeFileSync(path("file"), "file");
  symlinkSync("nested/target", path("relative-link"));
  symlinkSync("file/..", path("file-parent-link"));
  symlinkSync("cycle", path("cycle"));
  assert.deepEqual(resolve("relative-link"), path("nested/target"));
  assert.deepEqual(
    realpathSync.native(
      Buffer.from(relative(process.cwd(), join(directory, "relative-link"))),
      { encoding: "buffer" },
    ),
    path("nested/target"),
  );
  assert.deepEqual(resolve("relative-link/.."), path("nested"));
  const fileParentResults = ["file/..", "file-parent-link"].map((name) => {
    let result: Buffer;
    try {
      result = resolve(name);
    } catch (error) {
      assert.equal((error as NodeJS.ErrnoException).code, "ENOTDIR");
      return "ENOTDIR";
    }
    assert.deepEqual(result, canonical);
    return "resolved-parent";
  });
  for (const name of ["missing", "missing/.."])
    assert.throws(() => resolve(name), { code: "ENOENT" });
  assert.throws(() => resolve("cycle"), { code: "ELOOP" });

  const raw = Buffer.from([0xff]);
  let invalidName: "preserved" | "filesystem-rejected" = "preserved";
  try {
    mkdirSync(path(raw));
  } catch (error) {
    // APFS may reject the fixture itself; do not confuse that with a Node failure.
    assert.equal(process.platform, "darwin");
    assert(
      ["EILSEQ", "EINVAL"].includes((error as NodeJS.ErrnoException).code!),
    );
    invalidName = "filesystem-rejected";
  }
  // A replacement-character sibling must never satisfy the raw path lookup.
  mkdirSync(path("\ufffd"));
  let invalidLinkTarget: "preserved" | "filesystem-rejected" = "preserved";
  try {
    symlinkSync(raw, path("raw-relative-link"));
    symlinkSync(path(raw), path("raw-absolute-link"));
  } catch (error) {
    assert.equal(process.platform, "darwin");
    assert(
      ["EILSEQ", "EINVAL"].includes((error as NodeJS.ErrnoException).code!),
    );
    invalidLinkTarget = "filesystem-rejected";
  }
  if (invalidName === "preserved") {
    assert.equal(invalidLinkTarget, "preserved");
    for (const name of [raw, "raw-relative-link", "raw-absolute-link"])
      assert.deepEqual(resolve(name), path(raw));
  } else if (invalidLinkTarget === "preserved") {
    for (const name of [raw, "raw-relative-link", "raw-absolute-link"])
      assert.throws(
        () => resolve(name),
        (error: unknown) =>
          ["ENOENT", "EILSEQ"].includes((error as NodeJS.ErrnoException).code!),
      );
  }
  return {
    bufferPaths: true,
    invalidName,
    invalidLinkTarget,
    relativeLinks: true,
    symlinkParent: true,
    fileParent: fileParentResults[0],
    linkedFileParent: fileParentResults[1],
    missing: "ENOENT",
    cycles: "ELOOP",
  };
}

function accountProof() {
  let currentHomeMatches: boolean | null = null;
  try {
    const current = userInfo({ encoding: "buffer" });
    assert.deepEqual(
      checked(native.userHome(current.username)).value,
      current.homedir,
    );
    currentHomeMatches = true;
  } catch (error) {
    // A container can run a numeric UID with no account database entry.
    const system = error as { code?: string; info?: { code?: string } };
    assert.equal(system.code, "ERR_SYSTEM_ERROR");
    assert.equal(system.info?.code, "ENOENT");
  }
  const other = checked(native.userHome(Buffer.from("root"))).value;
  assert(other !== null && other[0] === 0x2f);
  assert.equal(
    checked(native.userHome(Buffer.from(`codex-${randomUUID().slice(0, 8)}`)))
      .value,
    null,
  );
  assert.throws(() => native.userHome(Buffer.from([0])));
  return {
    currentHomeMatches,
    namedHomeWithoutGit: true,
    missingAccount: true,
  };
}

const directoryFlags =
  constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
const ownFileFlags =
  constants.O_WRONLY |
  constants.O_CREAT |
  constants.O_EXCL |
  constants.O_NOFOLLOW;
const readFlags =
  constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const self = fileURLToPath(import.meta.url);

function expectedError(action: () => void, ...codes: number[]): number {
  try {
    action();
  } catch (error) {
    assert(error instanceof NativeError);
    assert(codes.includes(error.errno), error.message);
    return error.errno;
  }
  throw new Error("Expected native operation to fail");
}

function descriptorProof(root: string) {
  const scan = join(root, "scan");
  const movedScan = join(root, "held-scan");
  const outside = join(root, "outside");
  mkdirSync(scan);
  mkdirSync(outside);
  writeFileSync(join(outside, "result.json"), "outside sentinel");
  const held = new Set<number>();
  const keep = (fd: number) => {
    held.add(fd);
    return fd;
  };
  const close = (fd: number) => {
    closeSync(fd);
    held.delete(fd);
  };
  try {
    const rootFd = keep(openSync(scan, directoryFlags));
    const identity = fstatSync(rootFd, { bigint: true });
    mkdirAt(rootFd, "artifacts", 0o700);
    const originalParent = keep(openAt(rootFd, "artifacts", directoryFlags));
    const parentFd = keep(duplicate(originalParent));
    close(originalParent);
    const unreadable = fixtureName("u", 0xff);
    const rawLink = fixtureName("l", 0xfe);
    const rawTarget = Buffer.concat([
      Buffer.from("component/".repeat(80)),
      Buffer.from([0xff]),
    ]);
    writeFileSync(rawPath(join(scan, "artifacts"), unreadable), "unreadable", {
      mode: 0,
    });
    symlinkSync(rawTarget, rawPath(join(scan, "artifacts"), rawLink));
    const unreadableMetadata = statAt(parentFd, unreadable);
    const unreadableExpected = lstatSync(
      rawPath(join(scan, "artifacts"), unreadable),
      { bigint: true },
    );
    assert.equal(unreadableMetadata.mode, Number(unreadableExpected.mode));
    assert.equal(unreadableMetadata.device, unreadableExpected.dev.toString());
    assert.equal(unreadableMetadata.inode, unreadableExpected.ino.toString());
    assert.equal(unreadableMetadata.mode & 0o777, 0);
    if (process.geteuid?.() !== 0)
      expectedError(
        () => openAt(parentFd, unreadable, readFlags),
        errno.EACCES!,
      );
    const linkMetadata = statAt(parentFd, rawLink);
    assert.equal(linkMetadata.mode & constants.S_IFMT, constants.S_IFLNK);
    assert.deepEqual(readLinkAt(parentFd, rawLink), rawTarget);

    // Replace both visible ancestor paths while keeping their validated FDs.
    renameSync(scan, movedScan);
    symlinkSync(outside, scan, "dir");
    renameSync(join(movedScan, "artifacts"), join(movedScan, "held-artifacts"));
    symlinkSync(outside, join(movedScan, "artifacts"), "dir");
    assert.equal(fstatSync(rootFd, { bigint: true }).ino, identity.ino);
    assert.equal(statSync(movedScan, { bigint: true }).dev, identity.dev);
    assert.deepEqual(statAt(parentFd, unreadable), unreadableMetadata);
    assert.deepEqual(statAt(parentFd, rawLink), linkMetadata);
    assert.deepEqual(readLinkAt(parentFd, rawLink), rawTarget);
    assert.equal(
      statAt(rootFd, "artifacts").mode & constants.S_IFMT,
      constants.S_IFLNK,
    );
    assert.equal(readLinkAt(rootFd, "artifacts").toString(), outside);
    mkdirAt(parentFd, "nested", 0o700);

    const rawDirectory = fixtureName("d", 0xfd);
    const rawSource = fixtureName("s", 0xfc);
    const rawDestination = fixtureName("t", 0xfb);
    mkdirAt(parentFd, rawDirectory, 0o700);
    assert.equal(statAt(parentFd, rawDirectory).mode & 0o777, 0o700);
    const rawDirectoryFd = keep(openAt(parentFd, rawDirectory, directoryFlags));
    const rawFd = keep(openAt(parentFd, rawSource, ownFileFlags, 0o600));
    writeFileSync(rawFd, "raw path contents");
    close(rawFd);
    renameAt(parentFd, rawSource, rawDirectoryFd, rawDestination);
    const rawRead = keep(openAt(rawDirectoryFd, rawDestination, readFlags));
    assert.equal(readFileSync(rawRead, "utf8"), "raw path contents");
    close(rawRead);
    unlinkAt(rawDirectoryFd, rawDestination);
    close(rawDirectoryFd);
    rmSync(rawPath(join(movedScan, "held-artifacts"), rawDirectory), {
      recursive: true,
    });
    expectedError(() => statAt(parentFd, rawDirectory), errno.ENOENT!);

    const fd = keep(openAt(parentFd, ".result.tmp", ownFileFlags, 0o600));
    const payload = Buffer.from('{"proof":"anchored 🔐"}\n');
    writeFileSync(fd, payload);
    fsyncSync(fd);
    assert(fstatSync(fd).isFile());
    assert.equal(fstatSync(fd).mode & 0o777, 0o600);
    assert.equal(fstatSync(fd).size, payload.length);
    close(fd);
    renameAt(parentFd, ".result.tmp", parentFd, "result.json");

    const input = keep(openAt(parentFd, "result.json", readFlags));
    const chunks: Buffer[] = [];
    while (true) {
      const chunk = Buffer.alloc(5);
      const count = readDescriptor(input, chunk, 0, chunk.length, null);
      if (count === 0) break;
      chunks.push(chunk.subarray(0, count));
    }
    assert.deepEqual(Buffer.concat(chunks), payload);
    close(input);
    const anchoredDirectory = join(movedScan, "held-artifacts");
    assert.deepEqual(
      readFileSync(join(anchoredDirectory, "result.json")),
      payload,
    );
    assert.equal(
      readFileSync(join(outside, "result.json"), "utf8"),
      "outside sentinel",
    );
    assert(!existsSync(join(outside, "nested")));

    symlinkSync(join(outside, "result.json"), join(anchoredDirectory, "link"));
    const noFollowErrno = expectedError(
      () => openAt(parentFd, "link", readFlags),
      errno.ELOOP!,
    );
    unlinkAt(parentFd, "link");
    unlinkAt(parentFd, "result.json");
    assert(!existsSync(join(anchoredDirectory, "result.json")));
    assert.equal(
      readFileSync(join(outside, "result.json"), "utf8"),
      "outside sentinel",
    );
    expectedError(
      () => openAt(rootFd, "artifacts", directoryFlags),
      errno.ELOOP!,
      errno.ENOTDIR!,
    );
    expectedError(() => mkdirAt(parentFd, "nested", 0o700), errno.EEXIST!);
    expectedError(
      () => renameAt(parentFd, "missing", parentFd, "other"),
      errno.ENOENT!,
    );
    expectedError(() => unlinkAt(parentFd, "missing"), errno.ENOENT!);
    expectedError(() => statAt(-1, "missing"), errno.EBADF!);
    expectedError(() => readLinkAt(-1, "missing"), errno.EBADF!);
    const badFdErrno = expectedError(
      () => openAt(-1, "missing", readFlags),
      errno.EBADF!,
    );
    return {
      anchoredMkdirWriteRenameReadDelete: true,
      outsideSentinelPreserved: true,
      nodeFdWriteReadFstatFsyncClose: true,
      mode: "0600",
      duplicateSurvivesOriginalClose: true,
      rawMkdirOpenRenameUnlink: true,
      unreadableMetadataMatches: true,
      noFollowStatAndLongRawReadlinkSurviveReplacement: true,
      rawLinkTargetBytes: rawTarget.length,
      noFollowErrno,
      badFdErrno,
    };
  } finally {
    for (const fd of held) closeSync(fd);
  }
}

async function nativeLockWorker(path: string): Promise<void> {
  const fd = openSync(path, constants.O_RDWR | constants.O_CREAT, 0o600);
  try {
    if (process.argv[4] === "try") {
      const result = native.fileLock(fd, false, true);
      if (result.errno === 0) fileLock(fd, true);
      console.log(
        JSON.stringify({ acquired: result.errno === 0, errno: result.errno }),
      );
      return;
    }
    const commands = createInterface({ input: process.stdin })[
      Symbol.asyncIterator
    ]();
    console.log("waiting");
    fileLock(fd);
    console.log("acquired");
    await commands.next();
    fileLock(fd, true);
    console.log("released");
  } finally {
    closeSync(fd);
  }
}

// Temporary interoperability oracle: import the actual current Python functions.
// This protocol scaffold is never a migrated implementation or shipped artifact.
const pythonOracle = String.raw`
import json, os, sys
sys.path.insert(0, sys.argv[1])
from workbench_db import acquire_completion_file_lock, release_completion_file_lock, posix_file_lock
fd = os.open(sys.argv[2], os.O_RDWR | os.O_CREAT, 0o600)
try:
    if sys.argv[3] == "try":
        try:
            posix_file_lock.flock(fd, posix_file_lock.LOCK_EX | posix_file_lock.LOCK_NB)
        except OSError as error:
            print(json.dumps({"acquired": False, "errno": error.errno}), flush=True)
        else:
            release_completion_file_lock(fd)
            print(json.dumps({"acquired": True}), flush=True)
    else:
        print("waiting", flush=True)
        acquire_completion_file_lock(fd)
        print("acquired", flush=True)
        sys.stdin.buffer.readline()
        release_completion_file_lock(fd)
        print("released", flush=True)
finally:
    os.close(fd)
`;

type Worker = {
  child: ChildProcessWithoutNullStreams;
  lines: AsyncIterableIterator<string>;
  exit: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  stderr: () => string;
};
const workers: Worker[] = [];

function worker(command: string, args: string[]): Worker {
  const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.setEncoding("utf8").on("data", (chunk: string) => {
    stderr += chunk;
  });
  const result: Worker = {
    child,
    lines: createInterface({ input: child.stdout })[Symbol.asyncIterator](),
    exit: new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error(`worker exit timeout: ${stderr}`));
      }, 30_000);
      child.once("error", (error) => {
        clearTimeout(timeout);
        reject(error);
      });
      child.once("exit", (code, signal) => {
        clearTimeout(timeout);
        resolve({ code, signal });
      });
    }),
    stderr: () => stderr,
  };
  workers.push(result);
  return result;
}

async function line(child: Worker, expected?: string): Promise<string> {
  let timeout: ReturnType<typeof setTimeout>;
  const value = await Promise.race([
    child.lines.next(),
    new Promise<never>((_resolve, reject) => {
      timeout = setTimeout(
        () => reject(new Error(`worker protocol timeout: ${child.stderr()}`)),
        10_000,
      );
    }),
  ]).finally(() => clearTimeout(timeout));
  assert(!value.done, `worker ended early: ${child.stderr()}`);
  if (expected !== undefined) assert.equal(value.value, expected);
  return value.value;
}

async function release(child: Worker): Promise<void> {
  child.child.stdin.end("release\n");
  await line(child, "released");
  const ended = await child.exit;
  assert.equal(ended.code, 0, child.stderr());
}

async function kill(child: Worker): Promise<void> {
  child.child.kill("SIGKILL");
  assert.equal((await child.exit).signal, "SIGKILL");
}

async function lockProof(root: string, python?: string, scripts?: string) {
  const path = join(root, "completion.lock");
  const fd = openSync(path, constants.O_RDWR | constants.O_CREAT, 0o600);
  const peerWorker = (mode = "hold") =>
    python !== undefined && scripts !== undefined
      ? worker(python, ["-c", pythonOracle, scripts, path, mode])
      : worker(process.execPath, [self, "lock-worker", path, mode]);
  const nativeWorker = () =>
    worker(process.execPath, [self, "lock-worker", path]);
  try {
    fileLock(fd);
    const probe = peerWorker("try");
    const contention = JSON.parse(await line(probe)) as {
      acquired: boolean;
      errno: number;
    };
    assert.equal(contention.acquired, false);
    assert([errno.EAGAIN, errno.EWOULDBLOCK].includes(contention.errno));
    assert.equal((await probe.exit).code, 0, probe.stderr());
    const waitingPeer = peerWorker();
    await line(waitingPeer, "waiting");
    fileLock(fd, true);
    await line(waitingPeer, "acquired");
    const nativeContention = expectedError(
      () => fileLock(fd, false, true),
      errno.EAGAIN!,
      errno.EWOULDBLOCK!,
    );
    await release(waitingPeer);

    const heldPeer = peerWorker();
    await line(heldPeer, "waiting");
    await line(heldPeer, "acquired");
    const waitingNative = nativeWorker();
    await line(waitingNative, "waiting");
    await kill(heldPeer);
    await line(waitingNative, "acquired");
    await release(waitingNative);

    const heldNative = nativeWorker();
    await line(heldNative, "waiting");
    await line(heldNative, "acquired");
    const peerAfterDeath = peerWorker();
    await line(peerAfterDeath, "waiting");
    await kill(heldNative);
    await line(peerAfterDeath, "acquired");
    await release(peerAfterDeath);
    fileLock(fd, false, true);
    fileLock(fd, true);
    return {
      peerRuntime: python === undefined ? "node" : "python",
      peerContentionErrno: contention.errno,
      nativeContentionErrno: nativeContention,
      bidirectionalBlockingHandoff: true,
      unlockHandoff: true,
      peerDeathReleasesLock: true,
      nativeDeathReleasesLock: true,
    };
  } finally {
    closeSync(fd);
  }
}

if (process.argv[2] === "lock-worker") {
  await nativeLockWorker(process.argv[3]!);
} else {
  const python = process.argv[2];
  const scripts = process.argv[3];
  assert.equal(
    Boolean(python),
    Boolean(scripts),
    "Pass both the optional Python interpreter and legacy scripts directory",
  );
  const root = mkdtempSync(join(tmpdir(), "codex-security-native-"));
  try {
    const descriptors = descriptorProof(root);
    const realpath = realpathProof(root);
    const accounts = accountProof();
    const locks = await lockProof(root);
    const pythonCompatibility =
      python && scripts ? await lockProof(root, python, scripts) : undefined;
    console.log(
      JSON.stringify(
        {
          node: process.version,
          platform: process.platform,
          architecture: process.arch,
          nodeApi: 8,
          descriptors,
          realpath,
          accounts,
          locks,
          pythonCompatibility,
          fixture: basename(root),
        },
        null,
        2,
      ),
    );
  } finally {
    for (const child of workers) {
      if (child.child.exitCode === null && child.child.signalCode === null)
        child.child.kill("SIGKILL");
    }
    await Promise.allSettled(workers.map((child) => child.exit));
    rmSync(root, { recursive: true, force: true });
    assert(!existsSync(root));
  }
}
