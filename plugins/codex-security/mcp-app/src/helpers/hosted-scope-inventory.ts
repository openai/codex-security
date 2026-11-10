import { randomBytes } from "node:crypto";
import fs from "node:fs";
import { basename, dirname, isAbsolute, join } from "node:path";
import { ancestors, append, sameFile } from "./inventory-paths";
import { mkdir, normalizePath, resolvedPathText } from "./helper-files";
import { decodePosixBytes, encodePosixPath } from "./posix-path";

const readWithoutFollowingLinks =
  fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;

// A shared binding may use one protected alias. Use ordinary scan output
// for more complex path layouts instead of resolving them on the executor.
function trustedStatePath(
  path: string,
  uid: number,
  repo: string,
  scan: string,
  allowAlias = true,
): boolean {
  const spelling = normalizePath(path);
  if (spelling.split("/").includes("..")) return false;
  for (const directory of [...ancestors(spelling)].reverse()) {
    const encoded = encodePosixPath(directory);
    const info = fs.lstatSync(encoded);
    if (info.uid !== 0 && info.uid !== uid) return false;
    if (sameFile(directory, repo) || sameFile(directory, scan)) return false;
    if (info.isSymbolicLink()) {
      if (!allowAlias) return false;
      allowAlias = false;
      const link = decodePosixBytes(
        fs.readlinkSync(encoded, { encoding: "buffer" }),
      );
      const target = isAbsolute(link) ? link : append(dirname(directory), link);
      if (!trustedStatePath(target, uid, repo, scan, false)) return false;
    } else if (
      !info.isDirectory() ||
      ((info.mode & 0o022) !== 0 && (info.mode & 0o1000) === 0)
    ) {
      return false;
    }
  }
  return true;
}

/** Write to the hosted executor's bound state directory when it can protect the inventory. */
export function writeHostedScopeInventory(
  stateDirectory: string,
  scopesFile: string,
  repo: string,
  output: string,
  rows: Buffer[],
): string | undefined {
  if (process.platform !== "linux" || !isAbsolute(stateDirectory)) return;
  try {
    const uid = process.geteuid!();
    const scan = resolvedPathText(dirname(output), false);
    if (!trustedStatePath(stateDirectory, uid, repo, scan)) return;
    const parent = resolvedPathText(stateDirectory);
    const name = `${basename(scopesFile)}.scoped-${randomBytes(12).toString("hex")}.jsonl`;
    const encoded = encodePosixPath(join(parent, name));
    const fd = fs.openSync(encoded, "wx", 0o600);
    let reader: number | undefined;
    let cleanupFd = fd;
    try {
      let file = fs.fstatSync(fd);
      // A reader could already hold a descriptor if the mount created this
      // entry with group or other access. Only repair missing owner access.
      if (
        file.uid === uid &&
        (file.mode & 0o077) === 0 &&
        (file.mode & 0o777) !== 0o600
      ) {
        fs.fchmodSync(fd, 0o600);
        // Some mounted filesystems accept chmod without enforcing the requested mode.
        file = fs.fstatSync(fd);
      }
      if (file.uid !== uid || (file.mode & 0o777) !== 0o600)
        throw new Error(
          "The state directory does not support private inventory files.",
        );
      // Keep the inode pinned if closing the writer reports a delayed error.
      reader = fs.openSync(encoded, readWithoutFollowingLinks);
      const original = fs.fstatSync(fd, { bigint: true });
      const pinned = fs.fstatSync(reader, { bigint: true });
      if (pinned.dev !== original.dev || pinned.ino !== original.ino)
        throw new Error("The state inventory changed before writing.");
      for (const row of rows) fs.writeFileSync(fd, row);
      cleanupFd = reader;
      fs.closeSync(fd);
    } catch {
      if (cleanupFd === fd) {
        try {
          fs.ftruncateSync(fd, 0);
        } catch {
          // A storage failure can still leave the directory entry removable.
        }
      }
      const held = fs.fstatSync(cleanupFd, { bigint: true });
      const named = fs.lstatSync(encoded, {
        bigint: true,
        throwIfNoEntry: false,
      });
      if (named?.dev === held.dev && named.ino === held.ino)
        fs.unlinkSync(encoded);
      return undefined;
    } finally {
      for (const descriptor of [cleanupFd === fd ? fd : undefined, reader]) {
        if (descriptor === undefined) continue;
        try {
          fs.closeSync(descriptor);
        } catch {
          // These cleanup closes cannot change the write result.
        }
      }
    }
    return append(stateDirectory, name);
  } catch {
    return undefined;
  }
}

// Scan output can be on a mount that does not support rename.
export function writeHostedOutput(output: string, rows: Buffer[]): void {
  mkdir(dirname(output));
  const path = encodePosixPath(output);
  let writer: number;
  try {
    writer = fs.openSync(path, "wx");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    const entry = fs.lstatSync(path);
    if (!entry.isFile() && !entry.isSymbolicLink()) throw error;
    // Replace only this disposable scan entry, without writing through a link.
    fs.unlinkSync(path);
    writer = fs.openSync(path, "wx");
  }
  try {
    const file = fs.fstatSync(writer);
    if (file.uid === process.geteuid!() && !(file.mode & 0o400)) {
      try {
        fs.fchmodSync(writer, (file.mode & 0o777) | 0o600);
      } catch {
        // Some fixed-mode mounts permit reading even when chmod is unavailable.
      }
    }
    for (const row of rows) fs.writeFileSync(writer, row);
  } finally {
    fs.closeSync(writer);
  }
  // Some filesystems expose a newly written file only after the writer closes.
  const reader = fs.openSync(path, readWithoutFollowingLinks);
  try {
    if (!fs.fstatSync(reader).isFile())
      throw new Error(`--out: expected a regular file path: ${output}`);
  } finally {
    fs.closeSync(reader);
  }
}
