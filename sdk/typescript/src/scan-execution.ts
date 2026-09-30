import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync } from "node:fs";
import { lstat, mkdir, realpath } from "node:fs/promises";
import { createRequire } from "node:module";
import { constants as osConstants } from "node:os";
import { join, resolve, toNamespacedPath } from "node:path";

interface UnixBinding {
  fileLock(
    fd: number,
    unlock: boolean,
    nonblocking: boolean,
  ): { value: number; errno: number };
}

interface WindowsHandle {
  close(): number;
  attributes(): { error: number; attributes: number };
  fileType(): { error: number; value: number };
  lock(nonblocking: boolean): number;
}

interface WindowsBinding {
  openWindowsFile(
    path: Buffer,
    access: number,
    share: number,
    disposition: number,
    flags: number,
  ): { error: number; handle?: WindowsHandle | null };
}

/** A native transport stopped; the saved scan can continue in another host. */
export class ScanTransportClosedError extends Error {}

/** A required worker permission cannot be preserved by the selected runtime. */
export class ScanPermissionError extends Error {}

/** A process-owned lock protects saved scans across SDK and native hosts, including Node 20. */
export async function acquireScanExecution(
  stateDirectory: string,
  scanDirectory: string,
  pluginRoot: string,
): Promise<() => void> {
  const directory = join(stateDirectory, "scan-execution");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  if (!(await lstat(directory)).isDirectory())
    throw new Error("Scan execution locks require a real directory.");
  const key = createHash("sha256")
    .update(await realpath(scanDirectory))
    .digest("hex");
  const path = join(directory, key + ".lock");
  const metadata = await lstat(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return null;
    throw error;
  });
  if (metadata !== null && (!metadata.isFile() || metadata.nlink !== 1))
    throw new Error("Scan execution lock must be an ordinary file.");

  const libc =
    process.platform !== "linux"
      ? ""
      : (
            process.report.getReport() as {
              header: { glibcVersionRuntime?: string };
            }
          ).header.glibcVersionRuntime === undefined
        ? "-musl"
        : "-gnu";
  const nativeDirectory = join(
    pluginRoot,
    "mcp",
    "native",
    `${process.platform}-${process.arch}${libc}`,
  );
  const require = createRequire(import.meta.url);
  const alreadyRunning =
    "This saved scan is already running in another client.";
  if (process.platform === "win32") {
    const native = require(
      join(nativeDirectory, "windows.node"),
    ) as WindowsBinding;
    const opened = native.openWindowsFile(
      Buffer.from(toNamespacedPath(resolve(path)), "utf16le"),
      0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
      1 | 2 | 4, // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
      4, // OPEN_ALWAYS
      0x00200000, // FILE_FLAG_OPEN_REPARSE_POINT
    );
    if (opened.error !== 0 || opened.handle == null)
      throw new Error(
        `Cannot open scan execution lock (Windows error ${opened.error}).`,
      );
    const handle = opened.handle;
    try {
      const info = handle.attributes();
      const type = handle.fileType();
      if (info.error !== 0 || type.error !== 0)
        throw new Error(
          `Cannot inspect scan execution lock (Windows error ${info.error || type.error}).`,
        );
      if ((info.attributes & (0x10 | 0x400)) !== 0 || type.value !== 1)
        throw new Error("Scan execution lock must be an ordinary file.");
      const error = handle.lock(true);
      if (error !== 0)
        throw new Error(
          error === 33
            ? alreadyRunning
            : `Cannot lock saved scan (Windows error ${error}).`,
        );
    } catch (error) {
      handle.close();
      throw error;
    }
    return () => {
      const error = handle.close();
      if (error !== 0)
        throw new Error(
          `Cannot close scan execution lock (Windows error ${error}).`,
        );
    };
  }

  const native = require(join(nativeDirectory, "unix.node")) as UnixBinding;
  const fd = openSync(
    path,
    constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.nlink !== 1)
      throw new Error("Scan execution lock must be an ordinary file.");
    const { errno } = native.fileLock(fd, false, true);
    if (errno !== 0)
      throw new Error(
        errno === osConstants.errno.EAGAIN ||
          errno === osConstants.errno.EWOULDBLOCK
          ? alreadyRunning
          : `Cannot lock saved scan (errno ${errno}).`,
      );
  } catch (error) {
    closeSync(fd);
    throw error;
  }
  return () => closeSync(fd);
}
