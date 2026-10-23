import { constants, type BigIntStats, type Stats } from "node:fs";
import { lstat, open, realpath, type FileHandle } from "node:fs/promises";
import { dirname, isAbsolute, join, posix, resolve } from "node:path";
import {
  ContractValidationError,
  OutputDirectoryError,
  abortReason,
} from "./errors.js";
import { isRecord } from "./record.js";
import { isWithin as isContained } from "./trusted-executable.js";
import { isWindowsUnsafePathComponent } from "./windows-path.js";

interface CheckedScanFile {
  path: string;
  metadata: BigIntStats;
  parents: Array<{ path: string; metadata: BigIntStats }>;
}

export interface ScanRoot {
  path: string;
  metadata: BigIntStats;
}

export async function requireScanFile(
  scanDirectory: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
): Promise<string> {
  return (
    await requireCheckedScanFile(scanDirectory, relativePath, context, signal)
  ).path;
}

export async function readScanFile(
  scanDirectory: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
): Promise<Buffer> {
  const file = await openCheckedScanFile(
    scanDirectory,
    relativePath,
    context,
    signal,
  );
  try {
    return await file.readFile({ signal });
  } finally {
    await file.close();
  }
}

async function requireCheckedScanFile(
  scanDirectory: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
  expectedRoot?: ScanRoot,
): Promise<CheckedScanFile> {
  const checkedRoot = await requireScanRoot(scanDirectory, signal);
  const scanDir = checkedRoot.path;
  throwIfAborted(signal);
  const safePath = portableRelativePath(relativePath, context);
  const parts = safePath.split("/");
  let current = scanDir;
  try {
    const rootMetadata = checkedRoot.metadata;
    if (
      expectedRoot !== undefined &&
      (scanDir !== expectedRoot.path ||
        rootMetadata.dev !== expectedRoot.metadata.dev ||
        rootMetadata.ino !== expectedRoot.metadata.ino)
    ) {
      throw new Error("scan directory changed while reading");
    }
    const parents = [{ path: scanDir, metadata: rootMetadata }];
    throwIfAborted(signal);
    for (const part of parts.slice(0, -1)) {
      current = join(current, part);
      const metadata = await lstat(current, { bigint: true });
      throwIfAborted(signal);
      if (!metadata.isDirectory()) {
        throw new Error("unsafe parent");
      }
      parents.push({ path: current, metadata });
    }
    const path = join(scanDir, ...parts);
    const metadata = await lstat(path, { bigint: true });
    throwIfAborted(signal);
    if (!metadata.isFile()) {
      throw new ContractValidationError(
        `${context}: expected a regular non-symlink file.`,
      );
    }
    const canonical = await realpath(path);
    throwIfAborted(signal);
    if (!isContained(scanDir, canonical)) {
      throw new Error("outside scan directory");
    }
    return { path, metadata, parents };
  } catch (error) {
    throwIfAborted(signal);
    if (error instanceof ContractValidationError) {
      throw error;
    }
    throw new ContractValidationError(
      `${context}: expected a file inside the scan directory.`,
      {
        cause: error,
      },
    );
  }
}

export async function requireScanRoot(
  scanDirectory: string,
  signal?: AbortSignal,
): Promise<ScanRoot> {
  throwIfAborted(signal);
  const absolute = resolve(scanDirectory);
  try {
    const metadata = await lstat(absolute, { bigint: true });
    throwIfAborted(signal);
    const canonical = await realpath(absolute);
    throwIfAborted(signal);
    const current = await lstat(absolute, { bigint: true });
    throwIfAborted(signal);
    const returned = await lstat(canonical, { bigint: true });
    throwIfAborted(signal);
    if (
      !metadata.isDirectory() ||
      !current.isDirectory() ||
      metadata.dev !== current.dev ||
      metadata.ino !== current.ino ||
      !returned.isDirectory() ||
      metadata.dev !== returned.dev ||
      metadata.ino !== returned.ino
    ) {
      throw new Error("not a directory");
    }
    try {
      requirePrivateOutputDirectory(
        { mode: Number(returned.mode), uid: Number(returned.uid) },
        canonical,
      );
      await requireSecureOutputAncestry(canonical);
    } catch (error) {
      throw new ContractValidationError(
        error instanceof Error
          ? error.message
          : "Scan directory must remain private to the current user.",
        { cause: error },
      );
    }
    return { path: canonical, metadata: returned };
  } catch (error) {
    throwIfAborted(signal);
    if (error instanceof ContractValidationError) throw error;
    throw new ContractValidationError(
      "Scan directory must be an existing non-symlink directory.",
      { cause: error },
    );
  }
}

export async function verifyScanRoot(
  root: ScanRoot,
  signal?: AbortSignal,
): Promise<void> {
  try {
    const current = await lstat(root.path, { bigint: true });
    throwIfAborted(signal);
    if (
      !current.isDirectory() ||
      current.dev !== root.metadata.dev ||
      current.ino !== root.metadata.ino
    ) {
      throw new Error("scan directory changed while reading");
    }
    requirePrivateOutputDirectory(
      { mode: Number(current.mode), uid: Number(current.uid) },
      root.path,
    );
    await requireSecureOutputAncestry(root.path);
  } catch (error) {
    throwIfAborted(signal);
    throw new ContractValidationError(
      "Scan directory changed while reading the canonical contract.",
      { cause: error },
    );
  }
}

export function safeRelativePath(
  value: string,
  context: string,
  allowDot = false,
): string {
  const parts = value.split("/");
  if (
    value.length === 0 ||
    Buffer.from(value, "utf8").toString("utf8") !== value ||
    (!allowDot && value === ".") ||
    value.startsWith("/") ||
    /^[A-Za-z]:/.test(value) ||
    parts.includes("..") ||
    value.includes("\\") ||
    /[\u0000-\u001f]/u.test(value)
  ) {
    throw new ContractValidationError(
      `${context}: expected a safe scan-relative POSIX path.`,
    );
  }
  const normalized = posix.normalize(value).replace(/\/+$/, "");
  if (
    (!allowDot && normalized === ".") ||
    normalized.startsWith("../") ||
    isAbsolute(normalized)
  ) {
    throw new ContractValidationError(
      `${context}: expected a safe scan-relative POSIX path.`,
    );
  }
  return normalized;
}

export function portableRelativePath(value: string, context: string): string {
  const normalized = safeRelativePath(value, context);
  if (
    value.trim().length === 0 ||
    value.split("/").some(isWindowsUnsafePathComponent)
  ) {
    throw new ContractValidationError(
      `${context}: expected a safe scan-relative POSIX path.`,
    );
  }
  return normalized;
}

export async function openCheckedScanFile(
  scanDir: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
  expectedRoot?: ScanRoot,
): Promise<FileHandle> {
  const checked = await requireCheckedScanFile(
    scanDir,
    relativePath,
    context,
    signal,
    expectedRoot,
  );
  let file: FileHandle | undefined;
  try {
    file = await open(
      checked.path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const opened = await file.stat({ bigint: true });
    throwIfAborted(signal);
    if (
      !opened.isFile() ||
      opened.ino !== checked.metadata.ino ||
      !(await sameCheckedFileDevice(file, checked, opened))
    ) {
      throw new ContractValidationError(
        `${context}: expected the checked regular file.`,
      );
    }
    for (const parent of checked.parents) {
      const current = await lstat(parent.path, { bigint: true });
      throwIfAborted(signal);
      if (
        !current.isDirectory() ||
        current.dev !== parent.metadata.dev ||
        current.ino !== parent.metadata.ino
      ) {
        throw new ContractValidationError(
          `${context}: checked parent changed before opening the file.`,
        );
      }
    }
    const current = await lstat(checked.path, { bigint: true });
    throwIfAborted(signal);
    if (
      !current.isFile() ||
      current.dev !== checked.metadata.dev ||
      current.ino !== checked.metadata.ino
    ) {
      throw new ContractValidationError(
        `${context}: checked file changed before reading.`,
      );
    }
    return file;
  } catch (error) {
    await file?.close();
    throwIfAborted(signal);
    if (error instanceof ContractValidationError) throw error;
    throw new ContractValidationError(
      `${context}: unable to open the checked regular file.`,
      { cause: error },
    );
  }
}

export async function sameCheckedFileDevice(
  file: FileHandle,
  checked: { path: string; metadata: Pick<Stats | BigIntStats, "dev" | "ino"> },
  opened: Pick<Stats | BigIntStats, "dev" | "ino">,
  platform: NodeJS.Platform = process.platform,
  openReference: (path: string, flags: number) => Promise<FileHandle> = open,
): Promise<boolean> {
  if (opened.ino !== checked.metadata.ino) return false;
  if (opened.dev === checked.metadata.dev) return true;
  if (platform !== "win32") return false;

  const [openedIdentity, checkedIdentity] = await Promise.all([
    file.stat({ bigint: true }),
    lstat(checked.path, { bigint: true }),
  ]);
  if (
    !openedIdentity.isFile() ||
    !checkedIdentity.isFile() ||
    openedIdentity.ino !== checkedIdentity.ino
  ) {
    return false;
  }

  const reference = await openReference(
    checked.path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const referenceIdentity = await reference.stat({ bigint: true });
    return (
      referenceIdentity.isFile() &&
      openedIdentity.dev === referenceIdentity.dev &&
      openedIdentity.ino === referenceIdentity.ino
    );
  } finally {
    await reference.close();
  }
}

export function throwIfAborted(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  throw abortReason(signal);
}

export function requirePrivateOutputDirectory(
  metadata: Pick<Stats, "mode" | "uid">,
  path: string,
  effectiveUid = process.geteuid?.(),
): void {
  if (process.platform === "win32") return;
  if ((metadata.mode & 0o077) !== 0) {
    throw new OutputDirectoryError(
      `Scan output directory must not be accessible to other users (chmod 700): ${path}`,
    );
  }
  if (effectiveUid !== undefined && metadata.uid !== effectiveUid) {
    throw new OutputDirectoryError(
      `Scan output directory must be owned by the current user: ${path}`,
    );
  }
}

/** Reject shared parents whose owner can rename or replace private scan output. */
export async function requireSecureOutputAncestry(
  path: string,
  effectiveUid = process.geteuid?.(),
): Promise<void> {
  if (process.platform === "win32") return;
  let current = dirname(resolve(path));
  while (true) {
    try {
      current = await realpath(current);
      break;
    } catch (error) {
      if (nodeErrorCode(error) !== "ENOENT") {
        throw new OutputDirectoryError(
          `Unable to inspect scan output parent directory: ${current}`,
          { cause: error },
        );
      }
      const parent = dirname(current);
      if (parent === current) {
        throw new OutputDirectoryError(
          `Unable to inspect scan output parent directory: ${current}`,
          { cause: error },
        );
      }
      current = parent;
    }
  }
  while (true) {
    let metadata: Stats;
    try {
      metadata = await lstat(current);
    } catch (error) {
      throw new OutputDirectoryError(
        `Unable to inspect scan output parent directory: ${current}`,
        { cause: error },
      );
    }
    if (!metadata.isDirectory()) {
      throw new OutputDirectoryError(
        `Scan output parent must be a non-symlink directory: ${current}`,
      );
    }
    requireTrustedOutputAncestor(metadata, current, effectiveUid);
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

export function requireTrustedOutputAncestor(
  metadata: Pick<Stats, "mode" | "uid">,
  path: string,
  effectiveUid = process.geteuid?.(),
): void {
  if (
    effectiveUid !== undefined &&
    metadata.uid !== 0 &&
    metadata.uid !== effectiveUid
  ) {
    throw new OutputDirectoryError(
      `Scan output parent must have a trusted owner: ${path}`,
    );
  }
  if ((metadata.mode & 0o022) === 0) return;
  if ((metadata.mode & 0o1000) === 0) {
    throw new OutputDirectoryError(
      `Scan output parent must not be group- or world-writable without the sticky bit: ${path}`,
    );
  }
}

export function nodeErrorCode(error: unknown): string | undefined {
  return isRecord(error) && typeof error["code"] === "string"
    ? error["code"]
    : undefined;
}
