import { closeSync, fstatSync, openSync, writeFileSync } from "node:fs";
import {
  link,
  lstat,
  mkdtemp,
  realpath,
  rm,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, relative } from "node:path";
import { DependencyInvestigationBlockedError } from "./dependency-reviewed-check.js";
import { CodexSecurityError, errorMessage } from "./errors.js";

async function existing(path: string) {
  return lstat(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
    return undefined;
  });
}
const separateOutputs = "Report and progress files must have different paths.";

export async function withDependencyCheckOutput<T>(
  options: {
    subject: string;
    reportFile?: string;
    progressEvents?: string;
    signal: AbortSignal;
    warn: (message: string) => void;
  },
  run: (emit: (type: string, subject?: string) => void) => Promise<T>,
): Promise<T> {
  const { reportFile, progressEvents, signal } = options;
  if (reportFile && progressEvents) {
    const candidate = await realpath(dirname(progressEvents)).catch(
      () => undefined,
    );
    const parent = await realpath(dirname(reportFile));
    if (
      candidate &&
      !relative(
        join(parent, basename(reportFile)),
        join(candidate, basename(progressEvents)),
      )
    )
      throw new CodexSecurityError(separateOutputs);
  }
  if (reportFile) {
    if (await existing(reportFile))
      throw new CodexSecurityError(
        `Report destination already exists: ${reportFile}`,
      );
    if (!(await stat(dirname(reportFile))).isDirectory())
      throw new CodexSecurityError(
        "Report destination requires an existing parent directory.",
      );
  }
  let fd: number | undefined;
  let failedProgress = false;
  function warn(error: unknown) {
    if (!failedProgress)
      options.warn(
        `Could not write dependency progress: ${errorMessage(error)}`,
      );
    failedProgress = true;
  }
  if (progressEvents) {
    try {
      fd = openSync(progressEvents, "wx", 0o600);
    } catch (error) {
      warn(error);
    }
  }
  function emit(type: string, subject = options.subject) {
    if (fd === undefined || failedProgress) return;
    try {
      writeFileSync(
        fd,
        JSON.stringify({ timestamp: new Date().toISOString(), type, subject }) +
          "\n",
      );
    } catch (error) {
      warn(error);
    }
  }
  try {
    // A case-insensitive volume may alias differently spelled new file names.
    if (fd !== undefined && progressEvents && reportFile) {
      const target = await existing(reportFile),
        own = fstatSync(fd);
      if (target && target.dev === own.dev && target.ino === own.ino) {
        closeSync(fd);
        fd = undefined;
        await unlink(progressEvents);
        throw new CodexSecurityError(separateOutputs);
      }
    }
    signal.throwIfAborted();
    emit("started");
    const result = await run(emit);
    signal.throwIfAborted();
    if (reportFile) {
      const staging = await mkdtemp(
        join(dirname(reportFile), ".dependency-report-"),
      );
      const path = join(staging, "report.json");
      try {
        await writeFile(path, JSON.stringify(result, null, 2) + "\n", {
          flag: "wx",
          mode: 0o600,
        });
        signal.throwIfAborted();
        await link(path, reportFile);
      } finally {
        await rm(staging, { recursive: true, force: true }).catch(() => {});
      }
    }
    emit("report_ready");
    return result;
  } catch (error) {
    emit(
      signal.aborted
        ? "interrupted"
        : error instanceof DependencyInvestigationBlockedError
          ? "blocked"
          : "failed",
    );
    throw error;
  } finally {
    if (fd !== undefined)
      try {
        closeSync(fd);
      } catch (error) {
        warn(error);
      }
  }
}
