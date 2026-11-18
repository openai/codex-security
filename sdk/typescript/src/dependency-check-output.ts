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
import { formatSecurityPolicyText } from "./security-policy.js";
import { isRecord } from "./record.js";
import { CodexSecurityError, errorMessage } from "./errors.js";

async function existing(path: string) {
  return lstat(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
    return undefined;
  });
}
const separateOutputs = "Report and progress files must have different paths.";

export type DependencyProgressSink = (
  type: string,
  subject?: string,
  details?: Record<string, unknown>,
) => void;

function reportSummary(report: unknown) {
  const verdicts = {
    exploitable: 0,
    potentially_exploitable: 0,
    ruled_out: 0,
    unknown: 0,
  };
  let limitations = 0;
  if (isRecord(report)) {
    for (const check of Array.isArray(report["checks"])
      ? report["checks"]
      : [report]) {
      if (!isRecord(check)) continue;
      if (Array.isArray(check["limitations"]))
        limitations += check["limitations"].length;
      const uses = check["uses"] ?? check["assessments"];
      if (Array.isArray(uses))
        for (const use of uses)
          if (
            isRecord(use) &&
            typeof use["verdict"] === "string" &&
            Object.hasOwn(verdicts, use["verdict"])
          )
            verdicts[use["verdict"] as keyof typeof verdicts]++;
    }
  }
  return { verdicts, limitations };
}

export async function withDependencyCheckOutput<T>(
  options: {
    subject: string;
    checkout?: string;
    display?: (line: string) => void;
    reportFile?: string;
    progressEvents?: string;
    signal: AbortSignal;
    warn: (message: string) => void;
  },
  run: (emit: DependencyProgressSink) => Promise<T>,
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
  const started = Date.now();
  function writeEvent(
    type: string,
    subject: string,
    details?: Record<string, unknown>,
  ) {
    if (
      options.display &&
      ![
        "activity_finished",
        "finished",
        "advisory",
        "discovery",
        "investigation",
        "review",
      ].includes(type)
    ) {
      // Optional terminal progress must not change whether the report is saved.
      try {
        const label =
          details?.["summary"] ??
          details?.["reason"] ??
          details?.["function"] ??
          details?.["activity"] ??
          details?.["stage"] ??
          type;
        options.display(formatSecurityPolicyText(`${subject} · ${label}`));
      } catch {}
    }
    if (fd === undefined || failedProgress) return;
    try {
      writeFileSync(
        fd,
        JSON.stringify({
          schemaVersion: 1,
          elapsedMs: Math.max(0, Date.now() - started),
          timestamp: new Date().toISOString(),
          type,
          subject,
          ...details,
        }) + "\n",
      );
    } catch (error) {
      warn(error);
    }
  }
  function emit(
    type: string,
    subject = options.subject,
    details?: Record<string, unknown>,
  ) {
    const phase = {
      advisory: "advisory_lookup",
      discovery: "investigate",
      investigation: "investigate",
      review: "review",
    }[type as "advisory" | "discovery" | "investigation" | "review"];
    writeEvent(type, subject, details);
    if (phase)
      writeEvent("stage", subject, { stage: details?.["stage"] ?? phase });
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
    emit("started", options.subject, {
      checkout: options.checkout ?? process.cwd(),
    });
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
    emit("report_ready", options.subject, {
      ...reportSummary(result),
      ...(reportFile && { path: reportFile }),
    });
    emit("finished", options.subject, { outcome: "completed" });
    return result;
  } catch (error) {
    const outcome = signal.aborted
      ? "interrupted"
      : error instanceof DependencyInvestigationBlockedError
        ? "blocked"
        : "failed";
    emit(outcome);
    emit("finished", options.subject, { outcome });
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
