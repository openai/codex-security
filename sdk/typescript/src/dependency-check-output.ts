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
import type { DependencyBlockDetails } from "./dependency-blocked-schema.js";
import type { DependencyPackage } from "./dependency-advisory.js";
import { formatSecurityPolicyText } from "./security-policy.js";
import { isRecord } from "./record.js";
import { CodexSecurityError, errorMessage } from "./errors.js";

export type BlockedCheck = {
  status: "blocked";
  code: "INVESTIGATION_BLOCKED";
  reason: string;
};
export class DependencyInvestigationBlockedError extends CodexSecurityError {
  constructor(
    readonly outcome: BlockedCheck &
      Partial<DependencyBlockDetails> & {
        cve?: string;
        package?: DependencyPackage;
        checks?: unknown[];
        pendingAdvisories?: (string | null)[];
      },
    cause: unknown,
  ) {
    super(`Dependency investigation blocked: ${outcome.reason}`, { cause });
  }
}

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

const stages: Record<string, string> = {
  osv: "Looking up advisories in OSV",
  advisory_lookup: "Looking up advisories",
  advisory_analysis: "Identifying trigger conditions from advisories",
  supplied_advisory: "Using the supplied vulnerability description",
  investigate: "Starting source investigation",
  review: "Reviewing evidence",
};
const activities: Record<string, string> = {
  opengrep: "Searching with OpenGrep",
  trace: "Tracing source call paths",
  source_search: "Searching source",
  source_read: "Reading source",
  upstream: "Fetching upstream source",
  catalog: "Looking up services in the catalog",
  runtime: "Checking runtime inventory",
  profiles: "Checking runtime stacks",
};
const verdictNames: Record<string, string> = {
  exploitable: "exploitable",
  potentially_exploitable: "potentially exploitable",
  ruled_out: "ruled out",
  unknown: "requires more information",
};

function pathList(value: unknown) {
  if (!Array.isArray(value)) return "";
  const paths = [
    ...new Set(value.filter((p): p is string => typeof p === "string")),
  ];
  return [
    ...paths.slice(0, 3),
    ...(paths.length > 3 ? [`+${paths.length - 3} more`] : []),
  ].join(", ");
}

function progressLine(type: string, fields: Record<string, unknown>) {
  switch (type) {
    case "started":
      return "Preparing the checkout";
    case "stage":
      return stages[String(fields["stage"])];
    case "advisory_lookup_failed":
      return `Public advisory lookup failed: ${fields["error"]}. Continuing with the supplied advisory only`;
    case "advisories_loaded":
      return `Loaded ${fields["count"]} advisory records`;
    case "access_program":
      return fields["program"] === "unconfirmed"
        ? "Turn access program unconfirmed"
        : `Turn access program · ${fields["program"]}`;
    case "advisory_summary":
      return `Advisory · ${fields["summary"]}`;
    case "proposed_sink":
      return [
        "Proposed sink",
        fields["function"],
        fields["path"] &&
          `${fields["path"]}${fields["line"] ? ":" + fields["line"] : ""}`,
      ]
        .filter(Boolean)
        .join(" · ");
    case "activity_started": {
      const scope = isRecord(fields["scope"]) ? fields["scope"] : {};
      return [
        activities[String(fields["activity"])],
        scope["upstream"] ?? pathList(scope["files"] ?? scope["directories"]),
        scope["symbol"],
      ]
        .filter(Boolean)
        .join(" · ");
    }
    case "activity_finished": {
      const paths = pathList(fields["searchedPaths"]);
      if (paths)
        return `${fields["outcome"] === "partial" ? "Partial search" : "Searched"} · ${paths}`;
      if (fields["outcome"] === "failed")
        return `${activities[String(fields["activity"])]} failed`;
      return;
    }
    case "reviewed":
      return [
        verdictNames[String(fields["verdict"])],
        fields["location"],
        fields["scope"],
        fields["reason"],
        fields["previousVerdict"] &&
          `previously ${verdictNames[String(fields["previousVerdict"])]}`,
      ]
        .filter(Boolean)
        .join(" · ");
    case "reviewed_group":
      return `${verdictNames[String(fields["verdict"])]} · ${fields["callsites"]} reviewed calls · ${fields["location"]}`;
    case "report_ready": {
      const counts = Object.entries(
        isRecord(fields["verdicts"]) ? fields["verdicts"] : {},
      ).filter(([, n]) => typeof n === "number" && n > 0);
      return [
        "Investigation summary",
        ...counts.map(([key, n]) => `${n} ${verdictNames[key]}`),
        !counts.length && "0 reviewed uses",
        fields["limitations"] && `${fields["limitations"]} limitations`,
        fields["path"] && `Report saved · ${fields["path"]}`,
      ]
        .filter(Boolean)
        .join(" · ");
    }
    case "finished":
      if (fields["outcome"] !== "completed")
        return `Investigation ${fields["outcome"]}`;
  }
}

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
    if (options.display) {
      // Optional terminal progress must not change whether the report is saved.
      try {
        const label = progressLine(type, details ?? {});
        if (label)
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
