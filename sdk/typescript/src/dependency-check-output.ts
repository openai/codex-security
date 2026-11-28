import { stripVTControlCharacters } from "node:util";
import { dependencyRecordHash } from "./dependency-attempt-store.js";
import { premiseKey } from "./dependency-review-queue.js";
import type {
  Decision,
  VerifiedUse,
  reportedDeployment,
} from "./dependency-reviewed-claims.js";
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
import type { DependencyBlockDetails } from "./dependency-reachability.js";
import type { DependencyPackage } from "./dependency-advisory.js";
import { formatSecurityPolicyText } from "./security-policy.js";
import { asRecord, isRecord } from "./record.js";
import { dependencyVerdictLabels } from "./dependency-reachability.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import type { DependencyTarget } from "./dependency-source-identity.js";

export type BlockedCheck = {
  target?: DependencyTarget;
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
        subject?: string;
        analyzers?: Record<string, unknown>;
        pendingAnalyzers?: string[];
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

export interface PreparedAnalyzer {
  name: string;
  run: (emit: DependencyProgressSink) => Promise<unknown>;
}

export async function runPreparedAnalyzers(
  plans: readonly PreparedAnalyzer[],
  subject: string,
  emit: DependencyProgressSink,
  signal: AbortSignal,
) {
  if (!plans.length)
    throw new CodexSecurityError(
      "No analyzer has input. Supply --analyzer-input stacks=DIR or enable the repository analyzer.",
    );
  if (plans.length === 1) return plans[0]!.run(emit);

  const analyzers: Record<string, unknown> = {};
  for (const [index, { name, run }] of plans.entries()) {
    signal.throwIfAborted();
    const progress: DependencyProgressSink = (type, target, details) =>
      emit(type, target, { ...details, analyzer: name });
    try {
      analyzers[name] = await run(progress);
    } catch (error) {
      signal.throwIfAborted();
      const blocked: BlockedCheck =
        error instanceof DependencyInvestigationBlockedError
          ? error.outcome
          : {
              status: "blocked",
              code: "INVESTIGATION_BLOCKED",
              reason: errorMessage(error),
            };
      analyzers[name] = blocked;
      throw new DependencyInvestigationBlockedError(
        {
          subject,
          analyzers,
          status: "blocked",
          code: "INVESTIGATION_BLOCKED",
          reason: `${name}: ${blocked.reason}`,
          pendingAnalyzers: plans.slice(index + 1).map((plan) => plan.name),
        },
        error,
      );
    }
  }
  return { subject, analyzers };
}

const defaultStages: Record<string, string> = {
  advisory: "advisory_lookup",
  discovery: "investigate",
  investigation: "investigate",
  review: "review",
};
const stages: Record<string, string> = {
  osv: "Looking up advisories in OSV",
  advisory_lookup: "Looking up advisories",
  advisory_analysis: "Identifying trigger conditions from advisories",
  supplied_advisory: "Using the supplied vulnerability description",
  investigate: "Starting source investigation",
  review: "Reviewing evidence",
  review_follow_up: "Investigating questions raised by review",
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
const verdictNames = Object.fromEntries(
  Object.entries(dependencyVerdictLabels).map(([key, label]) => [
    key,
    label.toLowerCase(),
  ]),
);

function progressParts(...parts: unknown[]) {
  return parts.filter(Boolean).join(" · ");
}

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
      return progressParts(
        "Proposed sink",
        fields["function"],
        fields["path"] &&
          `${fields["path"]}${fields["line"] ? ":" + fields["line"] : ""}`,
      );
    case "activity_started": {
      const scope = asRecord(fields["scope"]) ?? {};
      return progressParts(
        activities[String(fields["activity"])],
        scope["upstream"] ?? pathList(scope["files"] ?? scope["directories"]),
        scope["symbol"],
      );
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
      return progressParts(
        verdictNames[String(fields["verdict"])],
        fields["location"],
        fields["scope"],
        fields["reason"],
        fields["previousVerdict"] &&
          `previously ${verdictNames[String(fields["previousVerdict"])]}`,
      );
    case "reviewed_group":
      return `${verdictNames[String(fields["verdict"])]} · ${fields["callsites"]} reviewed calls · ${fields["location"]}`;
    case "report_ready": {
      const counts = Object.entries(asRecord(fields["verdicts"]) ?? {}).filter(
        ([, n]) => typeof n === "number" && n > 0,
      );
      return progressParts(
        "Investigation summary",
        ...counts.map(([key, n]) => `${n} ${verdictNames[key]}`),
        !counts.length && "0 reviewed uses",
        fields["limitations"] && `${fields["limitations"]} limitations`,
        fields["path"] && `Report saved · ${fields["path"]}`,
      );
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
  const root = asRecord(report);
  const checks = root?.["checks"];
  const analyzers = asRecord(root?.["analyzers"]);
  const results = analyzers
    ? Object.values(analyzers)
    : Array.isArray(checks)
      ? checks
      : [report];
  for (const check of results) {
    if (!isRecord(check)) continue;
    if (Array.isArray(check["limitations"]))
      limitations += check["limitations"].length;
    const uses = check["uses"] ?? check["assessments"];
    if (!Array.isArray(uses)) continue;
    for (const use of uses) {
      const verdict = asRecord(use)?.["verdict"];
      if (typeof verdict === "string" && Object.hasOwn(verdicts, verdict))
        verdicts[verdict as keyof typeof verdicts]++;
    }
  }
  return { verdicts, limitations };
}

export async function writeDependencyReportFile(
  reportFile: string,
  result: unknown,
  signal: AbortSignal,
  format: "html" | "json" = "json",
) {
  signal.throwIfAborted();
  const content =
    format === "html"
      ? (
          await import("./dependency-report-renderer.js")
        ).renderDependencyReport(result)
      : JSON.stringify(result, null, 2) + "\n";
  const staging = await mkdtemp(
    join(dirname(reportFile), ".dependency-report-"),
  );
  const path = join(staging, "report");
  try {
    await writeFile(path, content, {
      flag: "wx",
      mode: 0o600,
    });
    signal.throwIfAborted();
    await link(path, reportFile);
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => {});
  }
}

export async function withDependencyCheckOutput<T>(
  options: {
    subject: string;
    checkout?: string;
    display?: (line: string) => void;
    reportFile?: string;
    reportFormat?: "html" | "json";
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
          options.display(
            formatSecurityPolicyText(
              progressParts(subject, details?.["analyzer"], label),
            ),
          );
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
    const phase = defaultStages[type];
    writeEvent(type, subject, details);
    if (phase)
      writeEvent("stage", subject, {
        stage: details?.["stage"] ?? phase,
        ...(typeof details?.["analyzer"] === "string" && {
          analyzer: details["analyzer"],
        }),
      });
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
    if (reportFile)
      await writeDependencyReportFile(
        reportFile,
        result,
        signal,
        options.reportFormat,
      );
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

function oneLine(value: string): string {
  return formatSecurityPolicyText(
    stripVTControlCharacters(value)
      .replaceAll(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\s]+/gu, " ")
      .trim(),
  );
}

type CallSite = { path: string; line: number };
const callLocation = (s: CallSite) => s.path + ":" + s.line;
const covers = (
  range: { path: string; startLine: number; endLine: number },
  s: CallSite,
) =>
  range.path === s.path && range.startLine <= s.line && s.line <= range.endLine;

function reviewedDependencyCallSite(
  use: VerifiedUse,
  candidates: readonly CallSite[],
): CallSite | undefined {
  // Prefer an explicitly cited caller over the inner sink shared by wrappers.
  const anchors = new Map<string, CallSite>();
  for (const [path, ranges] of Map.groupBy(use.evidence, ({ path }) => path)) {
    const prefix = `${path}:`;
    for (
      let index = use.location.indexOf(prefix);
      index >= 0;
      index = use.location.indexOf(prefix, index + prefix.length)
    ) {
      if (index > 0 && /[^\s(\[]/u.test(use.location[index - 1]!)) continue;
      const match = /^(\d+)(?=$|[\s),;\]])/u.exec(
        use.location.slice(index + prefix.length),
      );
      const site = { path, line: Number(match?.[1]) };
      if (ranges.some((range) => covers(range, site)))
        anchors.set(callLocation(site), site);
    }
  }
  const sink = use.proof.sink?.callSite;
  if (anchors.size > 1 && sink) anchors.delete(callLocation(sink));
  if (!anchors.size)
    for (const site of candidates) {
      if (sink && callLocation(site) === callLocation(sink)) continue;
      if (use.evidence.some((range) => covers(range, site)))
        anchors.set(callLocation(site), site);
    }
  return anchors.size === 1 ? anchors.values().next().value : undefined;
}

/** Compare only approvals grounded in the same exclusion or independently approved premise. */
function sharedVerdictEvidence(
  use: VerifiedUse,
  callSite: CallSite | undefined,
  evidenceKeys: readonly string[],
) {
  if (use.verdict !== "ruled_out" || !callSite) return [];
  const keys = new Set(evidenceKeys);
  const exclusions = use.proof.conditions
    .filter((condition) => condition.status === "ruled_out")
    .flatMap((condition) => condition.citations);
  const shared =
    use.evidence.some(
      (ref) =>
        keys.has(dependencyRecordHash(ref)) &&
        !covers(ref, callSite) &&
        exclusions.some((site) => covers(ref, site)),
    ) || use.premises?.some((ref) => keys.has(premiseKey(ref)));
  if (!shared) return [];
  const protectedSites = use.proof.conditions.flatMap(
    (condition) => condition.citations,
  );
  if (use.proof.sink) protectedSites.push(use.proof.sink.callSite);
  for (const source of use.evidence) {
    if (
      source.startLine === source.endLine &&
      covers(source, callSite) &&
      !protectedSites.some((site) => covers(source, site)) &&
      keys.delete(dependencyRecordHash(source))
    )
      keys.add("caller-line:" + dependencyRecordHash(source.excerpt));
  }
  return [...keys];
}

interface DependencyVerdictUpdate {
  use: VerifiedUse;
  place: ReturnType<typeof reportedDeployment>["place"];
  callers: readonly CallSite[];
  decision: Pick<Decision, "reason" | "evidenceKeys">;
}

function shortenedLine(value: string, maxLength: number): string {
  const line = oneLine(value);
  if (line.length <= maxLength) return line;
  const characters = [...line];
  return characters.length <= maxLength
    ? line
    : `${characters
        .slice(0, maxLength - 1)
        .join("")
        .trimEnd()}…`;
}

function proofGroupKey(
  use: VerifiedUse,
  source: string,
  sharedEvidenceKeys: string[],
) {
  const normalize = (value: string) =>
    oneLine(value.replaceAll(source, "<callsite>"));
  const conditions = use.proof.conditions
    .filter(({ status }) => status === "ruled_out")
    .map(({ label, explanation, citations }) => ({
      label,
      explanation: normalize(explanation),
      citations: citations.map(callLocation).sort(),
    }));
  return JSON.stringify([
    use.component,
    [...sharedEvidenceKeys].sort(),
    conditions.length ? conditions : normalize(use.reason),
  ]);
}

function reviewedEntry(id: string, review: DependencyVerdictUpdate) {
  const { use, place, callers, decision } = review;
  const { reason, evidenceKeys } = decision;
  const callSite = reviewedDependencyCallSite(use, callers);
  const anchor = callSite ?? use.proof.sink?.callSite;
  if (!anchor) return;
  const caller = oneLine(callLocation(anchor));
  const source = callSite && callLocation(callSite);
  const sharedEvidenceKeys = sharedVerdictEvidence(use, callSite, evidenceKeys);
  const label = source
    ? use.location
        .replace(`(${source})`, "")
        .replace(source, "")
        .trim()
        .replace(/^\((.*)\)$/u, "$1")
    : `submitted location: ${use.location}`;
  const selection = [
    place.deploymentDetail,
    place.environment,
    place.revision,
    place.artifact,
    place.dependencySelection,
    place.observationWindow,
    place.deploymentBasis,
  ];
  // Keep descriptive proof and full identity in the assessment and report.
  const scope = shortenedLine(
    [
      shortenedLine(label, 88),
      place.environment,
      shortenedLine(place.artifact ?? place.revision ?? "", 28),
      place.observationWindow,
      place.deploymentBasis !== "unknown" && place.deploymentBasis,
    ]
      .filter((part) => part && part !== use.verdict)
      .join(", "),
    120,
  );
  const assessment = JSON.stringify([
    source ?? id,
    use.proof.sink?.function,
    use.component,
    place.kind,
    label,
    selection,
  ]);
  const decisive =
    use.verdict === "ruled_out" || use.verdict === "unknown"
      ? use.verdict
      : "met";
  const group =
    source && use.verdict === "ruled_out" && sharedEvidenceKeys.length
      ? proofGroupKey(use, source, sharedEvidenceKeys)
      : undefined;
  return {
    assessment,
    caller,
    callerKey: source,
    locationKind: callSite ? "caller" : "sink",
    scope,
    verdict: use.verdict,
    component: oneLine(use.component),
    version: use.version && oneLine(use.version),
    reason: shortenedLine(
      use.proof.conditions.find(
        ({ status, explanation }) =>
          status === decisive && oneLine(explanation),
      )?.explanation ??
        (use.verdict === "unknown"
          ? place.unresolvedQuestions.find(oneLine)
          : undefined) ??
        reason,
      180,
    ),
    signature: JSON.stringify([
      caller,
      use.verdict,
      use.reason,
      reason,
      [...evidenceKeys].sort(),
    ]),
    group,
  };
}

type Entry = NonNullable<ReturnType<typeof reviewedEntry>>;

interface Group {
  members: Map<string, Entry>;
  calls: Map<string, number>;
  id: string;
  representative: Entry;
  lastCount?: { callsites: number; assessments: number };
}

export function createDependencyVerdictProgress(
  subject: string,
  emit: DependencyProgressSink | undefined,
) {
  // Multiple submitted IDs can name one call and selected place. Keep their
  // latest accepted opinions so withdrawing an alias doesn't erase another.
  const byItem = new Map<string, Entry>();
  const assessments = new Map<string, Map<string, Entry>>();
  const groups = new Map<string, Group>();
  const dirty = new Set<string>();
  let nextGroup = 0;

  function currentCount(group: Group) {
    return { callsites: group.calls.size, assessments: group.members.size };
  }

  function flush() {
    for (const key of dirty) {
      const group = groups.get(key)!;
      const first = group.members.values().next().value ?? group.representative;
      if (group.members.size === 0) {
        groups.delete(key);
        if (!group.lastCount) continue;
      }
      const count = currentCount(group);
      if (
        count.callsites === group.lastCount?.callsites &&
        count.assessments === group.lastCount?.assessments
      )
        continue;
      emit?.("reviewed_group", subject, {
        location: first.caller,
        verdict: first.verdict,
        reason: first.reason,
        groupId: group.id,
        ...count,
      });
      group.lastCount = count;
    }
    dirty.clear();
  }

  function joinGroup(entry: Entry) {
    const { assessment, group: key, callerKey } = entry;
    if (!key || !callerKey) return;
    let group = groups.get(key);
    if (!group) {
      group = {
        id: `${subject}:${++nextGroup}`,
        members: new Map(),
        calls: new Map(),
        representative: entry,
      };
      groups.set(key, group);
    }
    const places = group.calls.get(callerKey) ?? 0;
    if (!group.members.has(assessment)) group.calls.set(callerKey, places + 1);
    group.members.set(assessment, entry);
    return { group, anotherPlace: places > 0 };
  }

  function revise(assessment: string, id: string, entry?: Entry) {
    const entries = assessments.get(assessment) ?? new Map<string, Entry>();
    const previous = [...entries.values()].at(-1);
    entries.delete(id);
    if (entry) entries.set(id, entry);
    if (entries.size) assessments.set(assessment, entries);
    else assessments.delete(assessment);
    const current = entry ?? [...entries.values()].at(-1);
    if (
      previous?.signature === current?.signature &&
      previous?.group === current?.group
    )
      return;
    if (previous?.group && previous.group !== current?.group) {
      const group = groups.get(previous.group)!;
      const caller = previous.callerKey!;
      const places = group.calls.get(caller)! - 1;
      if (places) group.calls.set(caller, places);
      else group.calls.delete(caller);
      group.members.delete(assessment);
      dirty.add(previous.group);
    }
    if (!current) return;
    const membership = joinGroup(current);
    // A withdrawal can restore an alias but does not announce a new verdict.
    if (!entry) return;
    const old = byItem.get(id);
    const prior =
      previous ?? (old?.callerKey === current.callerKey ? old : undefined);
    if (prior?.group && groups.has(prior.group)) dirty.add(prior.group);
    if (current.group) dirty.add(current.group);

    const group = membership?.group;
    const changed = prior && prior.verdict !== current.verdict;
    if (!changed && membership?.group.lastCount) {
      // Coalesce new callers, but show distinct deployments at the same caller.
      if (prior ? prior.group === current.group : !membership.anotherPlace)
        return;
    }
    if (!group && !prior?.group && prior?.signature === current.signature)
      return;
    emit?.("reviewed", subject, {
      location: current.caller,
      locationKind: current.locationKind,
      ...(current.scope && { scope: current.scope }),
      verdict: current.verdict,
      component: current.component,
      ...(current.version && { version: current.version }),
      ...(changed && { previousVerdict: prior.verdict }),
      reason: current.reason,
      ...(group && { groupId: group.id }),
    });
    if (group && (changed ? group.members.size === 1 : !group.lastCount))
      group.lastCount = currentCount(group);
  }

  return {
    update(id: string, review?: DependencyVerdictUpdate) {
      const old = byItem.get(id);
      if (!review) {
        if (old) revise(old.assessment, id);
        return;
      }
      const entry = reviewedEntry(id, review);
      if (!entry) return;
      if (old && old.assessment !== entry.assessment)
        revise(old.assessment, id);
      revise(entry.assessment, id, entry);
      byItem.set(id, entry);
    },
    flush,
  };
}
