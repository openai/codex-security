import { stripVTControlCharacters } from "node:util";
import type { DependencyUse } from "./dependency-reachability.js";
import { formatSecurityPolicyText } from "./security-policy.js";

type CallSite = { path: string; line: number };
export interface DependencyVerdictUpdate {
  use: DependencyUse;
  callSite: CallSite | undefined;
  reason: string;
  evidenceKeys: string[];
  sharedEvidenceKeys: string[];
}

function oneLine(value: string) {
  return formatSecurityPolicyText(
    stripVTControlCharacters(value)
      .replaceAll(/[\u0000-\u001F\u007F-\u009F\u2028\u2029\s]+/gu, " ")
      .trim(),
  );
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

interface Entry {
  caller: string;
  callerKey: string | undefined;
  scope: string;
  verdict: DependencyUse["verdict"];
  reason: string;
  signature: string;
  group: string | undefined;
}

interface Group {
  members: Map<string, Entry>;
  calls: Map<string, number>;
  lastSummary?: string;
}

export function createDependencyVerdictProgress(
  subject: string,
  output: { write: (text: string) => unknown },
) {
  // Multiple submitted IDs can name one call and selected place. Keep their
  // latest accepted opinions so withdrawing an alias doesn't erase another.
  const byItem = new Map<string, { assessment: string; entry: Entry }>();
  const assessments = new Map<string, Map<string, Entry>>();
  const groups = new Map<string, Group>();
  const dirty = new Set<string>();
  let scheduled: ReturnType<typeof setImmediate> | undefined;

  function write(entry: Entry, label: string, suffix = "") {
    try {
      output.write(
        `[${new Date().toISOString()}] reviewed ${oneLine(subject)} ${entry.caller}${entry.scope} ${label}${suffix} — ${entry.reason}\n`,
      );
    } catch {
      // Progress is best-effort and cannot change the assessment outcome.
    }
  }

  function summary(group: Group) {
    const calls = group.calls.size;
    const distinct = `${calls} callsite${calls === 1 ? "" : "s"}`;
    return group.members.size === calls
      ? distinct
      : `${distinct}, ${group.members.size} assessments`;
  }

  function flush() {
    if (scheduled) clearImmediate(scheduled);
    scheduled = undefined;
    for (const key of dirty) {
      const group = groups.get(key)!;
      const first = group.members.values().next().value;
      if (!first) {
        groups.delete(key);
        continue;
      }
      const current = summary(group);
      if (current === group.lastSummary) continue;
      write(first, first.verdict, ` (${current})`);
      group.lastSummary = current;
    }
    dirty.clear();
  }

  function updateGroup(
    key: string | undefined,
    assessment: string,
    entry?: Entry,
  ) {
    if (key === undefined) return;
    let group = groups.get(key);
    if (!group) {
      if (!entry) return;
      group = { members: new Map(), calls: new Map() };
      groups.set(key, group);
    }
    const prior = group.members.get(assessment);
    if ((entry === undefined) !== (prior === undefined)) {
      const caller = (entry ?? prior)!.callerKey!;
      const count = (group.calls.get(caller) ?? 0) + (entry ? 1 : -1);
      if (count) group.calls.set(caller, count);
      else group.calls.delete(caller);
    }
    if (entry) group.members.set(assessment, entry);
    else group.members.delete(assessment);
    if (!group.members.size && !dirty.has(key)) groups.delete(key);
    return group;
  }

  function schedule(key: string | undefined) {
    if (key === undefined || !groups.has(key)) return;
    dirty.add(key);
    scheduled ??= setImmediate(flush);
  }

  function revise(
    assessment: string,
    id: string,
    entry?: Entry,
    previousPlace?: Entry,
  ) {
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
    if (previous?.group !== current?.group)
      updateGroup(previous?.group, assessment);
    if (!current) return;
    const anotherPlace =
      current.group !== undefined &&
      current.callerKey !== undefined &&
      groups.get(current.group)?.calls.has(current.callerKey);
    const group = updateGroup(current.group, assessment, current);
    // Retiring an unapproved revision only changes future group counts.
    if (!entry) return;
    const prior = previous ?? previousPlace;
    if (prior?.group !== current.group) schedule(prior?.group);
    schedule(current.group);
    if (
      prior?.signature === current.signature &&
      prior.group === current.group
    ) {
      if (group?.members.size === 1 && group.lastSummary === undefined)
        group.lastSummary = summary(group);
      return;
    }
    if (prior && prior.verdict !== current.verdict) {
      write(current, `corrected ${prior.verdict} → ${current.verdict}`);
      if (group?.members.size === 1) group.lastSummary = summary(group);
    } else if (
      !group ||
      group.lastSummary === undefined ||
      (prior && prior.group !== current.group) ||
      (!prior && anotherPlace)
    ) {
      write(current, prior ? `updated ${current.verdict}` : current.verdict);
      if (group && group.lastSummary === undefined)
        group.lastSummary = summary(group);
    }
  }

  return {
    update(id: string, review?: DependencyVerdictUpdate) {
      const old = byItem.get(id);
      if (!review) {
        if (old) revise(old.assessment, id);
        return;
      }
      const { use, callSite, reason, evidenceKeys, sharedEvidenceKeys } =
        review;
      const anchor = callSite ?? use.proof?.sink?.callSite;
      if (!anchor) return;
      const caller = oneLine(`${anchor.path}:${anchor.line}`);
      const source = callSite && `${callSite.path}:${callSite.line}`;
      const place = use.place;
      const label = source
        ? use.location
            .replace(`(${source})`, "")
            .replace(source, "")
            .trim()
            .replace(/^\((.*)\)$/u, "$1")
        : `sink, caller unresolved, submitted location: ${use.location}`;
      const selection = [
        place?.deploymentDetail,
        place?.environment,
        place?.revision,
        place?.artifact,
        place?.dependencySelection,
        place?.observationWindow,
        place?.deploymentBasis,
      ];
      // Keep descriptive proof and full identity in the assessment and report.
      const scope = shortenedLine(
        [
          shortenedLine(label, 88),
          place?.environment,
          shortenedLine(place?.artifact ?? place?.revision ?? "", 28),
          place?.observationWindow,
          place?.deploymentBasis !== "unknown" && place?.deploymentBasis,
        ]
          .filter((part) => part && part !== use.verdict)
          .join(", "),
        120,
      );
      const assessment = JSON.stringify([
        source ?? id,
        use.proof?.sink?.function,
        use.component,
        place?.kind,
        label,
        selection,
      ]);
      const text = oneLine(reason);
      const group =
        source && use.verdict === "ruled_out" && sharedEvidenceKeys.length
          ? JSON.stringify([
              use.component,
              oneLine(use.reason.replaceAll(source, "<callsite>")),
              oneLine(reason.replaceAll(source, "<callsite>")),
              [...sharedEvidenceKeys].sort(),
            ])
          : undefined;
      if (old && old.assessment !== assessment) revise(old.assessment, id);
      const entry = {
        caller,
        callerKey: source,
        scope: scope ? ` (${scope})` : "",
        verdict: use.verdict,
        reason: shortenedLine(
          use.proof?.conditions.find(
            ({ status, explanation }) =>
              status === use.verdict && oneLine(explanation),
          )?.explanation ?? reason,
          180,
        ),
        signature: JSON.stringify([
          caller,
          use.verdict,
          use.reason,
          text,
          [...evidenceKeys].sort(),
        ]),
        group,
      };
      byItem.set(id, { assessment, entry });
      revise(
        assessment,
        id,
        entry,
        old?.entry.callerKey === source ? old?.entry : undefined,
      );
    },
    flush,
  };
}
