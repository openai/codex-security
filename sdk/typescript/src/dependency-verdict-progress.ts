import type { DependencyProgressEvent } from "./dependency-progress.js";
import { progressText as oneLine } from "./dependency-progress.js";
import type { DependencyUse } from "./dependency-reachability.js";

type CallSite = { path: string; line: number };
export interface DependencyVerdictUpdate {
  use: DependencyUse;
  callSite: CallSite | undefined;
  reason: string;
  evidenceKeys: string[];
  sharedEvidenceKeys: string[];
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
  use: DependencyUse,
  source: string,
  sharedEvidenceKeys: string[],
) {
  const normalize = (value: string) =>
    oneLine(value.replaceAll(source, "<callsite>"));
  const conditions = use.proof?.conditions
    .filter(({ status }) => status === "ruled_out")
    .map(({ label, explanation, citations }) => ({
      label,
      explanation: normalize(explanation),
      citations: citations.map(({ path, line }) => `${path}:${line}`).sort(),
    }));
  return JSON.stringify([
    use.component,
    [...sharedEvidenceKeys].sort(),
    conditions?.length ? conditions : normalize(use.reason),
  ]);
}

interface Entry {
  caller: string;
  callerKey: string | undefined;
  locationKind: "caller" | "sink";
  scope: string;
  verdict: DependencyUse["verdict"];
  component: string;
  version: string | null;
  reason: string;
  signature: string;
  group: string | undefined;
}

interface Group {
  members: Map<string, Entry>;
  calls: Map<string, number>;
  id: string;
  representative: Entry;
  lastCount?: { callsites: number; assessments: number };
}

export function createDependencyVerdictProgress(
  subject: string,
  emit: (event: DependencyProgressEvent) => void,
) {
  // Multiple submitted IDs can name one call and selected place. Keep their
  // latest accepted opinions so withdrawing an alias doesn't erase another.
  const byItem = new Map<string, { assessment: string; entry: Entry }>();
  const assessments = new Map<string, Map<string, Entry>>();
  const groups = new Map<string, Group>();
  const dirty = new Set<string>();
  let scheduled: ReturnType<typeof setImmediate> | undefined;

  let nextGroup = 0;

  function publish(
    entry: Entry,
    group?: Group,
    previousVerdict?: Entry["verdict"],
  ) {
    emit({
      type: "reviewed",
      subject,
      location: entry.caller,
      locationKind: entry.locationKind,
      ...(entry.scope && { scope: entry.scope }),
      verdict: entry.verdict,
      component: entry.component,
      ...(entry.version && { version: entry.version }),
      ...(previousVerdict && { previousVerdict }),
      reason: entry.reason,
      ...(group && { groupId: group.id }),
    });
  }

  function currentCount(group: Group) {
    return { callsites: group.calls.size, assessments: group.members.size };
  }

  function flush() {
    if (scheduled) clearImmediate(scheduled);
    scheduled = undefined;
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
      emit({
        type: "reviewed_group",
        subject,
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

  function updateGroup(
    key: string | undefined,
    assessment: string,
    entry?: Entry,
  ) {
    if (key === undefined) return;
    let group = groups.get(key);
    if (!group) {
      if (!entry) return;
      group = {
        id: `${subject}:${++nextGroup}`,
        members: new Map(),
        calls: new Map(),
        representative: entry,
      };
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
    if (previous?.group !== current?.group) {
      updateGroup(previous?.group, assessment);
      schedule(previous?.group);
    }
    if (!current) return;
    const anotherPlace =
      current.group !== undefined &&
      current.callerKey !== undefined &&
      groups.get(current.group)?.calls.has(current.callerKey);
    const group = updateGroup(current.group, assessment, current);
    // Retiring an unapproved revision changes the group count, without
    // publishing a new verdict for that assessment.
    if (!entry) return;
    const prior = previous ?? previousPlace;
    if (prior?.group !== current.group) schedule(prior?.group);
    schedule(current.group);
    if (
      prior?.signature === current.signature &&
      prior.group === current.group &&
      (!group || group.lastCount !== undefined)
    )
      return;
    if (prior && prior.verdict !== current.verdict) {
      publish(current, group, prior.verdict);
      if (group?.members.size === 1) group.lastCount = currentCount(group);
    } else if (
      !group ||
      group.lastCount === undefined ||
      (prior && prior.group !== current.group) ||
      (!prior && anotherPlace)
    ) {
      publish(current, group);
      if (group && group.lastCount === undefined)
        group.lastCount = currentCount(group);
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
        : `submitted location: ${use.location}`;
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
      const decisive =
        use.verdict === "ruled_out"
          ? "ruled_out"
          : use.verdict === "unknown"
            ? "unknown"
            : "met";
      const group =
        source && use.verdict === "ruled_out" && sharedEvidenceKeys.length
          ? proofGroupKey(use, source, sharedEvidenceKeys)
          : undefined;
      if (old && old.assessment !== assessment) revise(old.assessment, id);
      const entry: Entry = {
        caller,
        callerKey: source,
        locationKind: callSite ? "caller" : "sink",
        scope,
        verdict: use.verdict,
        component: oneLine(use.component),
        version: use.version && oneLine(use.version),
        reason: shortenedLine(
          use.proof?.conditions.find(
            ({ status, explanation }) =>
              status === decisive && oneLine(explanation),
          )?.explanation ??
            (use.verdict === "unknown"
              ? place?.unresolvedQuestions.find(oneLine)
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
