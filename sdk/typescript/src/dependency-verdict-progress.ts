import { dependencyRecordHash } from "./dependency-attempt-store.js";
import type { VerifiedUse } from "./dependency-reviewed-claims.js";
import { premiseKey } from "./dependency-review-queue.js";
import { stripVTControlCharacters } from "node:util";
import { formatSecurityPolicyText } from "./security-policy.js";
import type { ReviewedDependencyUse } from "./dependency-reachability.js";
import type { DependencyProgressSink } from "./dependency-check-output.js";

function oneLine(value: string): string {
  return formatSecurityPolicyText(
    stripVTControlCharacters(value)
      .replaceAll(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\s]+/gu, " ")
      .trim(),
  );
}

type DependencyUse = Pick<
  ReviewedDependencyUse,
  "location" | "component" | "version" | "verdict" | "reason" | "evidence"
> &
  Partial<
    Pick<
      ReviewedDependencyUse,
      "proof" | "place" | "observations" | "deployment"
    >
  >;
type CallSite = { path: string; line: number };
const callLocation = (s: CallSite) => s.path + ":" + s.line;
const covers = (
  range: { path: string; startLine: number; endLine: number },
  s: CallSite,
) =>
  range.path === s.path && range.startLine <= s.line && s.line <= range.endLine;

export function reviewedDependencyCallSite(
  use: DependencyUse,
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
  const sink = use.proof?.sink?.callSite;
  if (anchors.size > 1 && sink) anchors.delete(callLocation(sink));
  if (anchors.size) {
    return anchors.size === 1 ? anchors.values().next().value : undefined;
  }
  const callers = new Map<string, CallSite>();
  for (const { path, line } of candidates) {
    const site = { path, line };
    if (sink && callLocation(site) === callLocation(sink)) continue;
    if (use.evidence.some((range) => covers(range, site)))
      callers.set(callLocation(site), site);
  }
  return callers.size === 1 ? callers.values().next().value : undefined;
}

/** Compare only approvals grounded in the same exclusion or independently approved premise. */
export function sharedVerdictEvidence(
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
  emit: DependencyProgressSink | undefined,
  state: "reviewed" | "unreviewed" = "reviewed",
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
    emit?.(state, subject, {
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
      emit?.(state + "_group", subject, {
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
