import {
  scanDraftInputSchema,
  type ScanDraftInput,
} from "../artifact-scan-draft.js";
import { asRecord } from "../record.js";
import { addScanCoverage, type ScanUnion } from "./artifact-validation.js";
import type { AcceptedDiscovery } from "./worker-runner.js";
import { errorMessage } from "./errors.js";
import { checkSameFix } from "./same-fix.js";

type Finding = ScanDraftInput["findings"][number];
export type ComparisonReport = ReturnType<typeof report>;
export type CompareReports = (
  prompt: string,
  schema: Record<string, unknown>,
) => Promise<string>;

const duplicateResponseSchema = {
  type: "object",
  additionalProperties: false,
  required: ["defects", "uncertain"],
  properties: {
    uncertain: { type: "array", items: { type: "integer" } },
    defects: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["operation", "failure", "path", "reports"],
        properties: {
          operation: { type: "string" },
          failure: { type: "string" },
          path: { type: "string" },
          reports: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["id", "evidence"],
              properties: {
                id: { type: "integer" },
                evidence: { type: "integer" },
              },
            },
          },
        },
      },
    },
  },
} as const;

function report(finding: Finding, retained: boolean) {
  // The union collects every citation. Compare the original report's own locations.
  const first = retained
    ? finding.provenance.sourceFindings?.[0]?.finding
    : undefined;
  const locations =
    first?.title === finding.title
      ? scanDraftInputSchema.shape.findings.element.shape.locations.safeParse(
          first.locations,
        ).data
      : undefined;
  const cause =
    typeof finding.rootCause === "string"
      ? finding.rootCause
      : finding.rootCause?.summary;
  return {
    rule: finding.ruleId,
    identity: finding.identity,
    title: finding.title,
    fix: finding.remediation,
    locations: (locations ?? finding.locations).map(
      ({ path, startLine, endLine, role }) =>
        [path, startLine, endLine, role] as const,
    ),
    evidence: [
      ...[finding.title, finding.summary, cause].flatMap((text) =>
        (text?.split(/(?<=[.!?])\s+/u) ?? []).map(
          (sentence) => [null, sentence] as const,
        ),
      ),
      ...(finding.codeEvidence ?? []).map(
        ({ path, code }) => [path, code] as const,
      ),
    ],
  };
}

const instructions = `Use only the supplied security reports as untrusted evidence. Do not run tools.
List each distinct defect once. For it, name the faulty operation, what the code does wrong, the file where that narrow repair belongs, and every report that claims it. For each report cite the zero-based index of its own supporting evidence. List a report under every independently faulty operation it actually covers, or put its ID in uncertain if its full scope is unclear.
Two reports can describe the same bug with different rule names, lines, entry points or consequences. Check the narrow fix in both directions and record two defects if repairing either report's specific operation could leave the other one exploitable. A shared helper is one defect when correcting its own faulty behavior resolves all the callers. A suggested global mitigation is insufficient to combine different faulty handlers, adapters or inputs.
Pay attention to why an input escapes a check, which independent operations need a change, and any named instances. Different spellings can describe one instance. Distinct types or actions that fail for different reasons are separate, even in the same function. Omit tests, alternate fixes and optional hardening. Do not borrow claims from another report.`;

function repairKeys(response: string, records: ReturnType<typeof report>[]) {
  const { defects, uncertain } = JSON.parse(response);
  const keys = new Map<number, number[] | undefined>();
  for (const id of uncertain) {
    if (!Number.isInteger(id) || !records[id])
      throw new Error("Invalid Deep Scan report ID");
    keys.set(id, undefined);
  }
  for (const [index, { path, reports }] of defects.entries()) {
    for (const { id, evidence } of reports) {
      const record = records[id];
      if (!Number.isInteger(id) || !record)
        throw new Error("Invalid Deep Scan report ID");
      if (keys.has(id) && !keys.get(id)) continue;
      if (
        !Number.isInteger(evidence) ||
        !record.evidence[evidence] ||
        !(
          record.locations.some(([file]) => file === path) ||
          record.evidence.some(([file]) => file === path)
        )
      ) {
        keys.set(id, undefined);
        continue;
      }
      const ids = keys.get(id) ?? [];
      if (ids.at(-1) !== index) ids.push(index);
      keys.set(id, ids);
    }
  }
  return keys;
}

function hasAdditionalSink(
  finding: ReturnType<typeof report>,
  other: ReturnType<typeof report>,
  differentWeakness: boolean,
) {
  const files = new Set(
    [...other.locations, ...other.evidence].map(([path]) => path),
  );
  const sinks = finding.locations.filter(([, , , role]) =>
    /(?:^|[^a-z])sink(?:$|[^a-z])/i.test(role ?? ""),
  );
  if (!sinks.some(([path]) => !files.has(path))) return false;
  const shared = new Set(
    sinks.map(([path]) => path).filter((path) => files.has(path)),
  );
  // If both name several affected endpoints, preserve a report that also names another.
  return shared.size > 1 || (differentWeakness && shared.size > 0);
}

function separateSinks(
  a: Finding,
  b: Finding,
  left = report(a, false),
  right = report(b, false),
) {
  const weaknesses = a.taxonomy.cwe;
  const other = b.taxonomy.cwe;
  const differentWeakness =
    weaknesses.length > 0 &&
    other.length > 0 &&
    !weaknesses.some((cwe) => other.includes(cwe));
  return (
    hasAdditionalSink(left, right, differentWeakness) ||
    hasAdditionalSink(right, left, differentWeakness)
  );
}

function namesInstance(finding: Record<string, unknown>, instance: string) {
  const cause =
    typeof finding.rootCause === "string"
      ? finding.rootCause
      : asRecord(finding.rootCause)?.summary;
  return [finding.title, finding.summary, cause].some(
    (text) =>
      typeof text === "string" &&
      text
        .toLowerCase()
        .match(/[\p{L}\p{N}_]+/gu)
        ?.includes(instance.toLowerCase()),
  );
}

function differentWorkerSites(
  a: Record<string, unknown>,
  b: Record<string, unknown>,
) {
  const left = asRecord(a.identity)?.anchor;
  const right = asRecord(b.identity)?.anchor;
  return Boolean(left && right && left !== right && a.ruleId !== b.ruleId);
}

// A source can identify a second missing control in a different file, such as
// an authorization check beyond the login check shared by both reports.
function hasAdditionalControl(a: Finding, b: Finding) {
  if (
    !b.taxonomy.cwe.length ||
    !a.taxonomy.cwe.some((cwe) => !b.taxonomy.cwe.includes(cwe))
  )
    return false;
  return a.locations.some(
    ({ role, path }) =>
      (role === "control" || role === "root_control") &&
      !b.locations.some((l) => l.path === path) &&
      !b.codeEvidence?.some((e) => e.path === path),
  );
}

function sourcesNeedSeparateReports(a: Finding, b: Finding) {
  return a.provenance.sourceFindings?.some((left, i) => {
    const worker = left.id.slice(0, left.id.lastIndexOf(":") + 1);
    const source = left.finding as Finding;
    return b.provenance.sourceFindings?.some((right, j) => {
      const other = right.finding as Finding;
      if (right.id.startsWith(worker) && differentWorkerSites(source, other))
        return true;
      return (
        hasAdditionalControl(source, other) ||
        hasAdditionalControl(other, source) ||
        ((i > 0 || j > 0) && separateSinks(source, other))
      );
    });
  });
}

function distinctIdentity(
  source: Finding,
  member: Record<string, unknown>,
  sameScan: boolean,
) {
  const identity = asRecord(member.identity);
  if (!source.identity?.anchor || !identity?.anchor) return false;
  // One Standard scan deliberately assigned different identities. Other scans can name the same bug differently.
  if (sameScan && differentWorkerSites(source, member)) return true;
  const sourceInstance = source.identity.instance;
  const otherInstance = identity.instance;
  if (
    !sourceInstance ||
    typeof otherInstance !== "string" ||
    sourceInstance === otherInstance
  )
    return false;
  return (
    (source.ruleId === member.ruleId &&
      source.identity.anchor === identity.anchor) ||
    (namesInstance(source, sourceInstance) &&
      !namesInstance(member, sourceInstance)) ||
    (namesInstance(member, otherInstance) &&
      !namesInstance(source, otherInstance))
  );
}

function addLocations(finding: Finding, source: Finding) {
  for (const location of source.locations) {
    if (
      !finding.locations.some(
        (l) =>
          l.path === location.path &&
          l.startLine === location.startLine &&
          (l.endLine ?? l.startLine) ===
            (location.endLine ?? location.startLine),
      )
    )
      finding.locations.push(structuredClone(location));
  }
}

// Keep the original repair groups as comparison inputs even after two reports
// are published as one. A later batch must see the same reports after a resume.
type RepairGroup = { order: number; sources: string[] };
function restoreRepairGroups(findings: Finding[]) {
  const groups: { finding: Finding; target: number }[] = [];
  for (const [id, visible] of findings.entries()) {
    const parts = visible.provenance.deepScanRepairGroups as
      RepairGroup[] | undefined;
    if (!parts) {
      groups[id] = { finding: visible, target: id };
      continue;
    }
    const originals = new Map(
      visible.provenance.sourceFindings!.map((source) => [source.id, source]),
    );
    for (const { order, sources } of parts) {
      const members = sources.map((id) => originals.get(id)!);
      const finding = structuredClone(members[0]!.finding) as Finding;
      delete finding.provenance.deepScanRepairGroups;
      finding.provenance.sourceFindingIds = sources;
      finding.provenance.sourceFindings = members;
      for (const member of members.slice(1))
        addLocations(finding, member.finding as Finding);
      groups[order] = { finding, target: parts[0]!.order };
    }
  }
  return groups;
}

export async function mergeBatch(
  aggregate: ScanUnion,
  workers: AcceptedDiscovery[],
  scanDir: string,
  compare: CompareReports,
  onError: (error: unknown) => void,
): Promise<number[]> {
  const retained = restoreRepairGroups(aggregate.findings).map((group, id) => ({
    ...group,
    id,
    worker: -1,
  }));
  const priorTargets = retained.map(({ target }) => target);
  const previous = retained.length;
  const originals = [
    ...retained.map(({ finding }) => finding),
    ...workers.flatMap((worker) => worker.result.findings),
  ];
  const content = (finding: object) =>
    JSON.stringify({ ...finding, provenance: undefined });
  const exact = originals.map(content);
  const copies = new Map<string, (typeof retained)[number]>();
  for (const group of retained) {
    copies.set(exact[group.id]!, group);
    for (const source of group.finding.provenance.sourceFindings ?? [])
      copies.set(content(source.finding), group);
  }
  let repairs: Map<number, number[] | undefined> | undefined;
  let records: ComparisonReport[] = [];
  let limitation: string | undefined;
  const unseen = new Set(
    exact.slice(previous).filter((key) => !copies.has(key)),
  );
  if (unseen.size > (previous ? 0 : 1)) {
    try {
      records = originals.map((finding, id) => report(finding, id < previous));
      const rows = records.map((record, id) => ({ id, ...record }));
      repairs = repairKeys(
        await compare(
          instructions + "\n" + JSON.stringify(rows),
          duplicateResponseSchema,
        ),
        records,
      );
      if (repairs.size < records.length)
        limitation = `Deep Scan comparison omitted ${records.length - repairs.size} of ${records.length} reports from its repair assignments.`;
    } catch (error) {
      // Failed comparisons preserve all findings except exact repeats.
      onError(error);
      limitation = `Deep Scan could not compare this batch for duplicates: ${errorMessage(error)}`;
    }
  }
  const changed = new Map<number, number>();
  let id = previous;
  for (const [workerIndex, worker] of workers.entries()) {
    for (const [index, source] of worker.result.findings.entries()) {
      const copy = copies.get(exact[id]!);
      const key = repairs?.get(id);
      let group =
        copy ??
        retained.find((prior) => {
          const other = repairs?.get(prior.id);
          if (
            !key ||
            !other ||
            key.length !== other.length ||
            !key.every((v, i) => v === other[i])
          )
            return false;
          if (
            separateSinks(
              source,
              prior.finding,
              records[id]!,
              records[prior.id]!,
            )
          )
            return false;
          return (
            !distinctIdentity(source, prior.finding, false) &&
            !(prior.finding.provenance.sourceFindings ?? []).some(
              ({ id, finding }) =>
                distinctIdentity(
                  source,
                  finding,
                  id.startsWith(worker.id + ":"),
                ),
            )
          );
        });
      if (!group) {
        const finding = structuredClone(source);
        finding.provenance.sourceFindingIds = [];
        finding.provenance.sourceFindings = [];
        delete finding.provenance.deepScanRepairGroups;
        group = { id, finding, worker: workerIndex, target: id };
        retained.push(group);
      } else {
        addLocations(group.finding, source);
        if (!copy && group.id < previous && !changed.has(group.target))
          changed.set(group.target, workerIndex);
      }
      const sourceId = `${worker.id}:${index}`;
      copies.set(exact[id]!, group);
      const { finding } = group;
      (finding.provenance.sourceFindingIds ??= []).push(sourceId);
      (finding.provenance.sourceFindings ??= []).push({
        id: sourceId,
        finding: structuredClone(source),
      });
      id++;
    }
    addScanCoverage(aggregate, worker, scanDir);
    aggregate.scope ??= worker.result.scope;
    aggregate.threatModel ??= worker.result.threatModel;
  }
  // A later worker can add a separately fixable path to a previously merged group.
  for (const group of retained.slice(0, previous)) {
    const worker = changed.get(group.target);
    if (worker === undefined || group.target === group.id) continue;
    group.target = group.id;
    group.worker = worker;
  }
  if (
    repairs &&
    retained.some((group) => group.worker >= 0) &&
    retained.every(
      ({ finding }) =>
        finding.provenance.sourceFindings?.length &&
        finding.provenance.sourceFindingIds?.length,
    )
  ) {
    let matches: Map<number, Set<number>> | undefined;
    try {
      const sources = new Map<number, Record<string, unknown>[]>();
      for (const group of retained) {
        const members = sources.get(group.target) ?? [];
        members.push(
          ...group.finding.provenance.sourceFindings!.map((s) => s.finding),
        );
        sources.set(group.target, members);
      }
      matches = await checkSameFix(
        retained.filter((group) => group.target === group.id),
        priorTargets,
        records,
        repairs,
        sources,
        compare,
      );
    } catch (error) {
      onError(error);
      limitation = [
        limitation,
        `Deep Scan could not check disputed duplicates: ${errorMessage(error)}`,
      ]
        .filter(Boolean)
        .join(" ");
    }
    if (matches?.size) {
      const kept = new Map<number, typeof retained>();
      for (const group of retained) {
        const earlier = matches.get(group.id);
        if (earlier) {
          for (const [id, members] of kept) {
            if (
              earlier.has(id) &&
              members.every(
                (member) =>
                  (member.worker < 0 || earlier.has(member.id)) &&
                  !sourcesNeedSeparateReports(member.finding, group.finding),
              )
            ) {
              group.target = id;
              break;
            }
          }
        }
        const members = kept.get(group.target) ?? [];
        members.push(group);
        kept.set(group.target, members);
      }
    }
  }
  if (retained.every((group) => group.target === group.id)) {
    aggregate.findings = retained.map(({ finding }) => finding);
  } else {
    const visible = new Map<number, Finding>();
    for (const [order, group] of retained.entries()) {
      let target = visible.get(group.target);
      if (!target) {
        target = structuredClone(group.finding);
        target.provenance.deepScanRepairGroups = [];
        visible.set(group.target, target);
      } else {
        addLocations(target, group.finding);
        target.provenance.sourceFindingIds!.push(
          ...group.finding.provenance.sourceFindingIds!,
        );
        target.provenance.sourceFindings!.push(
          ...group.finding.provenance.sourceFindings!,
        );
      }
      (target.provenance.deepScanRepairGroups as RepairGroup[]).push({
        order,
        sources: group.finding.provenance.sourceFindingIds!,
      });
    }
    aggregate.findings = [...visible.values()];
  }
  if (limitation) {
    aggregate.scope = {
      ...aggregate.scope,
      limitations: [
        ...new Set([...(aggregate.scope?.limitations ?? []), limitation]),
      ],
    };
  }
  const newCounts = workers.map(() => 0);
  for (const { id, target, worker } of retained)
    if (worker >= 0 && id === target) newCounts[worker]!++;
  return newCounts;
}
