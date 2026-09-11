export type ComparisonFinding = { occurrenceId: string } & Record<
  string,
  unknown
>;

export interface CatalogueEntry {
  card: ComparisonFinding;
  occurrences: readonly ComparisonFinding[];
}

export function groupFindings(
  findings: readonly ComparisonFinding[],
  knownFindingGroups: readonly (readonly string[])[] = [],
  occurrenceGroups: readonly (readonly string[])[] = [],
): ComparisonFinding[][] {
  const parents = new Map<string, string>();
  const root = (value: string): string => {
    const path: string[] = [];
    let current = value;
    while (parents.has(current)) {
      path.push(current);
      current = parents.get(current)!;
    }
    for (const item of path) parents.set(item, current);
    return current;
  };
  const link = (first: string, second: string): void => {
    const previous = root(first);
    const current = root(second);
    if (previous !== current) parents.set(current, previous);
  };
  for (const [prefix, groups] of [
    ["finding", knownFindingGroups],
    ["occurrence", occurrenceGroups],
  ] as const) {
    for (const group of groups) {
      const identities =
        prefix === "finding"
          ? group.filter((identity) => identity.trim().length > 0)
          : group;
      const first = identities[0];
      if (first === undefined) continue;
      for (const value of identities.slice(1)) {
        link(`${prefix}:${first}`, `${prefix}:${value}`);
      }
    }
  }
  for (const finding of findings) {
    const findingId = finding["findingId"];
    if (typeof findingId === "string" && findingId.trim().length > 0) {
      link(`finding:${findingId}`, `occurrence:${finding.occurrenceId}`);
    }
  }

  const groups = new Map<string, ComparisonFinding[]>();
  for (const finding of findings) {
    const key = root(`occurrence:${finding.occurrenceId}`);
    const group = groups.get(key);
    if (group === undefined) groups.set(key, [finding]);
    else group.push(finding);
  }

  return [...groups.values()];
}

export function findingCatalogue(
  findings: readonly ComparisonFinding[],
  knownFindingGroups: readonly (readonly string[])[] = [],
): Map<string, CatalogueEntry> {
  return new Map(
    groupFindings(findings, knownFindingGroups).map((occurrences) => {
      const latest = occurrences.at(-1)!;
      const card = compactFinding(latest);
      if (occurrences.length > 1) {
        const description = (finding: ComparisonFinding) => {
          const value: Record<string, unknown> = { ...compactFinding(finding) };
          delete value["occurrenceId"];
          delete value["findingId"];
          return value;
        };
        const current = description(latest);
        const seen = new Set<string>();
        const aliases = occurrences.slice(0, -1).flatMap((finding) => {
          const value = Object.fromEntries(
            Object.entries(description(finding)).filter(
              ([field, value]) =>
                JSON.stringify(value) !== JSON.stringify(current[field]),
            ),
          );
          if (Object.keys(value).length === 0) return [];
          const key = JSON.stringify(value);
          if (seen.has(key)) return [];
          seen.add(key);
          return [value];
        });
        card["occurrenceCount"] = occurrences.length;
        if (aliases.length > 0) card["earlierDescriptions"] = aliases;
      }
      const findingId = occurrences[0]!["findingId"];
      if (typeof findingId === "string" && findingId.trim().length > 0) {
        card["issueId"] = findingId;
      }
      return [latest.occurrenceId, { card, occurrences }];
    }),
  );
}

export function compactFinding(finding: ComparisonFinding): ComparisonFinding {
  const rootCause = finding["rootCause"] ?? finding["root_cause"];
  const attackPath = record(finding["attackPath"]);
  const dataFlow =
    attackPath?.["dataFlow"] ??
    attackPath?.["data_flow"] ??
    attackPath?.["dataflow"];
  const locations = Array.isArray(finding["locations"])
    ? finding["locations"].flatMap((value) => {
        const location = record(value);
        return location === undefined ? [] : [location];
      })
    : [];
  let controls = locations.filter(
    (location) => location["role"] === "root_control",
  );
  if (controls.length === 0) {
    controls = locations.filter((location) =>
      ["expected_control", "concrete_implementation"].includes(
        String(location["role"]),
      ),
    );
  }
  if (controls.length === 0) controls = locations.slice(0, 1);

  return {
    occurrenceId: finding.occurrenceId,
    ...present({
      findingId: finding["findingId"],
      title: finding["title"],
      identity: pick(finding["identity"], ["anchor", "instance"]),
      ruleId: finding["ruleId"],
      taxonomy: pick(finding["taxonomy"], ["category", "cwe"]),
      rootCause:
        (typeof rootCause === "string"
          ? rootCause
          : record(rootCause)?.["summary"]) ?? finding["summary"],
      remediation: finding["remediation"],
      locations: controls.map((location) =>
        pick(location, ["path", "startLine", "endLine", "role"]),
      ),
      attackPath: present({
        dataFlow: pick(dataFlow, ["source", "sink"]),
        reachability: pick(attackPath?.["reachability"], [
          "attacker",
          "entrypoint",
        ]),
      }),
      affectedComponent: finding["affectedComponent"],
      boundaryCrossed: finding["boundaryCrossed"],
    }),
  };
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function pick(value: unknown, fields: readonly string[]): unknown {
  if (typeof value === "string") return value;
  const object = record(value);
  return object === undefined
    ? undefined
    : present(
        Object.fromEntries(fields.map((field) => [field, object[field]])),
      );
}

function present(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value).filter(
      ([, item]) =>
        item !== undefined &&
        item !== null &&
        item !== "" &&
        (!Array.isArray(item) || item.length > 0) &&
        (record(item) === undefined || Object.keys(item as object).length > 0),
    ),
  );
}
