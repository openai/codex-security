import semver from "semver";
import type {
  DependencyPackage,
  lookupDependencyAdvisory,
} from "./dependency-advisory.js";

type Advisory = Awaited<
  ReturnType<typeof lookupDependencyAdvisory>
>["advisories"][number];
type Affected = Advisory["affected"][number];
type Range = NonNullable<Affected["ranges"]>[number];

// OSV's ordered events delimit disjoint intervals. Only rule out an entire
// version when every relevant range is understood and excludes it.
function inRange(
  version: string,
  range: Range,
  ecosystem: string,
): boolean | undefined {
  if (
    !semver.valid(version) ||
    !range.events.length ||
    !(
      range.type === "SEMVER" ||
      (range.type === "ECOSYSTEM" && ecosystem === "npm")
    )
  )
    return;
  let start: string | null | undefined;
  let previous: string | undefined;
  const intervals: {
    start: string | null;
    end?: string;
    inclusive?: boolean;
  }[] = [];
  for (const event of range.events) {
    const [name, boundary] = Object.entries(event)[0]!;
    if (name === "introduced" && boundary === "0") {
      if (start !== undefined || previous !== undefined) return;
      start = null;
      continue;
    }
    if (
      !semver.valid(boundary) ||
      (previous !== undefined && semver.lt(boundary, previous))
    )
      return;
    previous = boundary;
    if (name === "introduced") {
      if (start !== undefined) return;
      start = boundary;
    } else {
      if (
        start === undefined ||
        !["fixed", "limit", "last_affected"].includes(name)
      )
        return;
      intervals.push({
        start,
        end: boundary,
        inclusive: name === "last_affected",
      });
      start = undefined;
    }
  }
  if (start !== undefined) intervals.push({ start });
  return intervals.some(
    (i) =>
      (i.start === null || semver.gte(version, i.start)) &&
      (!i.end ||
        (i.inclusive ? semver.lte(version, i.end) : semver.lt(version, i.end))),
  );
}

export function affectedByFrozenVersion(
  pkg: DependencyPackage,
  version: string,
  advisories: Advisory[],
): boolean | undefined {
  function normalize(name: string) {
    return pkg.ecosystem === "PyPI"
      ? name.replace(/[-_.]+/gu, "-").toLowerCase()
      : name;
  }
  const relevant = advisories.flatMap((a) =>
    a.affected.filter(
      (entry) =>
        entry.package?.ecosystem === pkg.ecosystem &&
        normalize(entry.package.name) === normalize(pkg.name),
    ),
  );
  if (!relevant.length) return;
  const matches = relevant.map((entry) => {
    if (entry.versions?.includes(version)) return true;
    if (entry.ranges?.length) {
      const ranges = entry.ranges.map((range) =>
        inRange(version, range, pkg.ecosystem),
      );
      return ranges.includes(true)
        ? true
        : ranges.includes(undefined)
          ? undefined
          : false;
    }
    if (entry.versions?.length) return false;
    return undefined;
  });
  return matches.includes(true)
    ? true
    : matches.includes(undefined)
      ? undefined
      : false;
}
