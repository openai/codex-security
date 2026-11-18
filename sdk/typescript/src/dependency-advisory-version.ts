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

/** PEP 440 pads stable numeric releases with zeros for comparison. */
export function comparePythonReleases(
  left: string,
  right: string,
): number | undefined {
  const numeric = /^\d+(?:\.\d+)*$/u;
  if (!numeric.test(left) || !numeric.test(right)) return;
  const a = left.split(".").map(BigInt);
  const b = right.split(".").map(BigInt);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const first = a[i] ?? 0n;
    const second = b[i] ?? 0n;
    if (first !== second) return first < second ? -1 : 1;
  }
  return 0;
}

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
  const matches = relevant.flatMap((entry) => {
    const versions = (entry.versions ?? []).map((listed) => {
      if (listed === version) return true;
      if (pkg.ecosystem !== "PyPI") return false;
      const order = comparePythonReleases(version, listed);
      return order === undefined ? undefined : order === 0;
    });
    const ranges = (entry.ranges ?? []).map((range) =>
      inRange(version, range, pkg.ecosystem),
    );
    return versions.length || ranges.length
      ? [...versions, ...ranges]
      : [undefined];
  });
  return matches.includes(true)
    ? true
    : matches.includes(undefined)
      ? undefined
      : false;
}
