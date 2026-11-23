// PEP 440 version identifiers. Specifier support below is limited to the
// comparison operators used by captured stack catalogs.
const versionPattern =
  /^v?(?:(?<epoch>\d+)!)?(?<release>\d+(?:\.\d+)*)(?:[-_.]?(?<pre>a|alpha|b|beta|c|rc|pre|preview)[-_.]?(?<preNumber>\d+)?)?(?:-(?<implicitPost>\d+)|[-_.]?(?<post>post|rev|r)[-_.]?(?<postNumber>\d+)?)?(?:[-_.]?(?<dev>dev)[-_.]?(?<devNumber>\d+)?)?(?:\+(?<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$/iu;

function parse(version: string) {
  const parts = versionPattern.exec(version.trim())?.groups;
  if (!parts) return;
  const {
    epoch,
    release,
    pre: preLabel,
    preNumber,
    implicitPost,
    post,
    postNumber,
    dev,
    devNumber,
    local,
  } = parts;
  const pre = preLabel?.toLowerCase();
  return {
    epoch: BigInt(epoch ?? 0),
    release: release!.split(".").map(BigInt),
    pre: pre
      ? {
          rank: pre.startsWith("a") ? 1 : pre.startsWith("b") ? 2 : 3,
          number: BigInt(preNumber ?? 0),
        }
      : undefined,
    post:
      implicitPost || post
        ? BigInt(implicitPost ?? postNumber ?? 0)
        : undefined,
    dev: dev ? BigInt(devNumber ?? 0) : undefined,
    local: local
      ?.toLowerCase()
      .split(/[-_.]/u)
      .map((part) => (/^\d+$/u.test(part) ? BigInt(part).toString() : part))
      .join("."),
  };
}

type Version = NonNullable<ReturnType<typeof parse>>;

function order(left: bigint, right: bigint) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareRelease(left: Version, right: Version) {
  const epoch = order(left.epoch, right.epoch);
  if (epoch) return epoch;
  for (
    let i = 0;
    i < Math.max(left.release.length, right.release.length);
    i++
  ) {
    const result = order(left.release[i] ?? 0n, right.release[i] ?? 0n);
    if (result) return result;
  }
  return 0;
}

function preRank(version: Version) {
  // A development-only version precedes even alpha. A final or post-release
  // without a pre segment follows every prerelease.
  return (
    version.pre?.rank ??
    (version.dev !== undefined && version.post === undefined ? 0 : 4)
  );
}

function comparePublic(left: Version, right: Version) {
  return (
    compareRelease(left, right) ||
    preRank(left) - preRank(right) ||
    order(left.pre?.number ?? 0n, right.pre?.number ?? 0n) ||
    order(left.post ?? -1n, right.post ?? -1n) ||
    (left.dev === undefined
      ? Number(right.dev !== undefined)
      : right.dev === undefined
        ? -1
        : order(left.dev, right.dev))
  );
}

function equal(candidate: Version, expected: Version) {
  return (
    comparePublic(candidate, expected) === 0 &&
    (expected.local === undefined || candidate.local === expected.local)
  );
}

export function pythonVersionMatches(version: string, listed: string) {
  const candidate = parse(version),
    expected = parse(listed);
  if (candidate && expected) return equal(candidate, expected);
}

export function pythonReleaseMatches(version: string, specifier: string) {
  const candidate = parse(version);
  if (!candidate) return;
  let unknown = false;
  for (const term of specifier.split(",")) {
    const match = /^\s*(<=|>=|==|!=|<|>)\s*([^\s]+)\s*$/u.exec(term);
    const expected = match && parse(match[2]!);
    const operator = match?.[1];
    if (
      !expected ||
      (expected.local !== undefined && operator !== "==" && operator !== "!=")
    ) {
      unknown = true;
      continue;
    }
    const cmp = comparePublic(candidate, expected);
    let result: boolean;
    switch (operator) {
      case "==":
        result = equal(candidate, expected);
        break;
      case "!=":
        result = !equal(candidate, expected);
        break;
      case "<=":
        result = cmp <= 0;
        break;
      case ">=":
        result = cmp >= 0;
        break;
      case "<":
        // A final or post-release boundary excludes its own prereleases,
        // so the effective upper bound is that version's first dev release.
        result =
          expected.pre === undefined && expected.dev === undefined
            ? comparePublic(candidate, { ...expected, dev: 0n }) < 0
            : cmp < 0;
        break;
      case ">":
        // A post-release of the exact boundary is not strictly greater for
        // specifier matching unless the boundary is itself a post-release.
        result =
          cmp > 0 &&
          !(
            candidate.post !== undefined &&
            expected.post === undefined &&
            comparePublic(
              { ...candidate, post: undefined, dev: undefined },
              expected,
            ) === 0
          );
        break;
      default:
        unknown = true;
        continue;
    }
    if (!result) return false;
  }
  return unknown ? undefined : true;
}
