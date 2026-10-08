import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import JSON5 from "json5";
import { parse } from "yaml";
import { isMain } from "./is-main.mjs";

const lockPath = ".devcontainer/devcontainer-lock.json";
const manifestPath = ".devcontainer/devcontainer.json";
const policyPath = ".github/dependabot.yml";
const guardPaths = new Set([
  policyPath,
  manifestPath,
  ".github/workflows/node-ci.yml",
  "sdk/typescript/scripts/check-devcontainer-cooldown.mts",
]);

type Feature = { version: string; resolved: string; integrity: string };
type Lockfile = { features: Record<string, Feature> };
type PackageVersion = { name: string; created_at?: string };
type Request = (url: string, init: RequestInit) => Promise<Response>;

export function configuredFeatures(source: string): string[] {
  const manifest = JSON5.parse(source) as {
    features?: Record<string, unknown>;
  };
  return Object.keys(manifest.features ?? {}).filter(
    (name) =>
      !name.startsWith("./") &&
      !name.startsWith("../") &&
      !name.startsWith("/"),
  );
}

function featurePackage(name: string, feature: Feature) {
  const match =
    /^(ghcr\.io\/([^/]+)\/([^:@]+))(?::[^/@]+|@(sha256:[a-f0-9]{64}))?$/.exec(
      name,
    );
  if (!match)
    throw new Error(
      `Cannot verify publication time for ${name}: expected a GitHub Container Registry feature.`,
    );
  const [, resource, owner, packageName, sourceDigest] = match;
  if (
    !/^sha256:[a-f0-9]{64}$/.test(feature.integrity) ||
    feature.resolved !== `${resource}@${feature.integrity}` ||
    (sourceDigest !== undefined && sourceDigest !== feature.integrity)
  ) {
    throw new Error(
      `${name}: lockfile resolved and integrity must identify the configured feature's same immutable digest.`,
    );
  }
  return { owner: owner!, name: packageName!, digest: feature.integrity };
}

export function cooldownDays(source: string): number {
  const policy = parse(source) as {
    updates: Array<{
      "package-ecosystem": string;
      cooldown?: { "default-days"?: number };
    }>;
  };
  const days = policy.updates.find(
    (update) => update["package-ecosystem"] === "devcontainers",
  )?.cooldown?.["default-days"];
  if (days === undefined || !Number.isInteger(days) || days < 0) {
    throw new Error(
      "The devcontainers policy must specify cooldown.default-days.",
    );
  }
  return days;
}

export function featuresToCheck(
  previous: Lockfile,
  current: Lockfile,
  configured: readonly string[],
  changedPaths: readonly string[],
): Array<[string, Feature]> {
  const all = changedPaths.some((path) => guardPaths.has(path));
  const selected: Array<[string, Feature]> = [];
  for (const name of configured) {
    const feature = current.features[name];
    if (!feature)
      throw new Error(
        `${name}: the configured feature needs a matching lockfile entry before its cooldown can be verified.`,
      );
    featurePackage(name, feature);
    if (all || previous.features[name]?.integrity !== feature.integrity)
      selected.push([name, feature]);
  }
  return selected;
}

export async function publicationTime(
  name: string,
  feature: Feature,
  token: string,
  request: Request = fetch,
): Promise<Date> {
  const { owner, name: packageName, digest } = featurePackage(name, feature);
  const endpoint = `https://api.github.com/orgs/${encodeURIComponent(owner)}/packages/container/${encodeURIComponent(packageName)}/versions`;
  for (let page = 1; ; page++) {
    const response = await request(`${endpoint}?per_page=100&page=${page}`, {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    if (!response.ok) {
      throw new Error(
        `Cannot verify publication time for ${feature.resolved}: GitHub Packages returned HTTP ${response.status}: ${await response.text()}`,
      );
    }
    const versions = (await response.json()) as PackageVersion[];
    const version = versions.find((candidate) => candidate.name === digest);
    if (version) {
      const created = Date.parse(version.created_at ?? "");
      if (!Number.isFinite(created)) {
        throw new Error(
          `Cannot verify publication time for ${feature.resolved}: the matching package version has no valid created_at timestamp.`,
        );
      }
      return new Date(created);
    }
    if (!response.headers.get("link")?.includes('rel="next"')) break;
  }
  throw new Error(
    `Cannot verify publication time for ${feature.resolved}: GitHub Packages did not return the exact digest.`,
  );
}

export async function checkCooldown(
  features: ReadonlyArray<readonly [string, Feature]>,
  days: number,
  publishedAt: (name: string, feature: Feature) => Promise<Date>,
  now = new Date(),
): Promise<string[]> {
  const messages: string[] = [];
  if (days === 0) return messages;
  for (const [name, feature] of features) {
    const published = await publishedAt(name, feature);
    const eligible = new Date(published.getTime() + days * 86_400_000);
    if (now < eligible) {
      throw new Error(
        `${name} (${feature.version}) was published at ${published.toISOString()}; its ${days}-day cooldown ends at ${eligible.toISOString()}. Rerun CI after that time.`,
      );
    }
    messages.push(
      `${name} (${feature.version}): published ${published.toISOString()}, eligible since ${eligible.toISOString()}.`,
    );
  }
  return messages;
}

if (isMain(import.meta.url)) {
  const root = fileURLToPath(new URL("../../../", import.meta.url));
  const git = (...args: string[]) =>
    execFileSync("git", ["-c", "core.fsmonitor=false", ...args], {
      cwd: root,
      encoding: "utf8",
    });
  try {
    const paths = git("diff", "--name-only", "HEAD^1", "HEAD")
      .trim()
      .split("\n");
    const previous: Lockfile = git(
      "ls-tree",
      "--name-only",
      "HEAD^1",
      "--",
      lockPath,
    ).trim()
      ? JSON.parse(git("show", `HEAD^1:${lockPath}`))
      : { features: {} };
    const current: Lockfile = await readFile(join(root, lockPath), "utf8")
      .then((source) => JSON.parse(source))
      .catch((error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return { features: {} };
        throw error;
      });
    const days = cooldownDays(await readFile(join(root, policyPath), "utf8"));
    const source = await readFile(join(root, manifestPath), "utf8").catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return "{}";
        throw error;
      },
    );
    const features =
      days === 0
        ? []
        : featuresToCheck(previous, current, configuredFeatures(source), paths);
    if (features.length === 0 || days === 0) {
      console.log("No devcontainer feature digests need a cooldown check.");
    } else {
      const token = process.env["GH_TOKEN"];
      if (!token)
        throw new Error(
          "GH_TOKEN with packages:read is required for the devcontainer cooldown check.",
        );
      for (const message of await checkCooldown(
        features,
        days,
        (name, feature) => publicationTime(name, feature, token),
      )) {
        console.log(message);
      }
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
