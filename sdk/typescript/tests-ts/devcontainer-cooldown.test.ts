import { readFile } from "node:fs/promises";
import { expect, test } from "bun:test";
import { parse } from "yaml";
import {
  checkCooldown,
  cooldownDays,
  configuredFeatures,
  featuresToCheck,
  publicationTime,
} from "../scripts/check-devcontainer-cooldown.mts";

const digest = `sha256:${"a".repeat(64)}`;
const oldDigest = `sha256:${"b".repeat(64)}`;
const name = "ghcr.io/example/features/node:2";
const feature = {
  version: "2.1.1",
  resolved: `ghcr.io/example/features/node@${digest}`,
  integrity: digest,
};
const previous = {
  features: {
    [name]: {
      version: "2.1.0",
      resolved: `ghcr.io/example/features/node@${oldDigest}`,
      integrity: oldDigest,
    },
  },
};
const current = { features: { [name]: feature } };
const published = new Date("2026-01-01T12:00:00.000Z");

test("reads configured features from JSONC while excluding local source directories", () => {
  expect(
    configuredFeatures(`{
    // Feature options and trailing commas are valid devcontainer configuration.
    "features": { "${name}": {}, "./local-feature": {}, },
  }`),
  ).toEqual([name]);
});

test("rejects manifest-only tag changes and missing lock entries instead of using unpinned tags", () => {
  expect(() =>
    featuresToCheck(previous, current, ["ghcr.io/example/features/node:3"], []),
  ).toThrow("matching lockfile entry");
  expect(() => featuresToCheck(previous, { features: {} }, [name], [])).toThrow(
    "matching lockfile entry",
  );
  expect(featuresToCheck(previous, current, [], [])).toEqual([]);
});

test("checks the effective integrity and requires the resolved resource to match the configured feature", () => {
  const changed = {
    features: { [name]: { ...feature, integrity: oldDigest } },
  };
  expect(() => featuresToCheck(current, changed, [name], [])).toThrow(
    "same immutable digest",
  );
  const unrelated = {
    features: {
      [name]: { ...feature, resolved: `ghcr.io/other/unrelated@${digest}` },
    },
  };
  expect(() => featuresToCheck(current, unrelated, [name], [])).toThrow(
    "same immutable digest",
  );
});

test("uses the configured devcontainer cooldown rather than another ecosystem or a hardcoded value", () => {
  expect(
    cooldownDays(`updates:
  - package-ecosystem: npm
    cooldown:
      default-days: 10
  - package-ecosystem: devcontainers
    cooldown:
      default-days: 7
`),
  ).toBe(7);
  expect(
    cooldownDays(`updates:
  - package-ecosystem: devcontainers
    cooldown:
      default-days: 3
`),
  ).toBe(3);
  expect(() => cooldownDays("updates: []")).toThrow("cooldown.default-days");
});

test("checks new and changed digests, including rollback pins, and skips unchanged or deleted entries", () => {
  expect(featuresToCheck(previous, current, [name], [])).toEqual([
    [name, feature],
  ]);
  expect(featuresToCheck({ features: {} }, current, [name], [])).toEqual([
    [name, feature],
  ]);
  expect(featuresToCheck(current, previous, [name], [])).toEqual([
    [name, previous.features[name]],
  ]);
  expect(featuresToCheck(current, current, [name], [])).toEqual([]);
  expect(featuresToCheck(current, { features: {} }, [], [])).toEqual([]);
});

test.each([
  ".github/dependabot.yml",
  ".devcontainer/devcontainer.json",
  ".github/workflows/node-ci.yml",
  "sdk/typescript/scripts/check-devcontainer-cooldown.mts",
])("validates existing pins when %s changes", (path) => {
  expect(featuresToCheck(current, current, [name], [path])).toEqual([
    [name, feature],
  ]);
});

test("allows the exact seven-day boundary and reports when a younger digest becomes eligible", async () => {
  const eligible = new Date("2026-01-08T12:00:00.000Z");
  const read = async () => published;
  await expect(
    checkCooldown([[name, feature]], 7, read, eligible),
  ).resolves.toHaveLength(1);
  await expect(
    checkCooldown([[name, feature]], 7, read, new Date(eligible.getTime() - 1)),
  ).rejects.toThrow("2026-01-08T12:00:00.000Z");
  await expect(
    checkCooldown([[name, feature]], 7, read, new Date("2026-01-10T00:00:00Z")),
  ).resolves.toHaveLength(1);
  await expect(
    checkCooldown([], 7, async () => {
      throw new Error("unexpected lookup");
    }),
  ).resolves.toEqual([]);
});

test("does not fetch publication metadata when the configured cooldown is disabled", async () => {
  await expect(
    checkCooldown([[name, feature]], 0, async () => {
      throw new Error("unexpected lookup");
    }),
  ).resolves.toEqual([]);
});

test("finds the exact immutable digest across GitHub Packages pages", async () => {
  const requests: string[] = [];
  const result = await publicationTime(
    name,
    feature,
    "synthetic-package-token",
    async (url, init) => {
      requests.push(url);
      expect(new Headers(init.headers).get("Authorization")).toBe(
        "Bearer synthetic-package-token",
      );
      if (requests.length === 1) {
        return Response.json(
          [
            {
              name: oldDigest,
              created_at: "2020-01-01T00:00:00Z",
              metadata: { container: { tags: [feature.version] } },
            },
          ],
          {
            headers: {
              link: '<https://api.github.com/packages?page=2>; rel="next"',
            },
          },
        );
      }
      return Response.json([
        { name: digest, created_at: published.toISOString() },
      ]);
    },
  );
  expect(result).toEqual(published);
  expect(requests).toEqual([
    "https://api.github.com/orgs/example/packages/container/features%2Fnode/versions?per_page=100&page=1",
    "https://api.github.com/orgs/example/packages/container/features%2Fnode/versions?per_page=100&page=2",
  ]);
});

test.each([undefined, "", "not a timestamp"])(
  "rejects a matching version with publication time %s",
  async (created_at) => {
    await expect(
      publicationTime(name, feature, "synthetic-package-token", async () =>
        Response.json([{ name: digest, created_at }]),
      ),
    ).rejects.toThrow("no valid created_at");
  },
);

test("does not substitute a tagged version for an unavailable digest or hide API errors", async () => {
  await expect(
    publicationTime(name, feature, "synthetic-package-token", async () =>
      Response.json([{ name: oldDigest, created_at: published.toISOString() }]),
    ),
  ).rejects.toThrow("exact digest");
  await expect(
    publicationTime(
      name,
      feature,
      "synthetic-package-token",
      async () =>
        new Response("read:packages permission is required", { status: 403 }),
    ),
  ).rejects.toThrow("HTTP 403: read:packages permission is required");
});

test("runs the guard with package metadata access inside the existing required checks", async () => {
  const workflow = parse(
    await readFile(
      new URL("../../../.github/workflows/node-ci.yml", import.meta.url),
      "utf8",
    ),
  ) as {
    jobs: Record<
      string,
      {
        permissions?: Record<string, string>;
        needs?: string[];
        steps: Array<{
          name?: string;
          if?: string;
          run?: string;
          env?: Record<string, string>;
          with?: Record<string, unknown>;
        }>;
      }
    >;
  };
  const job = workflow.jobs["static-checks"]!;
  const index = job.steps.findIndex(
    (step) => step.name === "Check devcontainer dependency cooldown",
  );
  expect(index).toBeGreaterThan(
    job.steps.findIndex((step) => step.name === "Install dependencies"),
  );
  expect(job.steps[index]!.run).toContain(
    "sdk/typescript/scripts/check-devcontainer-cooldown.mts",
  );
  expect(job.steps[index]!.env).toEqual({ GH_TOKEN: "${{ github.token }}" });
  expect(job.permissions).toEqual({ contents: "read", packages: "read" });
  expect(job.steps[0]!.with?.["fetch-depth"]).toBe(2);
  for (const name of ["required-test", "windows"]) {
    const required = workflow.jobs[name]!;
    expect(required.needs).toContain("static-checks");
    expect(
      required.steps.some(
        (step) =>
          step.run === "exit 1" &&
          step.if?.includes("needs.static-checks.result != 'success'"),
      ),
    ).toBe(true);
  }
});
