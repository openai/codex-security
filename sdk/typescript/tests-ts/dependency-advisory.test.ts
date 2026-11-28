import { expect, test } from "bun:test";
import {
  affectedByFrozenVersion,
  affectedSinkVersion,
  effectiveSinks,
  lookupDependencyAdvisory,
  lookupPackageAdvisories,
  parseDependencyPackage,
} from "../src/exploitability/advisory.js";

const cve = "CVE-2099-0001";
const id = "SAMPLE-1";
const record = {
  id,
  aliases: [cve],
  summary: "Sample advisory",
  modified: "2020-03-12T00:00:00Z",
  details:
    "First case.\n\nA separate condition must also hold.\n\nAffected functions: `Codec.decode`.",
  affected: [
    {
      package: { ecosystem: "npm", name: "sample-codec" },
      ranges: [
        {
          type: "SEMVER",
          events: [
            { introduced: "0" },
            { fixed: "1.2.0" },
            { introduced: "2.0.0" },
            { last_affected: "2.0.1" },
          ],
        },
      ],
    },
  ],
};

test("CVE aliases freeze the original advisory text and disjoint version events", async () => {
  const fetcher = async (url: string) =>
    url.endsWith(cve)
      ? Response.json(
          {
            code: 5,
            message: `Vulnerability not found, but the following aliases were: ${id} unrelated`,
          },
          { status: 404 },
        )
      : Response.json(
          url.endsWith(id)
            ? record
            : { ...record, id: "unrelated", aliases: [] },
        );
  const { advisories } = await lookupDependencyAdvisory(
    cve,
    undefined,
    fetcher,
  );
  expect(advisories).toHaveLength(1);
  expect(advisories[0]).toMatchObject({
    id,
    body: record.details,
    modified: record.modified,
    affected: record.affected,
  });
  expect(advisories[0]).not.toHaveProperty("vulnerableFunctions");
  expect(
    effectiveSinks({
      format: "codex-security.sinks/v2",
      cve,
      advisoryDetails: advisories,
    }),
  ).toEqual([]);
  expect(advisories[0]!.sha256).toMatch(/^[a-f0-9]{64}$/);
  await expect(
    lookupDependencyAdvisory(cve, undefined, async () =>
      Response.json({ code: 5, message: "Not found" }, { status: 404 }),
    ),
  ).rejects.toThrow("No active public OSV advisory");
});

test("an advisory binds each affected operation and version range to its own package", async () => {
  const entry = (name: string, version: string) => ({
    package: { ecosystem: "crates.io", name },
    versions: [version],
    ecosystem_specific: { affects: { functions: ["decode"] } },
  });
  const { advisories } = await lookupDependencyAdvisory(
    cve,
    undefined,
    async () =>
      Response.json({
        id: cve,
        details: "Vulnerable function: `other`",
        affected: [entry("one", "1.0.0"), entry("two", "2.0.0")],
      }),
  );
  const catalog = {
    format: "codex-security.sinks/v2" as const,
    cve,
    advisoryDetails: advisories,
  };
  const sinks = effectiveSinks(catalog);
  expect(
    sinks.map((s) => [
      s.package,
      s.function,
      affectedSinkVersion(s, "1.0.0", catalog),
    ]),
  ).toEqual([
    ["one", "decode", true],
    ["two", "decode", false],
  ]);
  expect(new Set(sinks.map((s) => s.id)).size).toBe(2);
});

test("package lookup keeps distinct advisories and unifies aliases across pages", async () => {
  const pkg = parseDependencyPackage("npm:sample-codec");
  const pages: (string | undefined)[] = [];
  const result = await lookupPackageAdvisories(
    pkg,
    undefined,
    async (_url, init) => {
      const request = JSON.parse(String(init.body));
      expect(request.package).toEqual(pkg);
      pages.push(request.page_token);
      return request.page_token
        ? Response.json({
            vulns: [
              { ...record, id: cve, aliases: [id] },
              { ...record, id: "SAMPLE-2", aliases: [] },
              { ...record, id: "withdrawn", withdrawn: "2020-04-01" },
            ],
          })
        : Response.json({ vulns: [record], next_page_token: "more" });
    },
  );
  expect(pages).toEqual([undefined, "more"]);
  expect(
    result.map(({ id, advisories }) => [id, advisories.map((a) => a.id)]),
  ).toEqual([
    [cve, [cve, id]],
    ["SAMPLE-2", ["SAMPLE-2"]],
  ]);
  expect(() => parseDependencyPackage("npm:sample-codec@1.0.0")).toThrow(
    "unversioned",
  );
});

test("a frozen PyPI version list only excludes releases it can compare", () => {
  const pkg = { ecosystem: "PyPI", name: "example" };
  function affected(version: string, versions: string[]) {
    return affectedByFrozenVersion(pkg, version, [
      {
        id: "test-advisory",
        url: "https://example.invalid/advisory",
        sha256: "a".repeat(64),
        affected: [{ package: pkg, versions }],
      },
    ]);
  }
  expect(affected("1.0.0", ["1.0"])).toBe(true);
  expect(affected("1.0.1", ["1.0"])).toBe(false);
  expect(affected("1.0a1", ["1.0-alpha1"])).toBe(true);
  expect(affected("2.1.0+cpu", ["2.1.0"])).toBe(true);
  expect(affected("2.1.0+cpu", ["2.1.0+cu121"])).toBe(false);
  expect(affected("2.1.0+CUDA_012", ["2.1.0+cuda.12"])).toBe(true);
  expect(affected("1.0+", ["1.0"])).toBeUndefined();
});

test("Python sink ranges respect release boundaries and local build labels", () => {
  function affected(version: string, range: string) {
    const sink = {
      id: "decode",
      function: "decode",
      package: "sample-codec",
      versionScheme: "pep440",
      affectedVersions: [range],
      preconditions: [],
    };
    return affectedSinkVersion(sink, version, {
      format: "codex-security.sinks/v2",
      cve,
      sinks: [sink],
    });
  }
  expect(affected("2.1+cpu", "==2.1")).toBe(true);
  expect(affected("2.1+cpu", ">=2.1+cpu")).toBeUndefined();
  expect(affected("1.0rc2", ">1.0rc1,<1.1")).toBe(true);
  expect(affected("1.0rc2", "<1.0")).toBe(false);
  expect(affected("1.0.post1", ">1.0")).toBe(false);
  expect(affected("1.0.post1.dev1", "<1.0.post1")).toBe(false);
  expect(affected("1.0.dev1", ">=1.0.dev0,<=1.0")).toBe(true);
});
