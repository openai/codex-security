import { expect, test } from "bun:test";
import {
  lookupDependencyAdvisory,
  lookupPackageAdvisories,
  parseDependencyPackage,
} from "../src/dependency-advisory.js";

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
    vulnerableFunctions: ["Codec.decode"],
    affected: record.affected,
  });
  expect(advisories[0]!.sha256).toMatch(/^[a-f0-9]{64}$/);
  await expect(
    lookupDependencyAdvisory(cve, undefined, async () =>
      Response.json({ code: 5, message: "Not found" }, { status: 404 }),
    ),
  ).rejects.toThrow("No active public OSV advisory");
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
