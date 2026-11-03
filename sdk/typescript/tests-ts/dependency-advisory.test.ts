import { expect, mock, test } from "bun:test";
import { lookupDependencyAdvisory } from "../src/dependency-advisory.js";

const cve = "CVE-2000-1234";
const alias = "GHSA-2345-6789-cfgh";
const api = "https://api.osv.dev/v1/vulns/";
const publicUrl = "https://osv.dev/vulnerability/";

const affected = [
  {
    package: { ecosystem: "npm", name: "fixture-package" },
    ranges: [
      {
        type: "SEMVER",
        events: [
          { introduced: "0" },
          { fixed: "1.2.1" },
          { introduced: "2.0.0" },
          { last_affected: "2.1.0" },
        ],
      },
    ],
    versions: ["1.0.0", "2.0.0"],
  },
  {
    ranges: [
      {
        type: "GIT",
        repo: "https://example.invalid/source",
        events: [{ introduced: "0" }, { limit: "acb1234" }],
      },
    ],
  },
  {
    package: { ecosystem: "Go", name: "example.org/decoder" },
    ecosystem_specific: {
      imports: [
        {
          path: "example.org/decoder/parser",
          symbols: ["Read"],
          goos: ["linux"],
        },
      ],
    },
  },
  {
    package: { ecosystem: "crates.io", name: "fixture-parser" },
    ranges: [
      { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.0" }] },
    ],
    ecosystem_specific: {
      affects: {
        functions: [
          "fixture_parser::Parser::read",
          "fixture_parser::Parser::read_mut",
        ],
        arch: ["x86_64"],
        os: ["linux"],
      },
    },
  },
];

test("normalizes the CVE and preserves OSV package versions and ranges", async () => {
  const fetchRecord = mock(async (url: string, init: RequestInit) => {
    expect(url).toBe(api + cve);
    expect(init.redirect).toBe("error");
    expect(new Headers(init.headers).has("authorization")).toBe(false);
    return Response.json({
      id: cve,
      aliases: [],
      summary: "Example advisory",
      details:
        "## Summary\n\nOnly `Parser.read` uses the affected mode.\n\n## Examples\n\nAdditional details.",
      affected,
    });
  });
  const result = await lookupDependencyAdvisory(
    cve.toLowerCase(),
    undefined,
    fetchRecord,
  );
  expect(fetchRecord).toHaveBeenCalledTimes(1);
  expect(result).toEqual({
    cve,
    advisories: [
      {
        url: publicUrl + cve,
        summary: "Example advisory",
        overview: "Only `Parser.read` uses the affected mode.",
        affected,
      },
    ],
  });
});

test("resolves OSV's 404 alias hints and checks each returned record", async () => {
  const withdrawn = "GO-2000-0001";
  const unrelated = "PYSEC-2000-1";
  const requests: string[] = [];
  const fetchRecord = async (url: string) => {
    requests.push(url);
    switch (url) {
      case api + cve:
        return Response.json(
          {
            code: 5,
            message: `Vulnerability not found, but the following aliases were: ${alias} ${withdrawn} ${unrelated} ${alias}`,
          },
          { status: 404 },
        );
      case api + alias:
        return Response.json({
          id: alias,
          aliases: [cve],
          details: "Only decoder mode is affected.",
        });
      case api + withdrawn:
        return Response.json({
          id: withdrawn,
          aliases: [cve],
          withdrawn: "2021-03-15T00:00:00Z",
        });
      case api + unrelated:
        return Response.json({ id: unrelated, related: [cve] });
      default:
        throw new Error(`Unexpected request: ${url}`);
    }
  };
  const result = await lookupDependencyAdvisory(cve, undefined, fetchRecord);
  expect(result.advisories.map((a) => a.url)).toEqual([publicUrl + alias]);
  expect(result.advisories[0]).toMatchObject({
    overview: "Only decoder mode is affected.",
    affected: [],
  });
  expect(requests.sort()).toEqual(
    [cve, alias, withdrawn, unrelated].map((id) => api + id).sort(),
  );
});

test("keeps a canonical CVE and its direct aliases without traversing related records", async () => {
  const fetchRecord = mock(async (url: string) => {
    if (url === api + cve)
      return Response.json({
        id: cve,
        aliases: [alias],
        related: ["GO-2000-0001"],
      });
    if (url === api + alias)
      return Response.json({ id: alias, aliases: [cve, "PYSEC-2000-1"] });
    throw new Error(`Unexpected request: ${url}`);
  });
  const result = await lookupDependencyAdvisory(cve, undefined, fetchRecord);
  expect(result.advisories.map((a) => a.url).sort()).toEqual(
    [publicUrl + cve, publicUrl + alias].sort(),
  );
  expect(fetchRecord).toHaveBeenCalledTimes(2);
});

test("accepts an OSV record with null aliases and affected entries", async () => {
  const result = await lookupDependencyAdvisory(cve, undefined, async () =>
    Response.json({ id: cve, aliases: null, affected: null }),
  );
  expect(result.advisories).toEqual([{ url: publicUrl + cve, affected: [] }]);
});

test("omits code blocks and oversized paragraphs from advisory overviews", async () => {
  for (const details of [
    "### Impact\n\n" + "Example. ".repeat(100),
    "### Summary\n\n```js\nexample()\n```",
    "### Summary\n\nExample: `call(arg, value)`.",
  ]) {
    const { advisories } = await lookupDependencyAdvisory(
      cve,
      undefined,
      async () => Response.json({ id: cve, details }),
    );
    expect(advisories[0]?.overview).toBeUndefined();
  }
});

test("includes later applicability conditions and omits examples", async () => {
  const conditions = [
    "Both settings must be enabled:",
    "",
    "- `auth.identity_required`",
    "- `dedupe.enabled`",
    "",
    "Both default to `false`. A runtime override takes precedence over `dedupe.enabled = true` in the file.",
  ].join("\n");
  const details = [
    "### Summary",
    "Configuration matters.",
    "### Am I affected?",
    conditions,
    "",
    "```text",
    "Example command",
    "### Nested heading in example",
    "```",
    "",
    "#### Reproduction",
    "Excluded reproduction details",
    "",
    "~~~text",
    "### Prerequisites",
    "Excluded example text",
    "~~~",
  ].join("\r\n");
  const result = await lookupDependencyAdvisory(cve, undefined, async () =>
    Response.json({ id: cve, details }),
  );
  expect(result.advisories[0]?.applicability).toBe(conditions);
});

test("rejects invalid IDs and cancellation before sending a request", async () => {
  const fetchRecord = mock(async () => Response.json({ id: cve }));
  await expect(
    lookupDependencyAdvisory("path/private-repo", undefined, fetchRecord),
  ).rejects.toThrow("CVE");
  await expect(
    lookupDependencyAdvisory(
      cve,
      AbortSignal.abort(new Error("cancelled")),
      fetchRecord,
    ),
  ).rejects.toThrow("cancelled");
  expect(fetchRecord).not.toHaveBeenCalled();
});

test("reports missing records, upstream errors, and failed requests", async () => {
  for (const [status, diagnostic] of [
    [404, /not found|no active/i],
    [503, /503/],
  ] as const) {
    const fetchRecord = mock(async () =>
      Response.json({ code: 5, message: "Record unavailable" }, { status }),
    );
    await expect(
      lookupDependencyAdvisory(cve, undefined, fetchRecord),
    ).rejects.toThrow(diagnostic);
    expect(fetchRecord).toHaveBeenCalledTimes(1);
  }
  await expect(
    lookupDependencyAdvisory(cve, undefined, async () => {
      throw new TypeError("Connection failed");
    }),
  ).rejects.toThrow(/connection failed/i);
});
