import { expect, mock, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  dependencyAdvisoryDetailsSchema,
  lookupDependencyAdvisory,
  lookupPackageAdvisories,
  parseDependencyAdvisoryDetails,
  parseDependencyPackage,
} from "../src/dependency-advisory.js";
import { readDependencyCheckOutput } from "../src/dependency-reachability.js";
import { createDependencyReportSubmission } from "../src/dependency-report-submission.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

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
        id: cve,
        url: publicUrl + cve,
        summary: "Example advisory",
        overview: "Only `Parser.read` uses the affected mode.",
        affected,
      },
    ],
  });
});

test("preserves typed references and record identity in saved reports while accepting legacy details", () => {
  const references = [
    { type: "ADVISORY", url: "https://example.invalid/security/advisory" },
    { type: "FIX", url: "https://example.invalid/source/commit/abc123" },
    { type: "REPORT", url: "https://example.invalid/issues/123" },
  ];
  const details = parseDependencyAdvisoryDetails({
    id: alias,
    aliases: [cve],
    summary: "An operation requires invalid input.",
    references,
  });
  expect(details).toMatchObject({ id: alias, aliases: [cve], references });
  const report = readDependencyCheckOutput({
    status: "unknown",
    uses: [],
    limitations: ["The primary advisory and fix still need inspection."],
    cve,
    advisories: [details.url],
    advisoryDetails: [details],
    usage: null,
  });
  expect(report).toMatchObject({
    schemaVersion: 2,
    cve,
    advisoryDetails: [details],
  });
  expect(
    dependencyAdvisoryDetailsSchema.parse({
      url: publicUrl + cve,
      affected: [],
    }),
  ).toEqual({ url: publicUrl + cve, affected: [] });
});

test("keeps primary and fix links and conflicting alias descriptions when the GHSA lookup is missing", async () => {
  const secondary = "GO-2000-0001";
  const references = [
    { type: "ADVISORY", url: "https://example.invalid/security/advisory" },
    { type: "FIX", url: "https://example.invalid/source/commit/abc123" },
  ];
  const records = [
    {
      id: cve,
      aliases: [alias, secondary],
      details: "Invalid sizes can affect allocation.",
      references,
    },
    {
      id: secondary,
      aliases: [cve, alias],
      details: "Invalid state transitions can stall the decoder.",
      references,
    },
  ];
  const requests: string[] = [];
  const primaryApi = `https://api.github.com/advisories/${alias}`;
  const lookupErrors = [
    {
      url: primaryApi,
      message: "GitHub returned HTTP 403: API rate limit exceeded",
    },
  ];
  const advisory = await lookupDependencyAdvisory(
    cve,
    undefined,
    async (url) => {
      requests.push(url);
      const record = records.find((record) => url === api + record.id);
      if (record) return Response.json(record);
      if (url === primaryApi)
        return new Response("API rate limit exceeded", { status: 403 });
      expect(url).toBe(api + alias);
      return Response.json({ message: "Not found" }, { status: 404 });
    },
  );
  expect(requests).toEqual([
    api + cve,
    api + alias,
    api + secondary,
    primaryApi,
  ]);
  expect(advisory.cve).toBe(cve);
  expect(advisory.advisories).toEqual(
    records.map(({ id, aliases, details }) => ({
      id,
      aliases,
      url: publicUrl + id,
      overview: details,
      references,
      lookupErrors,
      affected: [],
    })),
  );

  await using repo = await scopedTemporaryDirectory("advisory-review-");
  await writeFile(join(repo.path, "worker.ts"), "decode(input);\n");
  const received = Promise.withResolvers<unknown>();
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1));
      received.resolve(packet.advisory);
      return JSON.stringify({
        items: packet.items.map(
          (item: { id: string; revision: number; excerptIds: string[] }) => ({
            id: item.id,
            revision: item.revision,
            accepted: true,
            citedVersion: null,
            reason: "The differing descriptions remain an explicit gap.",
            evidenceIds: item.excerptIds,
          }),
        ),
      });
    },
  });
  try {
    expect(
      await submission.queue({
        items: [
          {
            id: "description-conflict",
            kind: "unresolved",
            candidateIds: [],
            reason:
              "The aliased descriptions differ; the primary advisory and fix need reconciliation.",
            evidence: [
              { path: "worker.ts", startLine: 1, endLine: 1, supports: [] },
            ],
            observations: [],
          },
        ],
      }),
    ).toMatchObject({ queued: true });
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(await received.promise).toEqual(advisory);
  } finally {
    await submission.close();
  }
});

test.each([true, false])(
  "fetches the published primary body after an OSV alias 404 (repository reference: %s)",
  async (repositoryReference) => {
    const html = repositoryReference
      ? `https://github.com/example/decoder/security/advisories/${alias}`
      : `https://github.com/advisories/${alias}`;
    const primaryApi = repositoryReference
      ? `https://api.github.com/repos/example/decoder/security-advisories/${alias}`
      : `https://api.github.com/advisories/${alias}`;
    const fix = "https://github.com/example/decoder/commit/" + "a".repeat(40);
    const body =
      "Invalid state can stall decoding.\n\n### Required condition\n\nThe state must be invalid.\n\n```c\nreturn validate(state);\n```";
    const vulnerabilities = [
      {
        package: { ecosystem: "go", name: "example.org/decoder" },
        vulnerable_version_range: "< 1.4.0",
        patched_versions: "1.4.0",
        vulnerable_functions: ["decodeHeader"],
      },
    ];
    const calls: string[] = [];
    const result = await lookupDependencyAdvisory(
      cve,
      undefined,
      async (url, init) => {
        calls.push(url);
        expect(init.redirect).toBe("error");
        expect(new Headers(init.headers).has("authorization")).toBe(false);
        if (url === api + cve)
          return Response.json({
            id: cve,
            // Discover the repository advisory from the explicit reference too.
            aliases: repositoryReference ? [] : [alias],
            details: "Allocation is affected.",
            references: [
              { type: "ADVISORY", url: html },
              { type: "FIX", url: fix },
            ],
          });
        if (url === api + alias)
          return Response.json({ message: "Not found" }, { status: 404 });
        expect(url).toBe(primaryApi);
        expect(init.credentials).toBe("omit");
        expect(new Headers(init.headers).get("accept")).toBe(
          "application/vnd.github+json",
        );
        return Response.json({
          ghsa_id: alias,
          cve_id: cve,
          identifiers: [
            { type: "GHSA", value: alias },
            { type: "CVE", value: cve },
          ],
          html_url: html,
          summary: "Invalid decoder state",
          description: body,
          ...(repositoryReference
            ? { state: "published" }
            : { type: "reviewed" }),
          withdrawn_at: null,
          references: [fix],
          vulnerabilities,
        });
      },
    );
    expect(calls).toEqual([api + cve, api + alias, primaryApi]);
    expect(result.advisories).toHaveLength(2);
    expect(result.advisories[0]).toMatchObject({
      id: cve,
      overview: "Allocation is affected.",
      references: [
        { type: "ADVISORY", url: html },
        { type: "FIX", url: fix },
      ],
    });
    expect(result.advisories[1]).toMatchObject({
      id: alias,
      aliases: [cve],
      url: html,
      source: {
        type: repositoryReference
          ? "github_repository_advisory"
          : "github_global_advisory",
        url: primaryApi,
      },
      body,
      overview: "Invalid state can stall decoding.",
      vulnerabilities,
      references: [
        { type: "ADVISORY", url: html },
        { type: "WEB", url: fix },
      ],
    });
    expect(dependencyAdvisoryDetailsSchema.parse(result.advisories[1])).toEqual(
      result.advisories[1]!,
    );
  },
);

test.each(["wrong-cve", "withdrawn", "draft", "network"])(
  "retains indexed evidence when primary retrieval is unusable: %s",
  async (failure) => {
    const html = `https://github.com/example/decoder/security/advisories/${alias}`;
    const primaryApi = `https://api.github.com/repos/example/decoder/security-advisories/${alias}`;
    const result = await lookupDependencyAdvisory(
      cve,
      undefined,
      async (url) => {
        if (url === api + cve)
          return Response.json({
            id: cve,
            aliases: [alias],
            details: "The indexed interpretation needs reconciliation.",
            references: [{ type: "ADVISORY", url: html }],
          });
        if (url === api + alias) return Response.json({}, { status: 404 });
        expect(url).toBe(primaryApi);
        if (failure === "network")
          throw new Error("Public API transport failed");
        return Response.json({
          ghsa_id: alias,
          cve_id: failure === "wrong-cve" ? "CVE-2000-9999" : cve,
          identifiers: [],
          html_url: html,
          summary: "Primary advisory",
          description: "A different interpretation.",
          state: failure === "draft" ? "draft" : "published",
          withdrawn_at: failure === "withdrawn" ? "2000-01-01T00:00:00Z" : null,
        });
      },
    );
    expect(result.advisories).toHaveLength(1);
    expect(result.advisories[0]).toMatchObject({
      overview: "The indexed interpretation needs reconciliation.",
      lookupErrors: [{ url: primaryApi, message: expect.any(String) }],
    });
    expect(result.advisories[0]).not.toHaveProperty("body");
  },
);

test("does not convert cancellation during primary retrieval into an optional lookup error", async () => {
  const controller = new AbortController();
  await expect(
    lookupDependencyAdvisory(cve, controller.signal, async (url) => {
      if (url === api + cve)
        return Response.json({ id: cve, aliases: [alias] });
      if (url === api + alias) return Response.json({}, { status: 404 });
      expect(url).toBe(`https://api.github.com/advisories/${alias}`);
      controller.abort(new Error("Cancelled advisory lookup"));
      throw controller.signal.reason;
    }),
  ).rejects.toThrow("Cancelled advisory lookup");
});

test("uses a maintainer reference found in a later alias without probing the global API first", async () => {
  const secondary = "GO-2000-0001";
  const html = `https://github.com/example/decoder/security/advisories/${alias}`;
  const primaryApi = `https://api.github.com/repos/example/decoder/security-advisories/${alias}`;
  const calls: string[] = [];
  const result = await lookupDependencyAdvisory(cve, undefined, async (url) => {
    calls.push(url);
    if (url === api + cve)
      return Response.json({ id: cve, aliases: [alias, secondary] });
    if (url === api + alias) return Response.json({}, { status: 404 });
    if (url === api + secondary)
      return Response.json({
        id: secondary,
        aliases: [cve, alias],
        references: [{ type: "ADVISORY", url: html }],
      });
    expect(url).toBe(primaryApi);
    return Response.json({
      ghsa_id: alias,
      cve_id: cve,
      identifiers: [],
      html_url: html,
      summary: "Primary advisory",
      description: "The published interpretation.",
      state: "published",
    });
  });
  expect(calls).toEqual([api + cve, api + alias, api + secondary, primaryApi]);
  expect(result.advisories.at(-1)).toMatchObject({
    source: { type: "github_repository_advisory", url: primaryApi },
    body: "The published interpretation.",
  });
});

test("groups conflicting aliased records together without equating unrelated issues sharing a fix", async () => {
  const secondary = "GO-2000-0001";
  const different = "CVE-2000-5678";
  const references = [
    { type: "FIX", url: "https://example.invalid/source/commit/abc123" },
  ];
  const result = await lookupPackageAdvisories(
    parseDependencyPackage("Go:example.org/decoder"),
    undefined,
    async () =>
      Response.json({
        vulns: [
          { id: cve, aliases: [alias], details: "Allocation.", references },
          {
            id: secondary,
            aliases: [alias],
            details: "State validation.",
            references,
          },
          { id: different, details: "A separate defect.", references },
        ],
      }),
  );
  expect(result.map(({ id }) => id)).toEqual([cve, different]);
  expect(result[0]?.advisories.map(({ id }) => id)).toEqual([cve, secondary]);
  expect(result[0]?.advisories.map(({ overview }) => overview)).toEqual([
    "Allocation.",
    "State validation.",
  ]);
  expect(result.flatMap(({ advisories }) => advisories)).toHaveLength(3);
  for (const issue of result)
    for (const advisory of issue.advisories)
      expect(advisory.references).toEqual(references);
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
  expect(result.advisories).toEqual([
    { id: cve, url: publicUrl + cve, affected: [] },
  ]);
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

test("projects named functions from explicit labels outside code examples", () => {
  const record = parseDependencyAdvisoryDetails({
    id: alias,
    summary: "Example advisory",
    details: [
      "An ordinary description mentions `Prose.only`.",
      "",
      "- Vulnerable function: `LinkifyIt.prototype.match` — `index.mjs:528-554`",
      "- **Affected functions:** `Parser.read`, `Parser.write`, and `Parser.close()`",
      "- Affected method: `Parser.read`",
      "- Affected function: see `Unlabeled.reference`",
      "- Vulnerable function: `another.js:99`",
      "    Vulnerable function: `Indented.example`",
      "",
      "```md",
      "Vulnerable function: `Fenced.example`",
      "```",
      "~~~md",
      "Affected function: `Tilde.example`",
      "~~~",
    ].join("\n"),
    affected,
  });
  expect(record).toMatchObject({
    url: publicUrl + alias,
    summary: "Example advisory",
    overview: "An ordinary description mentions `Prose.only`.",
    affected,
    vulnerableFunctions: [
      "LinkifyIt.prototype.match",
      "Parser.read",
      "Parser.write",
      "Parser.close()",
    ],
  });
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

test("parses ecosystem-qualified public package names without changing OSV casing", () => {
  for (const [subject, ecosystem, name] of [
    ["npm:@scope/example", "npm", "@scope/example"],
    ["Maven:org.example:sample", "Maven", "org.example:sample"],
    ["Echo:Maven:org.example:sample", "Echo:Maven", "org.example:sample"],
    ["Go:example.invalid/module", "Go", "example.invalid/module"],
    ["PyPI:Sample_Package", "PyPI", "Sample_Package"],
    ["GitHub Actions:example/action", "GitHub Actions", "example/action"],
    ["Debian:12:sample", "Debian:12", "sample"],
    ["openSUSE:Leap 15.6:sample", "openSUSE:Leap 15.6", "sample"],
    ["Alpine:v3.20:sample", "Alpine:v3.20", "sample"],
    [
      "SwiftURL:https://example.invalid/Module",
      "SwiftURL",
      "https://example.invalid/Module",
    ],
  ] as const)
    expect(parseDependencyPackage(subject)).toEqual({ ecosystem, name });
  for (const invalid of [
    "unqualified",
    ":sample",
    "npm:",
    "npm:bad name",
    "Maven:missing-artifact",
    "Debian::sample",
    "npm:@scope",
    "npm:sample@1.0",
    "https://example.invalid/repo",
    "https://example.invalid:8443/repo",
  ])
    expect(() => parseDependencyPackage(invalid)).toThrow(/package/iu);
});

test("queries all OSV pages for the named package and groups only active aliases", async () => {
  const pkg = parseDependencyPackage("npm:@sample/example");
  const signal = new AbortController().signal;
  const data = { package: pkg };
  const queries: unknown[] = [];
  const pages = [
    { next_page_token: "first" },
    {
      vulns: [
        {
          id: alias,
          aliases: [cve],
          details: "Affected under the documented conditions.",
          affected,
        },
        { id: "MAL-2000-2", related: [cve] },
        {
          id: "WITHDRAWN-1",
          aliases: [cve, "MAL-2000-2"],
          withdrawn: "2000-01-01T00:00:00Z",
        },
        { id: "SECONDARY-2", aliases: ["OTHER-2"] },
      ],
      next_page_token: "second",
    },
    {
      vulns: [
        {
          id: alias,
          aliases: [cve],
          details: "Affected under the documented conditions.",
          affected,
        },
        { id: "BRIDGE-3", aliases: [alias, "OTHER-2"] },
      ],
    },
  ];
  const actual = await lookupPackageAdvisories(
    pkg,
    signal,
    async (url, options) => {
      expect(url).toBe("https://api.osv.dev/v1/query");
      expect(options.method).toBe("POST");
      expect(options.redirect).toBe("error");
      expect(options.signal).toBe(signal);
      expect(new Headers(options.headers).get("content-type")).toBe(
        "application/json",
      );
      expect(new Headers(options.headers).has("authorization")).toBe(false);
      queries.push(JSON.parse(options.body as string));
      return Response.json(pages[queries.length - 1]);
    },
  );
  expect(queries).toEqual([
    data,
    { ...data, page_token: "first" },
    { ...data, page_token: "second" },
  ]);
  expect(actual.map((x) => x.id).sort()).toEqual([cve, "MAL-2000-2"]);
  expect(actual.find((x) => x.id === cve)?.advisories).toEqual([
    {
      id: "BRIDGE-3",
      aliases: [alias, "OTHER-2"],
      url: publicUrl + "BRIDGE-3",
      affected: [],
    },
    {
      id: alias,
      aliases: [cve],
      url: publicUrl + alias,
      overview: "Affected under the documented conditions.",
      affected,
    },
    {
      id: "SECONDARY-2",
      aliases: ["OTHER-2"],
      url: publicUrl + "SECONDARY-2",
      affected: [],
    },
  ]);
});

test("an empty package result is distinct from an OSV error, repeated cursor or cancellation", async () => {
  const pkg = parseDependencyPackage("PyPI:example-package");
  expect(
    await lookupPackageAdvisories(pkg, undefined, async () =>
      Response.json({}),
    ),
  ).toEqual([]);
  await expect(
    lookupPackageAdvisories(
      pkg,
      undefined,
      async () => new Response(null, { status: 503 }),
    ),
  ).rejects.toThrow("503");
  const repeated = mock(async () => Response.json({ next_page_token: "same" }));
  await expect(
    lookupPackageAdvisories(pkg, undefined, repeated),
  ).rejects.toThrow(/page token/iu);
  expect(repeated).toHaveBeenCalledTimes(2);
  const cancelled = mock(async () => Response.json({}));
  await expect(
    lookupPackageAdvisories(
      pkg,
      AbortSignal.abort(new Error("cancelled")),
      cancelled,
    ),
  ).rejects.toThrow("cancelled");
  expect(cancelled).not.toHaveBeenCalled();
});
