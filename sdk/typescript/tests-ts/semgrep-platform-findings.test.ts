import { expect, test } from "bun:test";
import { normalizeSemgrepFindings } from "../src/semgrep-findings.js";
import {
  collectSemgrepPlatformFindings,
  normalizeSemgrepPlatformFindings,
} from "../src/semgrep-platform-findings.js";
import {
  collectProject,
  platformFinding,
  platformProject,
  platformRef,
  platformReport,
} from "./support/semgrep-platform-fixtures.js";

const environment = {
  CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
  SEMGREP_APP_TOKEN: "synthetic-web-token",
};
const options = {
  deployment: "example",
  project: platformProject.name,
  ref: platformRef,
};
const first = Array.from({ length: 3000 }, (_, index) => ({ id: index + 1 }));

function collectPages(...pages: unknown[]) {
  const responses = [{ project: platformProject }, ...pages];
  return collectSemgrepPlatformFindings(options, {
    environment,
    fetch: async () => {
      const page = responses.shift();
      return page instanceof Response ? page : Response.json(page);
    },
  });
}

test("retries the throttled page for the selected Semgrep project, ref and product", async () => {
  const pages: string[] = [];
  const name = "https://example.test/monorepo/.";
  const selection = {
    ...options,
    project: name,
    sourceRepositoryUrl: platformProject.url,
  };
  const report = await collectSemgrepPlatformFindings(selection, {
    environment,
    fetch: async (url, init) => {
      expect(url.origin).toBe("https://semgrep.dev");
      expect(new Headers(init.headers).get("authorization")).toBe(
        "Bearer synthetic-web-token",
      );
      expect(init.redirect).toBe("error");
      expect(init.method).toBe("GET");
      if (url.pathname.includes("/projects/")) {
        expect(url.pathname).toBe(
          `/api/v1/deployments/example/projects/${encodeURIComponent(name)}`,
        );
        selection.sourceRepositoryUrl = "https://github.com/other/project";
        return Response.json({ project: { ...platformProject, name } });
      }
      const query = Object.fromEntries(url.searchParams);
      expect(query).toMatchObject({
        ref: platformRef,
        repository_ids: "77",
        dedup: "false",
        issue_type: "sast",
        page_size: "3000",
      });
      pages.push(query["page"]!);
      if (pages.length === 2)
        return new Response("try again", {
          status: 429,
          headers: { "Retry-After": "0" },
        });
      return Response.json({
        findings: query["page"] === "0" ? first : [{ id: first.length + 1 }],
      });
    },
  });
  expect(pages).toEqual(["0", "1", "1", "0"]);
  expect(report.findings).toEqual([...first, { id: first.length + 1 }]);
  expect(JSON.stringify(report)).not.toContain("synthetic-web-token");
});

test("collects and replays 101 findings in a single API page", async () => {
  const rows = Array.from({ length: 101 }, (_, index) =>
    platformFinding(index + 1),
  );
  const report = await collectPages({ findings: rows });
  expect(report.findings).toEqual(rows);
  const parsed = normalizeSemgrepPlatformFindings(report);
  expect(parsed.findings[0]?.evidence).toMatchObject({
    branch: platformRef,
    severity: "medium",
    locations: [{ path: "src/app.ts", line: 3 }],
    details: {
      kind: "sast",
      source_status: "open",
      weakness_ids: ["CWE-79"],
      code: { end_line: 5 },
    },
  });
  const original = platformFinding(1);
  const moved = normalizeSemgrepPlatformFindings(
    platformReport([{ ...original, location: null, status: "ignored" }]),
  );
  expect(moved.findings[0]?.source_finding_id).toBe(
    parsed.findings[0]?.source_finding_id,
  );
  expect(moved.findings[0]?.evidence.locations).toEqual([]);
  const partial = normalizeSemgrepPlatformFindings(
    platformReport([
      { ...original, location: { file_path: "src/app.ts", end_line: 17 } },
    ]),
  );
  expect(partial.findings[0]?.evidence).toMatchObject({
    locations: [{ path: "src/app.ts", line: null }],
    details: { code: { end_line: null } },
    source_data: { finding: { location: { end_line: 17 } } },
  });
});

test("uses the requested scope for missing row fields and preserves the original evidence", async () => {
  const { repository, ref, ...base } = platformFinding(1);
  const rows = [
    base,
    { ...base, id: 2, repository: {} },
    { ...base, id: 3, ref },
    { ...base, id: 4, repository },
    { ...base, id: 5, repository: { name: "project", url: null } },
  ];
  const report = await collectPages({ findings: rows });
  const parsed = normalizeSemgrepPlatformFindings(
    JSON.parse(JSON.stringify(report)),
  );
  expect(
    parsed.findings.map(({ evidence }) => evidence.source_data?.["finding"]),
  ).toEqual(rows);
  expect(
    parsed.findings.every(
      ({ evidence }) =>
        evidence.branch === platformRef &&
        evidence.details?.repository?.url === platformProject.url,
    ),
  ).toBe(true);
  for (const scope of [
    { repository: null },
    { repository: { url: 42, name: "project" } },
    { repository: { url: null } },
    { repository: { name: 42, url: platformProject.url } },
    { ref: null },
    { ref: "" },
    { ref: "refs/heads/foreign" },
  ]) {
    expect(() =>
      normalizeSemgrepPlatformFindings(platformReport([{ ...base, ...scope }])),
    ).toThrow();
  }
});

test("fails before acquisition without opt-in, honors cancellation, and never returns a partial page set", async () => {
  const never = () => {
    throw new Error("unexpected request");
  };
  await expect(
    collectSemgrepPlatformFindings(options, { environment: {}, fetch: never }),
  ).rejects.toThrow("CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS");
  await expect(
    collectSemgrepPlatformFindings(options, {
      environment: { ...environment, SEMGREP_APP_TOKEN: "synthetic\nline" },
      fetch: never,
    }),
  ).rejects.toThrow("NUL or line break");
  for (const project of [".", ".."])
    await expect(
      collectSemgrepPlatformFindings(
        { ...options, project },
        { environment, fetch: never },
      ),
    ).rejects.toThrow("Invalid Semgrep");
  const stopped = AbortSignal.abort(new Error("stopped"));
  for (const [signal, dependencySignal] of [
    [stopped],
    [new AbortController().signal, stopped],
  ]) {
    await expect(
      collectSemgrepPlatformFindings(
        { ...options, signal },
        { environment, signal: dependencySignal, fetch: never },
      ),
    ).rejects.toThrow("stopped");
  }
  for (const [response, error] of [
    [Response.json({ findings: first }), "repeated"],
    [
      Response.json({
        findings: [{ id: String(first.length) }, { id: first.length + 1 }],
      }),
      "repeated",
    ],
    [
      new Response("try later", {
        status: 429,
        headers: { "retry-after": "11" },
      }),
      "Retry-After: 11",
    ],
    [Response.json({ error: "not a findings page" }), "must be an array"],
  ] as const) {
    await expect(collectPages({ findings: first }, response)).rejects.toThrow(
      error,
    );
  }
  const limited = () =>
    new Response("try later", { status: 429, headers: { "Retry-After": "0" } });
  await expect(
    collectPages({ findings: first }, limited(), limited()),
  ).rejects.toThrow("Retry-After: 0: try later");
});

test("detects removals before the next offset even when no finding ID repeats", async () => {
  // Finding 1 disappears and the first finding from page 1 shifts into page 0.
  await expect(
    collectPages(
      { findings: first },
      { findings: [{ id: first.length + 2 }] },
      { findings: [...first.slice(1), { id: first.length + 1 }] },
    ),
  ).rejects.toThrow("changed across pages");

  const invalid = { ...platformFinding(1), id: null };
  const initial = [invalid, ...first.slice(1)];
  const reread = [
    { id: null, ...Object.fromEntries(Object.entries(invalid).reverse()) },
    ...first
      .slice(1)
      .map((row) => ({ ...row, id: String(row.id), status: "fixed" })),
  ];
  const report = await collectPages(
    { findings: initial },
    { findings: [] },
    { findings: reread.reverse() },
  );
  expect(report.findings).toEqual(initial);
});

test("checks the web and Git destinations of native Semgrep repository URLs", async () => {
  const source = "https://scm.example.test/Team/repo";
  const foreign = "https://scm.example.test/Team/%2e%2e/../repo";
  const project = { ...platformProject, url: source };
  const finding = { ...platformFinding(12), repository: { url: foreign } };
  for (const sourceRepositoryUrl of [source, foreign])
    await expect(
      collectProject({ ...project, url: foreign }, [], sourceRepositoryUrl),
    ).rejects.toThrow("does not match");
  await expect(collectProject(project, [finding])).rejects.toThrow(
    "does not match",
  );
  expect(() =>
    normalizeSemgrepPlatformFindings({ ...platformReport([finding]), project }),
  ).toThrow("does not match");

  finding.repository.url =
    "https://scm.example.test/Team/foreign%5Csub/../repo";
  const report = await collectProject(project, [finding]);
  expect(
    normalizeSemgrepPlatformFindings(report).findings[0]!.evidence
      .source_data?.["finding"],
  ).toEqual(finding);
});

test("keeps an operator mapping separate from a URL-less project and its short repository name", async () => {
  const project = { ...platformProject, url: null };
  const finding = { ...platformFinding(1), repository: { name: "project" } };
  const report = await collectProject(project, [finding], platformProject.url);
  expect(report).toMatchObject({
    project,
    sourceRepositoryUrl: platformProject.url,
  });
  expect(() =>
    normalizeSemgrepPlatformFindings({
      ...report,
      project: { ...project, url: {} },
    }),
  ).toThrow("Semgrep project repository URL must be text.");
  const { findings } = normalizeSemgrepPlatformFindings(report);
  expect(findings[0]?.evidence).toMatchObject({
    details: { repository: { url: platformProject.url } },
    source_data: { project, sourceRepositoryUrl: platformProject.url, finding },
  });
  expect(() =>
    normalizeSemgrepPlatformFindings(
      report,
      "https://github.com/other/project",
    ),
  ).toThrow("does not match");
  expect(() =>
    normalizeSemgrepPlatformFindings({
      ...report,
      findings: [{ ...finding, repository: { name: "other/project" } }],
    }),
  ).toThrow("matching source repository");
});

test("replays only the repository names observed for each collected split project", async () => {
  const project = {
    ...platformProject,
    name: "example/mono/moduleA",
    url: "https://github.com/example/mono.git/",
  };
  // An independently configured name and the physical SCM path can both differ from the selected project.
  const names = ["example/mono", "mono", project.name, "moduleA"];
  const rows = names.map((name, i) => ({
    ...platformFinding(i + 1),
    repository: { name },
  }));
  const customName = "legacy/scanner-repo";
  const report = await collectProject(project, [
    ...rows,
    {
      ...platformFinding(5),
      repository: { name: customName, url: project.url },
    },
  ]);
  expect(report.repositoryAliases).toEqual([...names, customName]);
  expect(normalizeSemgrepPlatformFindings(report).findings).toHaveLength(5);

  const other = { ...project, id: 78, name: "example/mono/moduleB" };
  const foreign = {
    ...platformFinding(6),
    repository: { name: other.name, url: project.url },
  };
  const otherReport = await collectProject(other, [foreign]);
  expect(normalizeSemgrepPlatformFindings(otherReport).findings).toHaveLength(
    1,
  );
  const swapped = {
    ...report,
    findings: otherReport.findings,
    findingCount: 1,
  };
  for (const repository of [
    foreign.repository,
    { name: other.name },
    { name: "mono", url: "https://github.com/other/mono" },
  ]) {
    expect(() =>
      normalizeSemgrepPlatformFindings({
        ...swapped,
        findings: [{ ...foreign, repository }],
      }),
    ).toThrow("repository");
  }
  // Public v1 exports predate the observation list. They used the URL as the binding when present.
  const legacy = { ...swapped };
  delete legacy.repositoryAliases;
  const normalized = normalizeSemgrepPlatformFindings(legacy);
  expect(normalized.findings[0]?.evidence.source_data).toMatchObject({
    finding: foreign,
  });
  expect(normalized.findings[0]?.evidence.source_data).not.toHaveProperty(
    "repositoryAliases",
  );
});

test.each([
  ["github.com/example/tmp/../repo", "github.com/example/./repo", true],
  ["github.com/example/%2e/repo", "github.com/example/./repo", false],
  ["github.com/example/my-repo", "github.com/example/my%2Drepo", true],
  ["github.com/example/my%2Drepo", "github.com/example/my-repo", true],
  ["github.com/example/nested/repo", "github.com/example/nested%2Frepo", false],
  ["github.com/example/my-repo", "github.com/example/my%252Drepo", false],
  [
    "[2001:db8::1]:8443/org/repo",
    "[2001:0db8:0:0:0:0:0:1]:8443/org/repo",
    true,
  ],
  ["bücher.example.test/Org/Repo", "xn--bcher-kva.example.test/Org/Repo", true],
  [
    "bücher.example.test/Org/Repo",
    "xn--bcher-kva.example.test:443/Org/Repo",
    false,
  ],
] as const)(
  "compares HTTP repositories %s and %s (matches=%s)",
  async (native, path, matches) => {
    const base = "https://";
    const project = { ...platformProject, url: base + native };
    const url = base + path;
    const finding = { ...platformFinding(1), repository: { url } };
    if (!matches) {
      await expect(collectProject(project, [finding])).rejects.toThrow(
        "does not match",
      );
      expect(() =>
        normalizeSemgrepPlatformFindings({
          ...platformReport([finding]),
          project,
        }),
      ).toThrow("does not match");
      return;
    }
    const report = await collectProject(project, [finding], url);
    const replay = normalizeSemgrepPlatformFindings(report, url);
    expect(replay.findings[0]?.evidence.source_data).toMatchObject({
      project,
      sourceRepositoryUrl: url,
      finding,
    });
  },
);

test.each([
  "git@scm.example.test:team/repo.git",
  "https://scm.example.test/team/%72epo",
])(
  "normalizes %s against the caller's identified Enterprise GitHub repository",
  (rowUrl) => {
    const url = "https://scm.example.test/Team/Repo";
    const row = {
      ...platformFinding(1),
      repository: { url: rowUrl },
    };
    const report = {
      ...platformReport([row]),
      project: { ...platformProject, url },
    };
    for (const normalize of [
      normalizeSemgrepFindings,
      normalizeSemgrepPlatformFindings,
    ]) {
      const source = { url: url.toLowerCase(), platform: "github" as const };
      expect(
        normalize(report, { sourceRepositories: [source] }).findings,
      ).toHaveLength(1);
      expect(() =>
        normalize(report, {
          sourceRepositories: [{ ...source, url: source.url + "-other" }],
        }),
      ).toThrow();
      expect(() => normalize(report)).toThrow();
    }
  },
);

test("preserves .git on custom repository URLs and legacy name-only rows", () => {
  const url = "https://git.example.test/team/lib";
  const read = (repository: { url?: string; name?: string }, github = false) =>
    normalizeSemgrepPlatformFindings(
      {
        ...platformReport([{ ...platformFinding(10), repository }]),
        project: {
          ...platformProject,
          name: "scan-project",
          url: url + ".git",
        },
      },
      github ? { sourceRepositories: [{ url, platform: "github" }] } : {},
    );
  expect(() => read({ url })).toThrow("repository");
  expect(() => read({ name: "lib" })).toThrow("repository");
  expect(read({ name: "lib.git" }).findings).toHaveLength(1);
  for (const name of ["lib.git", "lib"])
    expect(read({ name }, true).findings).toHaveLength(1);
});

test("legacy name-only rows match SCM path segments in plain or URL spelling", () => {
  const read = (path: string, name: string) =>
    normalizeSemgrepPlatformFindings({
      ...platformReport([{ ...platformFinding(1), repository: { name } }]),
      project: {
        ...platformProject,
        name: "scan-module",
        url: `https://gitlab.com/${path}`,
      },
    });
  const path = "Group/My%2DCaf%C3%A9.git";
  for (const name of ["Group/My-Café", "My-Café", "My%2DCaf%C3%A9"])
    expect(read(path, name).findings).toHaveLength(1);
  expect(() => read("Group/My%2FCaf%C3%A9", "Café")).toThrow("matching source");
  expect(() => read("Group/My%252DRepo", "My-Repo")).toThrow("matching source");
});

test.each(["github.com.", "example.ghe.com.", "gitlab.com."])(
  "collects and replays public clone aliases on the same %s authority",
  async (host) => {
    const url = `https://${host}/Team/Lib.git`;
    const mapping =
      host === "gitlab.com."
        ? url.slice(0, -4)
        : url.slice(0, -4).toLowerCase();
    const project = { ...platformProject, url };
    const finding = { ...platformFinding(7), repository: { url: mapping } };
    const report = await collectProject(project, [finding], mapping);
    expect(
      normalizeSemgrepPlatformFindings(report).findings[0]?.evidence
        .source_data,
    ).toMatchObject({ project, sourceRepositoryUrl: mapping });
    await expect(
      collectProject(project, [finding], mapping.replace("./", "/")),
    ).rejects.toThrow("does not match");
    for (const name of ["Lib", "Lib.git"])
      expect(
        normalizeSemgrepPlatformFindings({
          ...platformReport([{ ...finding, repository: { name } }]),
          project,
        }).findings,
      ).toHaveLength(1);
  },
);

test("keeps known non-GitHub URLs case-sensitive during collection", async () => {
  for (const host of [
    "gitlab.com",
    "bitbucket.org",
    "dev.azure.com",
    "example.visualstudio.com",
    "example.visualstudio.com.",
  ]) {
    const url = `https://${host}/Team/Repo`;
    const finding = {
      ...platformFinding(1),
      repository: { url: url.toLowerCase() },
    };
    await expect(
      collectProject({ ...platformProject, url }, [finding]),
    ).rejects.toThrow("does not match");
  }
});

test("losslessly captures distinct int64 IDs and rejects a truncated saved report", async () => {
  const ids = [
    "9223372036854775806",
    "9.223372036854775807e18",
    "9007199254740990.5",
  ];
  const digits = "9007199254740993";
  const records = ids.map((id) => ({
    ...platformFinding(17),
    id,
    rule: { name: digits, message: digits },
    first_seen_scan_id: digits,
  }));
  // Emit int64 fields as JSON numbers without rounding them in the fixture.
  const json = JSON.stringify({ findings: records }).replace(
    /"(id|first_seen_scan_id)":"([\d.e]+)"/gu,
    '"$1":$2',
  );
  const report = await collectPages(new Response(json));
  expect(report.findings).toEqual(records);
  const parsed = normalizeSemgrepPlatformFindings(
    JSON.parse(JSON.stringify(report)),
  );
  expect(parsed.excluded).toHaveLength(1);
  const legacy = normalizeSemgrepPlatformFindings({
    ...platformReport(records),
    project: { ...platformProject, id: String(platformProject.id) },
    repositoryAliases: ["project"],
  });
  expect(parsed.findings).toMatchObject(legacy.findings);
  expect(
    parsed.findings.map((row) => row.evidence.source_data?.["numericFields"]),
  ).toEqual(
    ids
      .slice(0, 2)
      .map((id) => ({ finding: { id, first_seen_scan_id: digits } })),
  );
  expect(parsed.findings[0]!.evidence).toMatchObject({
    title: digits,
    description: digits,
  });

  const numericRule = await collectPages(
    new Response(
      json.replace(
        `"name":"${digits}","message":"${digits}"`,
        `"name":${digits},"message":${digits}`,
      ),
    ),
  );
  for (const saved of [numericRule, JSON.parse(JSON.stringify(numericRule))]) {
    const replay = normalizeSemgrepPlatformFindings(saved);
    expect(replay.findings).toEqual([parsed.findings[1]!]);
    expect(replay.excluded[0]).toMatchObject({
      position: 1,
      source_finding_id: parsed.findings[0]!.source_finding_id,
      reason: expect.stringContaining("title"),
    });
  }
  const canonical = normalizeSemgrepPlatformFindings(
    platformReport([{ ...records[1], id: "9223372036854775807" }]),
  );
  expect(parsed.findings).toHaveLength(2);
  expect(parsed.findings[1]?.source_finding_id).toBe(
    canonical.findings[0]!.source_finding_id,
  );
  expect(parsed.findings[0]?.source_finding_id).not.toBe(
    parsed.findings[1]?.source_finding_id,
  );
  expect(() =>
    normalizeSemgrepPlatformFindings({
      ...report,
      findings: [report.findings[0]],
    }),
  ).toThrow("Incomplete");
});

test("validates numeric field markers against the saved finding's own values", () => {
  const digits = "9007199254740993";
  const metadata = { ["__proto__"]: digits, label: "ordinary text" };
  const row = { ...platformFinding(17), metadata };
  const saved = (fields: unknown) =>
    JSON.parse(
      JSON.stringify({
        ...platformReport([row]),
        numericFields: { findings: { 0: fields } },
      }),
    );
  for (const fields of [
    { missing: digits },
    { ["__proto__"]: {} },
    { metadata: { label: metadata.label } },
    { metadata: { ["__proto__"]: "9007199254740995" } },
  ])
    expect(() => normalizeSemgrepPlatformFindings(saved(fields))).toThrow(
      /scanner (?:number|numeric)/iu,
    );

  const input = saved({ metadata: { ["__proto__"]: digits } });
  const original = JSON.stringify(input);
  const { findings } = normalizeSemgrepPlatformFindings(input);
  expect(JSON.stringify(findings[0]!.evidence.source_data?.["finding"])).toBe(
    JSON.stringify(row),
  );
  expect(JSON.stringify(input)).toBe(original);
});

test("rejects wrong repository or ref even on rows otherwise excluded; excludes ambiguous and unsafe integer IDs", async () => {
  const finding = platformFinding(10);
  expect(() =>
    normalizeSemgrepPlatformFindings(
      platformReport([]),
      "https://github.com/other/project",
    ),
  ).toThrow("repository");
  const ambiguousUrl = platformProject.url + "?";
  const ambiguous = {
    ...platformReport([]),
    project: { ...platformProject, url: ambiguousUrl },
  };
  expect(() => normalizeSemgrepPlatformFindings(ambiguous)).toThrow(
    "without credentials, query or fragment",
  );
  for (const wrong of [
    { ...finding, id: null, ref: "main" },
    {
      ...finding,
      repository: { url: "git@[github.com:]:example/project.git" },
    },
    {
      ...finding,
      repository: { url: "git@github.com\x01:example/project.git" },
    },
    {
      ...finding,
      repository: { url: "https://git.example.test/other/project" },
    },
  ])
    expect(() =>
      normalizeSemgrepPlatformFindings(platformReport([wrong])),
    ).toThrow();
  const samePage = await collectPages({ findings: [finding, finding] });
  const duplicate = normalizeSemgrepPlatformFindings(
    platformReport([...samePage.findings, { ...finding, id: 2 ** 53 }]),
  );
  expect(duplicate.excluded).toHaveLength(3);
  expect(duplicate.findings).toHaveLength(0);
  const empty = normalizeSemgrepPlatformFindings(platformReport([]));
  expect(empty).toEqual({
    read: 0,
    excluded: [],
    findings: [],
    sourceRepositoryUrl: platformProject.url,
  });
});

test("maps Supply Chain packages, preserves source-only reachability, and keeps AI SAST in its own namespace", () => {
  const normalizeSupplyChain = (...findings: unknown[]) =>
    normalizeSemgrepPlatformFindings(platformReport(findings, "sca"));
  const finding = platformFinding(21);
  const sca = {
    ...finding,
    vulnerability_identifier: "CVE-2025-0001",
    found_dependency: {
      package: "example-pkg",
      ecosystem: "npm",
      version: "1.0.0",
    },
    fix_recommendations: [
      { package: "other-pkg", version: "2.0.0" },
      { package: "example-pkg", version: "1.1.0" },
    ],
    reachability: "reachable",
    location: { file_path: "../outside", line: 1 },
  };
  const result = normalizeSupplyChain(sca);
  expect(result.findings[0]?.evidence).toMatchObject({
    packages: [
      {
        name: "example-pkg",
        ecosystem: "npm",
        installed_version: "1.0.0",
        fixed_versions: ["1.1.0"],
      },
    ],
    advisory_ids: ["CVE-2025-0001"],
    locations: [],
    source_data: { finding: { reachability: "reachable" } },
  });
  for (const metadata of [
    {},
    { found_dependency: {} },
    { found_dependency: { ecosystem: "npm", version: "1.0.0" } },
  ]) {
    const advisoryOnly = {
      ...finding,
      ...metadata,
      vulnerability_identifier: "CVE-2025-0001",
    };
    const result = normalizeSupplyChain(advisoryOnly);
    expect(result.findings[0]?.evidence).toMatchObject({
      advisory_ids: ["CVE-2025-0001"],
      packages: [],
      source_data: { finding: advisoryOnly },
    });
  }
  const ruleOnly = normalizeSupplyChain(finding);
  expect(ruleOnly.findings[0]?.evidence).toMatchObject({
    title: finding.rule.name,
    packages: [],
    advisory_ids: [],
    source_data: { finding },
  });
  const invalid = normalizeSupplyChain(
    {
      ...finding,
      rule: {},
      found_dependency: {},
      vulnerability_identifier: " ",
    },
    { ...sca, id: 22, found_dependency: { package: 42 } },
    { ...sca, id: 23, found_dependency: [] },
  );
  expect(invalid.excluded).toHaveLength(3);
  expect(
    normalizeSemgrepPlatformFindings(platformReport([sca])).excluded,
  ).toHaveLength(1);
  const code = normalizeSemgrepPlatformFindings(platformReport([finding]));
  const ai = normalizeSemgrepPlatformFindings(
    platformReport([finding], "ai_sast"),
  );
  expect(ai.findings[0]?.evidence.details?.kind).toBe("sast");
  expect(ai.findings[0]?.source_finding_id).not.toBe(
    code.findings[0]?.source_finding_id,
  );
});

test("keeps message-only findings and preserves ambiguous hosted paths as native evidence", () => {
  for (const product of ["sast", "ai_sast", "sca"] as const) {
    const description = "Check the unsafe input.";
    const finding = {
      ...platformFinding(42),
      ...(product === "ai_sast"
        ? { rule: {}, rule_message: description }
        : { rule: { message: description } }),
      location: { file_path: "src/rules\\test.py", line: 2, end_line: 4 },
    };
    const report = normalizeSemgrepPlatformFindings(
      platformReport([finding], product),
    );
    expect(report.excluded).toEqual([]);
    expect(report.findings[0]?.evidence).toMatchObject({
      title: description,
      description,
      locations: [],
      source_data: { finding },
      ...(product === "sca"
        ? { packages: [], advisory_ids: [] }
        : { details: { rule: null, code: { end_line: null } } }),
    });
  }
});

test("keeps a long rule message in the Cloud description and native evidence", async () => {
  const message = "é".repeat(257);
  const id = "9.223372036854775807e18";
  const finding = { ...platformFinding(42), id, rule: { message } };
  const page = JSON.stringify({ findings: [finding] }).replace(
    `"id":"${id}"`,
    `"id":${id}`,
  );
  const captured = await collectPages(new Response(page));
  for (const product of ["sast", "ai_sast", "sca"] as const) {
    const report = { ...JSON.parse(JSON.stringify(captured)), product };
    const current = normalizeSemgrepPlatformFindings(report).findings[0]!;
    const legacy = normalizeSemgrepPlatformFindings(
      platformReport([finding], product),
    ).findings[0]!;
    expect(current.source_finding_id).toBe(legacy.source_finding_id);
    expect(legacy.evidence.title).toBe(`Semgrep finding ${id}`);
    expect(current.evidence).toMatchObject({
      title: "Semgrep finding 9223372036854775807",
      description: message,
      source_data: { finding },
    });
    expect(
      normalizeSemgrepPlatformFindings(report, {}, "local").findings[0]
        ?.evidence.title,
    ).toBe(message);
  }
});
