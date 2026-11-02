import { expect, test } from "bun:test";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import { normalizeSelectedSemgrepPlatformFindings } from "../src/semgrep-platform-findings.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";

const url = "https://github.com/example/project";
const ref = "refs/heads/topic";
const ids = ["9007199254740992", "9007199254740993"];
const source = {
  deployment: "demo",
  ref,
  sourceRepositoryUrl: url,
  projectResponse: JSON.stringify({
    project: { id: 77, name: "example/project", url },
  }),
  findingIds: ids,
};
const page = (id: string, branch = ref, repo = url) =>
  `{"findings":[{"id":${id},"ref":"${branch}","repository":{"url":"${repo}"},"rule":{"name":"example.rule"},"severity":"medium","location":{"file_path":"src/app.ts","line":2},"score":1.00000000000000001,"units":9007199254740993,"magnitude":1e100000}]}`;

test("reimporting two selected IDs from a non-default branch leaves both SQLite records unchanged", async () => {
  await using fixture = await localFindingsFixture({ remote: url });
  fixture.git("switch", "--quiet", "--orphan", "topic");
  expect(fixture.git("symbolic-ref", "HEAD").trim()).toBe(ref);
  const options = {
    provider: "semgrep" as const,
    sourceKey: "demo/topic",
    repository: fixture.repository,
  };
  const dependencies = {
    environment: fixture.environment,
    sourceRepositories: [{ url }],
  };
  const prepare = (findingsResponses: string[]) =>
    prepareNormalizedLocalImport(
      normalizeSelectedSemgrepPlatformFindings({
        ...source,
        findingsResponses,
      }),
      options,
      dependencies,
    );
  const pages = [page("3"), ...ids.map((id) => page(id))];
  const first = await prepare(pages);
  expect(first.preview.excluded).toEqual([]);
  expect((await first.import()).counts).toEqual({
    created: 2,
    updated: 0,
    unchanged: 0,
  });
  const original = await listLocalExternalFindings(options, dependencies);
  expect(original).toHaveLength(2);
  expect(new Set(original.map((row) => row.sourceFindingId)).size).toBe(2);
  for (const row of original) {
    expect(row.evidence.branch).toBe(ref);
    const raw = row.evidence.source_data?.["semgrepPlatformFindingJson"];
    expect(raw).toContain('"score":1.00000000000000001');
    expect(raw).toContain('"units":9007199254740993');
    expect(raw).toMatch(/"magnitude":1e\+?100000/u);
  }
  const replay = await prepare(
    pages
      .reverse()
      .map((p) =>
        p
          .replace('"severity":"medium","location":', '"location":')
          .replace('"line":2', '"line":2.0')
          .replace(
            ',"score":1.00000000000000001',
            ',"severity":"medium","score":1.000000000000000010',
          )
          .replace('"units":9007199254740993', '"units":90071992547409930e-1')
          .replace('"magnitude":1e100000', '"magnitude":10e99999'),
      ),
  );
  expect((await replay.import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 2,
  });
  const malformed = await prepare([
    page(ids[0]!).replace('"rule":{"name":"example.rule"}', '"rule":42'),
    page(ids[1]!).replace(
      '"location":{"file_path":"src/app.ts","line":2}',
      '"location":42',
    ),
  ]);
  expect(malformed.preview.excluded).toHaveLength(2);
  expect((await malformed.import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 0,
  });
  const identityOnly = await prepare(
    ids.map((id) =>
      JSON.stringify({
        findings: [{ id, ref, repository: { url } }],
      }),
    ),
  );
  expect(identityOnly.preview.excluded).toHaveLength(2);
  expect((await identityOnly.import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 0,
  });
  expect(await listLocalExternalFindings(options, dependencies)).toEqual(
    original,
  );
});

test("each selected finding must match the independently named project, ref, and SAST product", () => {
  const first = page(ids[0]!);
  const second = page(ids[1]!);
  const select = (pages: string[]) =>
    normalizeSelectedSemgrepPlatformFindings({
      ...source,
      findingsResponses: pages,
    });
  const unrelated = '{"findings":[{"rule_name":"no-id"},{"id":2.5}]}';
  expect(select([first, unrelated, second]).findings).toHaveLength(2);
  const findingsPage = (rows: unknown[]) => JSON.stringify({ findings: rows });
  const selectedRow = {
    id: ids[1],
    ref,
    repository: { url },
    rule_name: "example.rule",
  };
  for (const other of [
    { ai_impact: "Synthetic impact" },
    { is_malicious: false },
    { issue_type: "ai_sast" },
  ]) {
    const sibling = { ...selectedRow, id: "99", ...other };
    expect(() => select([first, findingsPage([selectedRow, sibling])])).toThrow(
      "SAST",
    );
    expect(() => select([first, findingsPage([sibling, selectedRow])])).toThrow(
      "SAST",
    );
    expect(
      select([first, findingsPage([sibling]), second]).findings,
    ).toHaveLength(2);
  }
  const unknown = select([
    first,
    second.replace('"severity":"medium"', '"severity":"WARNING"'),
  ]).findings[1]!;
  expect(unknown.evidence.severity).toBe("unknown");
  expect(
    unknown.evidence.source_data?.["semgrepPlatformFindingJson"],
  ).toContain('"severity":"WARNING"');
  expect(() => select([first, unrelated])).toThrow(ids[1]);
  expect(() => select([first, second, second])).toThrow("Duplicate");
  expect(() => select([first, page(ids[1]!, "refs/heads/main")])).toThrow(
    "project and ref",
  );
  expect(() => select([first, page(ids[1]!, ref, url + ".git")])).toThrow(
    "project and ref",
  );
  for (const fields of [
    { ai_impact: "Synthetic impact" },
    { epss_score: { score: 0 } },
    { fix_recommendations: [{ package: "example", version: "2.0.0" }] },
    { found_dependency: { package: "example" } },
    { is_malicious: false },
    { reachability: "reachable" },
    { reachable_condition: "imported" },
    { usage: { location: { file_path: "src/app.ts" } } },
    { vulnerability_identifier: "CVE-2099-0001" },
  ]) {
    const finding = { ...selectedRow, ...fields };
    expect(() =>
      select([first, JSON.stringify({ findings: [finding] })]),
    ).toThrow("SAST");
  }
  for (const product of ['"sca"', '["sast"]']) {
    expect(() =>
      select([
        first,
        second.replace('"id":', '"product":' + product + ',"id":'),
      ]),
    ).toThrow("SAST");
  }
  expect(() =>
    normalizeSelectedSemgrepPlatformFindings({
      ...source,
      sourceRepositoryUrl: url + "-other",
      findingsResponses: [first, second],
    }),
  ).toThrow("operator");
});

test("the same native ID from distinct project IDs or refs has distinct occurrence IDs", () => {
  const occurrence = (projectId: number, branch: string) =>
    normalizeSelectedSemgrepPlatformFindings({
      ...source,
      projectResponse: JSON.stringify({
        project: { id: projectId, name: "example/project", url },
      }),
      ref: branch,
      findingIds: ["8"],
      findingsResponses: page("8", branch),
    }).findings[0]!.source_finding_id;
  expect(
    new Set([
      occurrence(77, ref),
      occurrence(78, ref),
      occurrence(77, "refs/tags/topic"),
    ]).size,
  ).toBe(3);
  for (const invalid of [
    "topic",
    "refs/heads/main~1",
    "refs/heads/.hidden",
    "refs/heads/a.lock",
  ]) {
    expect(() => occurrence(77, invalid)).toThrow(/ref/i);
  }
});

test("equivalent numeric IDs replay as integers while textual IDs stay exact", () => {
  const select = (token: string, wanted = "8", project = "77") =>
    normalizeSelectedSemgrepPlatformFindings({
      ...source,
      projectResponse: source.projectResponse.replace(
        '"id":77',
        '"id":' + project,
      ),
      findingIds: [wanted],
      findingsResponses: page(token),
    }).findings[0]!;
  const original = select("8");
  expect(select("8.0", "8", "77.0")).toEqual(original);
  expect(select("8e0", "8", "77e0")).toEqual(original);
  for (const token of ['"8.0"', '"8e0"', "8.00000000000000001"])
    expect(() => select(token)).toThrow("missing");
  expect(() => select("8", JSON.parse("[8.00000000000000001]")[0])).toThrow(
    "must be nonempty text",
  );
  const int64Max = "9223372036854775807";
  expect(select("9.223372036854775807e18", int64Max)).toEqual(
    select(int64Max, int64Max),
  );
  const large = "12345678901234567890123";
  expect(select(large + ".0", large)).toEqual(select(large, large));
  expect(select(large + "e0", large)).toEqual(select(large, large));
  expect(
    select(large, large).evidence.source_data?.["semgrepPlatformFindingJson"],
  ).toContain('"id":1.2345678901234567890123e+22,');
  const textualProject = select("8", "8", JSON.stringify(large));
  expect(textualProject.evidence.source_data?.["project"]).toMatchObject({
    id: large,
  });
  expect(textualProject.source_finding_id).toBe(
    select("8", "8", large).source_finding_id,
  );
  const power = "1000000000000000000000";
  expect(select("1e21", power)).toEqual(select(power, power));
  expect(() => select("1.0000000000000000000001e21", power)).toThrow("missing");
});

test("a URL-less row needs the matching project ID and full name, while an exact URL identifies the path of a short-named project", () => {
  function select(
    projectName: string,
    repository: Record<string, unknown>,
    projectUrl = url,
  ) {
    return normalizeSelectedSemgrepPlatformFindings({
      ...source,
      sourceRepositoryUrl: projectUrl,
      projectResponse: JSON.stringify({
        project: { id: 77, name: projectName, url: projectUrl },
      }),
      findingIds: ["8"],
      findingsResponses: [
        JSON.stringify({
          findings: [{ id: 8, ref, repository, rule_name: "example.rule" }],
        }),
      ],
    });
  }
  const name = "example/project";
  expect(() =>
    select("old-group/project", { id: 77, name: "old-group/project" }),
  ).toThrow("project and ref");
  expect(select(name, { id: 77, name }).findings).toHaveLength(1);
  expect(select("project", { id: 77, name }).findings).toHaveLength(1);
  expect(() => select("project", { id: 77, name: "project" })).toThrow(
    "project and ref",
  );
  for (const repository of [
    { name },
    { id: 78, name },
    { id: 77, name: "project" },
  ]) {
    expect(() => select(name, repository)).toThrow("project and ref");
  }
  expect(select("project", { url, name }).findings).toHaveLength(1);
  expect(select("old-group/project", { url, name }).findings).toHaveLength(1);
  expect(
    select("group/old-name", { url, name: "project" }).findings,
  ).toHaveLength(1);
  const encoded = "https://github.com/example/caf%C3%A9";
  expect(
    select("café", { id: 77, name: "example/café" }, encoded).findings,
  ).toHaveLength(1);
  const literal = "https://scm.example.test/team/repo.git";
  expect(() =>
    select("team/repo.git", { id: 77, name: "team/repo" }, literal),
  ).toThrow("project and ref");
  expect(
    select("team/repo.git", { id: 77, name: "team/repo.git" }, literal)
      .findings,
  ).toHaveLength(1);
  const cloneUrl = url + ".git";
  expect(
    select("project", { url: cloneUrl, name }, cloneUrl).findings,
  ).toHaveLength(1);
  const historicalProject = "old-group/project/api";
  const sibling = { url, name: "old-group/project/cli" };
  expect(select(historicalProject, sibling).findings).toHaveLength(1);
  expect(() => select(historicalProject, { ...sibling, id: 78 })).toThrow(
    "project and ref",
  );
});

test("a fractional source position cannot round to an integer during projection", () => {
  for (const position of [
    '"line":2.00000000000000001',
    '"line":2,"end_line":2.00000000000000001',
  ]) {
    const result = normalizeSelectedSemgrepPlatformFindings({
      ...source,
      findingIds: ["8"],
      findingsResponses: [page("8").replace('"line":2', position)],
    });
    expect(result.findings).toHaveLength(0);
    expect(result.excluded).toHaveLength(1);
  }
});

test("only repository-relative files are projected and original paths remain in evidence", () => {
  const evidenceFor = (path: string) =>
    normalizeSelectedSemgrepPlatformFindings({
      ...source,
      findingIds: ["8"],
      findingsResponses: page("8").replace(
        '"src/app.ts"',
        JSON.stringify(path),
      ),
    }).findings[0]!.evidence;
  for (const path of ["src/vendor://app.ts", "src/a\\b.ts", "src/a/b.ts"]) {
    expect(evidenceFor(path).locations).toEqual([{ path, line: 2 }]);
  }
  for (const path of [
    "file:src/app.ts",
    "data:text/plain,hello",
    "generated:/api.ts",
    "./C:/work/app.ts",
    "git@host:team/repo/app.ts",
    "src\\..\\outside.ts",
    ".",
    "src/",
  ]) {
    const evidence = evidenceFor(path);
    expect(evidence.locations).toEqual([]);
    expect(evidence.source_data?.["semgrepPlatformFindingJson"]).toContain(
      JSON.stringify(path),
    );
  }
});
