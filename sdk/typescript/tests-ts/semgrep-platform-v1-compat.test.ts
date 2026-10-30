import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { semgrepJson } from "./support/semgrep-import-fixtures.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { prepareNormalizedExternalPublication } from "../src/external-findings-publish.js";
import { cloudRepositoryUrlKey } from "../src/external-import-contract.js";
import { isolatedGitReportFixture as localReportFixture } from "./external-findings-local-helpers.js";
import {
  normalizeSemgrepFindings,
  readSemgrepFindings,
} from "../src/semgrep-findings.js";
import {
  selectSemgrepPlatformFindings,
  semgrepPlatformFindingRepository,
} from "../src/semgrep-platform-findings.js";

const url = "https://github.com/example/project";
const scope = {
  deployment: "demo",
  project: { id: "10", name: "example/project", url },
  ref: "refs/heads/topic",
  product: "sast",
};
const code = {
  ref: scope.ref,
  repository: { url },
  rule: { name: "fixture.rule" },
};

test.each(["sast", "ai_sast", "sca"])(
  "v1 %s requires the original title sources",
  (product) => {
    const untitled = { id: 11, ref: scope.ref, repository: { url } };
    const rows = [
      untitled,
      { id: 12, rule: { name: "named", message: "description" } },
      { id: 13, rule_message: "message" },
      ...(product === "sca"
        ? [
            {
              id: 14,
              vulnerability_identifier: "advisory",
              found_dependency: { package: "dependency" },
              rule_message: "description",
            },
            {
              id: 15,
              found_dependency: { package: "dependency" },
              rule_message: "description",
            },
          ]
        : []),
    ];
    const report = { ...scope, product, findingCount: rows.length };
    const legacy = normalizeSemgrepFindings(
      { ...report, format: "semgrep-platform-findings/v1", findings: rows },
      {},
      "local",
    );
    expect(legacy.excluded).toMatchObject([
      { position: 1, reason: "Semgrep finding title must be nonempty text." },
    ]);
    expect(legacy.findings.map((row) => row.evidence.title)).toEqual([
      "named",
      "message",
      ...(product === "sca" ? ["advisory", "dependency"] : []),
    ]);
    for (const format of [
      "semgrep-platform-findings/v2",
      ...(product === "sast" ? ["semgrep-platform-selection/v1"] : []),
    ]) {
      const current = normalizeSemgrepFindings(
        {
          ...report,
          format,
          findingCount: 1,
          findings: [JSON.stringify(untitled)],
          repositoryAliases: [],
        },
        {},
        "local",
      );
      expect(current.findings[0]?.evidence.title).toBe("Semgrep finding 11");
    }
  },
);

test("a v1 project SSH URL requires a matching GitHub Enterprise reader reference", () => {
  const source = {
    url: "https://git.example.test/team/service",
    platform: "github" as const,
  };
  const report = {
    ...scope,
    format: "semgrep-platform-findings/v1",
    sourceRepositoryUrl: source.url,
    project: { ...scope.project, url: "git@git.example.test:team/service.git" },
    findingCount: 1,
    findings: [{ id: 12, rule_name: "example.rule" }],
  };
  const read = (sourceRepositories: (typeof source)[]) =>
    normalizeSemgrepFindings(report, { sourceRepositories }, "local");
  for (const reference of [
    source.url,
    "git@git.example.test:team/service",
    "ssh://git@git.example.test/team/service",
  ]) {
    expect(read([{ ...source, url: reference }]).findings).toHaveLength(1);
  }
  expect(() => read([])).toThrow(/repository/);
  for (const foreign of [
    "git@git.example.test:team/other",
    "ssh://git@other.example.test/team/service",
  ]) {
    expect(() => read([{ ...source, url: foreign }])).toThrow(/repository/);
  }
});

test("v1 files preserve native JSON numbers without witnesses and reject a rounded finding count", async () => {
  const dir = await mkdtemp(join(tmpdir(), "semgrep-v1-"));
  const path = join(dir, "report.gz");
  try {
    const first = "9007199254740992",
      second = "9007199254740993";
    const rows = [first, second].map(
      (id) =>
        `{"id":${id},"metadata":{"score":1.00000000000000001,"key":${id}},"rule":{"name":"fixture.rule"}}`,
    );
    const report = (count: string) =>
      `{"format":"semgrep-platform-findings/v1","deployment":"demo","project":{"id":9007199254740993,"name":"example/project","url":"${url}"},"ref":"refs/heads/topic","product":"sast","findings":[${rows}],"findingCount":${count}}`;
    await writeFile(path, gzipSync(report("2")));
    const result = await readSemgrepFindings(path, {}, "local");
    expect(result.excluded).toEqual([]);
    expect(new Set(result.findings.map((f) => f.source_finding_id)).size).toBe(
      2,
    );
    for (const [index, finding] of result.findings.entries()) {
      const retained = finding.evidence.source_data!;
      expect(retained["project"]).toMatchObject({ id: second });
      expect(retained["semgrepPlatformFindingJson"]).toContain(
        '"score":1.00000000000000001',
      );
      expect(retained["semgrepPlatformFindingJson"]).toContain(
        `"key":${[first, second][index]}`,
      );
    }
    await writeFile(
      path,
      gzipSync(
        report("2").replace(
          '"metadata"',
          '"repository":{"id":9007199254740992},"metadata"',
        ),
      ),
    );
    await expect(readSemgrepFindings(path, {}, "local")).rejects.toThrow(
      "repository",
    );
    // A direct SDK input that already went through JSON.parse cannot recover an unsafe ID.
    const rounded = {
      ...scope,
      project: { ...scope.project, id: first },
      format: "semgrep-platform-findings/v1",
      findingCount: 1,
      findings: [JSON.parse('{"id":1,"repository":{"id":9007199254740993}}')],
    };
    expect(() => normalizeSemgrepFindings(rounded, {}, "local")).toThrow(
      "exact, positive",
    );
    await writeFile(path, gzipSync(report("2.00000000000000001")));
    await expect(readSemgrepFindings(path, {}, "local")).rejects.toThrow(
      "finding count",
    );
    const mixed = {
      ...scope,
      format: "semgrep-platform-findings/v1",
      findingCount: 2,
      findings: [
        { ...code, id: 1.5 },
        { ...code, id: 12 },
      ],
    };
    await writeFile(path, gzipSync(JSON.stringify(mixed)));
    const file = await readSemgrepFindings(path, {}, "local");
    expect(file.findings).toHaveLength(1);
    expect(file.excluded).toMatchObject([{ position: 1 }]);
    expect(normalizeSemgrepFindings(mixed, {}, "local")).toEqual(file);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a legacy object witness cannot turn a native number into repository evidence", async () => {
  const dir = await mkdtemp(join(tmpdir(), "semgrep-v1-witness-"));
  try {
    const path = join(dir, "report.json");
    await writeFile(
      path,
      JSON.stringify({
        ...scope,
        format: "semgrep-platform-findings/v1",
        findingCount: 1,
        findings: [{ ...code, id: 12, repository: 42 }],
        numericFields: { findings: { 0: { repository: {} } } },
      }),
    );
    await expect(readSemgrepFindings(path, {}, "local")).rejects.toThrow(
      "Invalid scanner numeric fields",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("v1 SDK rows reject numbers that cannot be retained exactly", () => {
  const report = (token: string) => ({
    ...scope,
    format: "semgrep-platform-findings/v1",
    findingCount: 1,
    findings: [
      { ...code, id: 12, metadata: { values: JSON.parse(`[${token}]`) } },
    ],
  });
  for (const token of ["9007199254740993", "1e400"]) {
    expect(() => normalizeSemgrepFindings(report(token), {}, "local")).toThrow(
      "original Semgrep export",
    );
  }
  const result = normalizeSemgrepFindings(report("0.125"), {}, "local");
  expect(
    result.findings[0]!.evidence.source_data?.["semgrepPlatformFindingJson"],
  ).toContain('"values":[0.125]');
});

test("textual decimal and exponent IDs stay specific to v1 artifacts", () => {
  const historical = normalizeSemgrepFindings(
    {
      ...scope,
      project: { ...scope.project, id: "1e1" },
      format: "semgrep-platform-findings/v1",
      findings: [{ ...code, id: "1.2e1" }],
      findingCount: 1,
    },
    {},
    "local",
  );
  const v2 = (id: string | number) => ({
    ...scope,
    format: "semgrep-platform-findings/v2",
    findingCount: 1,
    repositoryAliases: [],
    findings: [JSON.stringify({ ...code, id })],
  });
  const modern = normalizeSemgrepFindings(v2(12), {}, "local");
  expect(historical.excluded).toEqual([]);
  expect(historical.findings[0]!.source_finding_id).toBe(
    modern.findings[0]!.source_finding_id,
  );
  expect(
    historical.findings[0]!.evidence.source_data?.[
      "semgrepPlatformFindingJson"
    ],
  ).toContain('"id":"1.2e1"');
  expect(
    semgrepPlatformFindingRepository(historical.findings[0]!, "semgrep"),
  ).toBe(url);
  expect(
    normalizeSemgrepFindings(v2("1.2e1"), {}, "local").findings,
  ).toHaveLength(0);
  expect(() =>
    selectSemgrepPlatformFindings({
      deployment: scope.deployment,
      ref: scope.ref,
      projectResponse: JSON.stringify({ project: scope.project }),
      findingsResponses: [JSON.stringify({ findings: [{ ...code, id: 12 }] })],
      findingIds: ["1.2e1"],
    }),
  ).toThrow("exact, positive");
});

test("v1 files, original projected rows and v2 share one local occurrence version", async () => {
  const rows = [
    { ...code, id: 12, repository: { name: "display", id: "10" } },
    { ...code, id: "13", repository: { name: "display" } },
  ];
  const report = { ...scope, repositoryAliases: ["display"], findingCount: 2 };
  const source = { provider: "semgrep" as const, sourceKey: "demo/topic" };
  await using fixture = await localReportFixture("semgrep.json", source, {
    remote: url,
  });
  await fixture.writeJson({
    ...report,
    format: "semgrep-platform-findings/v1",
    sourceRepositoryUrl: "https://github.com/Example/Project.git",
    findings: rows,
  });
  const original = await fixture.prepare();
  expect((await original.import()).counts).toEqual({
    created: 2,
    updated: 0,
    unchanged: 0,
  });
  const projected = structuredClone(original.preview);
  for (const [i, finding] of projected.findings.entries()) {
    finding.evidence.source_data = {
      ...scope,
      format: "semgrep-platform-findings/v1",
      repositoryAliases: report.repositoryAliases,
      finding: rows[i],
    };
  }
  const prepareProjected = () =>
    prepareNormalizedLocalImport(
      projected,
      { ...source, repository: fixture.repository },
      { environment: fixture.environment },
    );
  const unchanged = { created: 0, updated: 0, unchanged: 2 };
  expect((await (await prepareProjected()).import()).counts).toEqual(unchanged);
  expect((await (await fixture.prepare()).import()).counts).toEqual(unchanged);
  expect((await fixture.read()).map((row) => row.version)).toEqual([1, 1]);
  await fixture.writeJson({
    ...report,
    format: "semgrep-platform-findings/v2",
    findings: rows.map((row) => JSON.stringify(row)),
  });
  const replay = await fixture.prepare();
  expect(replay.preview.findings).toEqual(original.preview.findings);
  expect((await replay.import()).counts).toEqual(unchanged);

  // A change in the retained vendor row is meaningful even when its title and location stay the same.
  projected.findings[0]!.evidence.source_data!["finding"] = {
    ...rows[0],
    metadata: { revision: 2 },
  };
  expect((await (await prepareProjected()).import()).counts).toEqual({
    created: 0,
    updated: 1,
    unchanged: 1,
  });
  expect((await fixture.read()).map((row) => row.version).sort()).toEqual([
    1, 2,
  ]);
});

test("original v1 normalized rows can bind a name-only alias through a sibling in the same scope", async () => {
  const label = "display";
  const legacy = {
    ...scope,
    format: "semgrep-platform-findings/v1",
    repositoryAliases: [label],
  };
  const native = [
    { ...code, id: 12, repository: { name: label } },
    { ...code, id: 13, repository: { name: label, id: scope.project.id, url } },
  ];
  const batch = normalizeSemgrepFindings(
    { ...legacy, findingCount: native.length, findings: native },
    {},
    "local",
  );
  for (const [i, finding] of batch.findings.entries()) {
    // #2085 stored the vendor object without the later per-row witness string.
    finding.evidence.source_data = { ...legacy, finding: native[i] };
    finding.source_finding_id = "retained-" + i;
  }
  const source = { provider: "semgrep" as const, sourceKey: "demo/topic" };
  await using fixture = await localReportFixture("v1.json", source, {
    remote: url,
  });
  const prepare = (input: typeof batch) =>
    prepareNormalizedLocalImport(
      input,
      { ...source, repository: fixture.repository },
      { environment: fixture.environment },
    );
  batch.findings[0]!.evidence.title = "Title chosen by the caller";
  const first = await prepare(batch);
  expect((await first.import()).counts).toEqual({
    created: 2,
    updated: 0,
    unchanged: 0,
  });
  expect((await (await prepare(batch)).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 2,
  });
  expect(
    (await fixture.read()).find((row) => row.sourceFindingId === "retained-0"),
  ).toMatchObject({
    version: 1,
    evidence: { title: "Title chosen by the caller" },
  });
  expect(batch.findings[0]!.evidence.source_data).toEqual({
    ...legacy,
    finding: native[0],
  });

  for (const other of [
    { ...scope, project: { ...scope.project, id: "11" } },
    { ...scope, ref: "refs/heads/other" },
    {
      ...scope,
      project: { ...scope.project, url: "https://github.com/other/project" },
    },
  ]) {
    const foreign = structuredClone(batch);
    const witness = foreign.findings[1]!.evidence;
    witness.source_data = {
      ...legacy,
      ...other,
      finding: {
        ...native[1],
        ref: other.ref,
        repository: {
          name: label,
          id: other.project.id,
          url: other.project.url,
        },
      },
    };
    witness.branch = other.ref;
    witness.details!.repository!.url = other.project.url;
    await expect(prepare(foreign)).rejects.toThrow(/alias|witness|repository/i);
  }
});

test("v1 replays legacy decimal proof IDs and canonical bindings on dependent rows", () => {
  const result = normalizeSemgrepFindings(
    {
      ...scope,
      format: "semgrep-platform-findings/v1",
      repositoryAliases: ["display"],
      findingCount: 2,
      findings: [
        { ...code, id: 12, repository: { name: "display", id: "1e1" } },
        { ...code, id: 13, repository: { name: "display" } },
      ],
    },
    {},
    "local",
  );
  expect(result.excluded).toEqual([]);
  expect(result.findings).toHaveLength(2);
  const [proof, dependent] = result.findings;
  expect(proof!.evidence.source_data?.["format"]).toBe(
    "semgrep-platform-findings/v1",
  );
  expect(dependent!.evidence.source_data?.["format"]).toBe(
    "semgrep-platform-findings/v2",
  );
  for (const finding of result.findings)
    expect(semgrepPlatformFindingRepository(finding, "semgrep")).toBe(url);

  // Previously saved name-only rows can still carry the proving row's decimal v1 repository ID.
  const previous = structuredClone(dependent!);
  Object.assign(previous.evidence.source_data!, {
    format: "semgrep-platform-findings/v1",
    idEncoding: "v1-decimal",
    repositoryWitnessJson: JSON.stringify({ name: "display", id: "1e1" }),
  });
  expect(semgrepPlatformFindingRepository(previous, "semgrep")).toBe(url);
});

test("a legacy report verifies each display label against that row's repository ID or URL", async () => {
  const name = "display";
  const row = (repository: Record<string, unknown>, id = 12) => ({
    ...code,
    id,
    repository,
  });
  const report = (...findings: ReturnType<typeof row>[]) => ({
    ...scope,
    format: "semgrep-platform-findings/v1",
    findings,
    findingCount: findings.length,
  });
  await using fixture = await localReportFixture(
    "v1.json",
    { provider: "semgrep", sourceKey: "demo/topic" },
    { remote: url },
  );
  await fixture.writeJson(report(row({ name, id: 10 })));
  const prepared = await fixture.prepare();
  expect((await prepared.import()).counts).toEqual({
    created: 1,
    updated: 0,
    unchanged: 0,
  });
  for (const rows of [
    [row({ name, id: 11, url })],
    [row({ name, id: 10, url: "https://github.com/example/other" })],
    [row({ name, url }), row({ name }, 13)],
  ]) {
    await fixture.writeJson(report(...rows));
    await expect(fixture.prepare()).rejects.toThrow(/repository/);
  }
});

test("projected legacy textual IDs retain their verified occurrence", () => {
  const report = {
    ...scope,
    format: "semgrep-platform-findings/v1",
    findings: [{ ...code, id: "1.2e1" }],
    findingCount: 1,
  };
  const [finding] = normalizeSemgrepFindings(report, {}, "local").findings;
  const data = finding!.evidence.source_data!;
  delete data["format"];
  expect(semgrepPlatformFindingRepository(finding!, "semgrep")).toBe(url);
  data["format"] = "semgrep-platform-findings/v2";
  expect(() => semgrepPlatformFindingRepository(finding!, "semgrep")).toThrow(
    "exact, positive",
  );
});

test("direct historic object-row evidence honors the caller's repository comparator", () => {
  const lower = "https://ghe.example.test/org/service";
  const upper = "https://ghe.example.test/ORG/Service";
  const original = { ...code, id: 12, repository: { url: upper } };
  const report = {
    ...scope,
    format: "semgrep-platform-findings/v1",
    project: { ...scope.project, url: upper },
    sourceRepositoryUrl: lower,
  };
  const [finding] = normalizeSemgrepFindings(
    { ...report, findings: [original], findingCount: 1 },
    {
      sourceRepositoryUrl: lower,
      sourceRepositories: [{ url: lower, platform: "github" }],
    },
    "local",
  ).findings;
  finding!.evidence.source_data = { ...report, finding: original };
  expect(() => semgrepPlatformFindingRepository(finding!, "semgrep")).toThrow(
    /repository/,
  );
  expect(
    semgrepPlatformFindingRepository(
      finding!,
      "semgrep",
      cloudRepositoryUrlKey,
    ),
  ).toBe(upper);
});

test("the retained repository witness stays stable when the API returns rows in another order", () => {
  const name = "display";
  const dependent = { ...code, id: 12, repository: { name } };
  const byId = { ...code, id: 13, repository: { name, id: 10 } };
  const byUrl = { ...code, id: 14, repository: { name, url } };
  const project = (witnesses: (typeof byId | typeof byUrl)[]) =>
    normalizeSemgrepFindings(
      {
        ...scope,
        format: "semgrep-platform-findings/v2",
        findingCount: 3,
        repositoryAliases: [name],
        findings: [dependent, ...witnesses].map((row) => JSON.stringify(row)),
      },
      {},
      "local",
    ).findings[0]!;
  const first = project([byId, byUrl]);
  expect(first.evidence.source_data?.["repositoryWitnessJson"]).toBeDefined();
  expect(project([byUrl, byId])).toEqual(first);
});

test("unmarked legacy native IDs identify a URL-less Semgrep project without claiming generic Wiz records", async () => {
  const options = {
    provider: "wiz" as const,
    sourceKey: "demo/topic",
    repository: url,
  };
  const dependencies = {
    environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
    credentials: async () => {
      throw new Error("Reached Cloud credential lookup");
    },
  };
  const report = (
    id: string | number | null,
    projectUrl: string | null,
    format?: string,
  ) => ({
    read: 1,
    excluded: [],
    findings: [
      {
        source_finding_id: "opaque",
        evidence: {
          title: "Example",
          severity: "low" as const,
          source_data: {
            ...scope,
            ...(format && { format }),
            project: { ...scope.project, id: 10, url: projectUrl },
            finding: { id },
          },
        },
      },
    ],
  });
  await expect(
    prepareNormalizedExternalPublication(
      report("1.2e1", null),
      options,
      dependencies,
    ),
  ).rejects.toThrow("local import");
  await expect(
    prepareNormalizedExternalPublication(
      report(null, null),
      { ...options, provider: "semgrep" },
      dependencies,
    ),
  ).rejects.toThrow("local import");
  await expect(
    prepareNormalizedExternalPublication(
      report(12, url, "normalized/v1"),
      { ...options, provider: "semgrep" },
      dependencies,
    ),
  ).rejects.toThrow("local import");
  const branded = report(12, url, "wiz-findings/v1");
  expect(
    semgrepPlatformFindingRepository(branded.findings[0]!, "wiz"),
  ).toBeUndefined();
  await expect(
    prepareNormalizedExternalPublication(branded, options, dependencies),
  ).rejects.toThrow("Reached Cloud credential lookup");
  const generic = report("WIZ-1", url);
  await expect(
    prepareNormalizedExternalPublication(generic, options, dependencies),
  ).rejects.toThrow("Reached Cloud credential lookup");
});
test("v2 files require exact counts and string project IDs", async () => {
  const dir = await mkdtemp(join(tmpdir(), "semgrep-v2-controls-"));
  const path = join(dir, "report.json");
  const report = (projectId: string, count: string, rows: string[]) =>
    `{"deployment":"demo","project":{"id":${projectId},"name":"example/project","url":"${url}"},"ref":"refs/heads/topic","product":"sast","repositoryAliases":[],"findingCount":${count},"format":"semgrep-platform-findings/v2","metadata":{"findingCount":1},"findings":${JSON.stringify(rows)}}`;
  const rows = [JSON.stringify({ ...code, id: 12 })];
  try {
    await writeFile(path, report('"10"', "1e0", rows));
    expect(
      (await readSemgrepFindings(path, {}, "local")).findings,
    ).toHaveLength(1);
    await writeFile(path, report('"10"', "0", []));
    expect((await readSemgrepFindings(path, {}, "local")).findings).toEqual([]);
    // An escaped format name is still the same Platform document.
    const rounded = report('"10"', "1.00000000000000001", rows);
    for (const json of [
      rounded,
      rounded.replace(
        "semgrep-platform-findings",
        "\\u0073emgrep-platform-findings",
      ),
    ]) {
      await writeFile(path, json);
      await expect(readSemgrepFindings(path, {}, "local")).rejects.toThrow(
        "finding count",
      );
    }
    for (const projectId of ["10", "10.00000000000000001"]) {
      await writeFile(path, report(projectId, "1", rows));
      await expect(readSemgrepFindings(path, {}, "local")).rejects.toThrow(
        /project ID/i,
      );
    }
    const native = semgrepJson();
    Object.assign(native.results[0]!.extra.metadata, {
      nested: { format: "semgrep-platform-findings/v2", number: 42 },
    });
    await writeFile(path, JSON.stringify(native));
    expect(
      await readSemgrepFindings(path, { sourceRepositoryUrl: url }, "local"),
    ).toEqual(
      normalizeSemgrepFindings(native, { sourceRepositoryUrl: url }, "local"),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
