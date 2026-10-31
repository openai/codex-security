import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { semgrepJson } from "./support/semgrep-import-fixtures.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { prepareNormalizedExternalPublication } from "../src/external-findings-publish.js";
import { bundledPluginRoot, runWorkbench } from "../src/runtime.js";
import {
  cloudRepositoryUrlKey,
  validateExternalEvidence,
} from "../src/external-import-contract.js";
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

test("strongly bound current SAST rows have identical selection and backlog exclusions", () => {
  const location = { file_path: "src/service.ts", line: 2, end_line: 3 };
  const rows = [
    { ...code, id: 11, severity: "unrecognized" },
    { ...code, id: 12, location: { ...location, line: "2" } },
    { ...code, id: 13, location: { ...location, end_line: "3" } },
  ];
  const read = (format: string, findings: unknown[]) =>
    normalizeSemgrepFindings(
      {
        ...scope,
        format,
        findingCount: findings.length,
        findings,
        repositoryAliases: [],
      },
      {},
      "local",
    );
  const json = rows.map((row) => JSON.stringify(row));
  const selection = read("semgrep-platform-selection/v1", json);
  const backlog = read("semgrep-platform-findings/v2", json);
  expect(selection.excluded.map((row) => row.position)).toEqual([2, 3]);
  expect(backlog.excluded).toEqual(selection.excluded);
  expect(backlog.findings).toEqual(selection.findings);
  expect(selection.findings).toHaveLength(1);
  const evidence = selection.findings[0]!.evidence;
  expect(evidence.severity).toBe("unknown");
  expect(
    JSON.parse(String(evidence.source_data?.["semgrepPlatformFindingJson"]))
      .severity,
  ).toBe("unrecognized");
  const legacy = read("semgrep-platform-findings/v1", rows);
  expect(legacy.excluded.map((row) => row.position)).toEqual([2, 3]);
  expect(legacy.findings[0]!.evidence.severity).toBe("unknown");
  const weak = read(
    "semgrep-platform-findings/v2",
    rows.map((row) => JSON.stringify({ ...row, ref: undefined })),
  );
  expect(weak.excluded).toEqual([]);
  expect(weak.findings[0]!.evidence.severity).toBe("unknown");
  expect(weak.findings[1]!.evidence.locations?.[0]?.line).toBe(2);
  expect(weak.findings[2]!.evidence.details!.code!.end_line).toBe(3);
});

test.each(["sca", "weak SAST", "selected SAST"])(
  "%s file and normalized SDK replays retain equivalent native number values once",
  async (kind) => {
    const strong = kind === "selected SAST";
    const product = kind === "sca" ? "sca" : "sast";
    const id = strong ? "12" : "1.2e1";
    const repository = strong ? JSON.stringify({ id: 10, url }) : '{"id":1e1}';
    const ref = strong ? `,"ref":${JSON.stringify(scope.ref)}` : "";
    const rule = product === "sast" ? ',"rule_name":"example.rule"' : "";
    const native = `{"id":${id}${rule},"repository":${repository},"metadata":{"source":"demo","score":10.0}${ref}}`;
    const replayRepository = strong ? repository : '{"id":10.0}';
    const equivalent = `{"metadata":{"score":1e1,"source":"demo"},"repository":${replayRepository},"id":12${rule}${ref}}`;
    const report = (row: string) => ({
      ...scope,
      format: "semgrep-platform-findings/v2",
      product,
      repositoryAliases: [],
      findingCount: 1,
      findings: [row],
    });
    const source = { provider: "semgrep" as const, sourceKey: "demo/topic" };
    await using fixture = await localReportFixture("semgrep.json", source, {
      remote: url,
    });
    await fixture.writeJson(report(native));
    const initial = await fixture.prepare();
    expect((await initial.import()).counts.created).toBe(1);
    const result = normalizeSemgrepFindings(report(native), {}, "local");
    const data = result.findings[0]!.evidence.source_data!;
    const prepare = () =>
      prepareNormalizedLocalImport(
        result,
        { ...source, repository: fixture.repository },
        { environment: fixture.environment },
      );
    const unchanged = { created: 0, updated: 0, unchanged: 1 };
    data["semgrepPlatformFindingJson"] = equivalent;
    for (const format of strong
      ? [data["format"], undefined, "another-format"]
      : [data["format"]]) {
      if (format === undefined) delete data["format"];
      else data["format"] = format;
      expect((await (await prepare()).import()).counts).toEqual(unchanged);
    }
    await fixture.writeJson(report(equivalent));
    expect((await (await fixture.prepare()).import()).counts).toEqual(
      unchanged,
    );
    const [stored] = await fixture.read();
    expect(stored?.version).toBe(1);
    if (!strong) {
      const raw = stored!.evidence.source_data!["semgrepPlatformFindingJson"];
      expect(raw).toContain('"id":12,');
      expect(raw).toContain('"repository":{"id":10}');
    }

    data["callerAnnotation"] = { group: "demo" };
    expect((await (await prepare()).import()).counts.updated).toBe(1);
    expect((await (await prepare()).import()).counts).toEqual(unchanged);
    expect(
      (await fixture.read())[0]?.evidence.source_data?.["callerAnnotation"],
    ).toEqual({ group: "demo" });
  },
);

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
      if (product === "sast") {
        expect(current.findings).toEqual([]);
        expect(current.excluded).toEqual(legacy.excluded);
      } else {
        expect(current.findings[0]?.evidence.title).toBe("Semgrep finding 11");
      }
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

test("legacy SSH repository projections replay unchanged alongside file imports", async () => {
  const original = {
    ...scope,
    format: "semgrep-platform-findings/v1",
    project: { ...scope.project, url: "git@github.com:example/project.git" },
    sourceRepositoryUrl: url,
  };
  const row = {
    ...code,
    id: 12,
    location: { file_path: "src\\service.ts", line: 2, end_line: 4 },
  };
  const source = { provider: "semgrep" as const, sourceKey: "demo/topic" };
  await using fixture = await localReportFixture("v1.json", source, {
    remote: url,
  });
  await fixture.writeJson({ ...original, findings: [row], findingCount: 1 });
  const file = await fixture.prepare();
  expect((await file.import()).counts.created).toBe(1);
  const batch = structuredClone(file.preview);
  const evidence = batch.findings[0]!.evidence;
  evidence.source_data = { ...original, finding: row };
  evidence.details!.repository!.url = url;
  evidence.locations = [];
  evidence.details!.code!.end_line = null;
  const prepare = () =>
    prepareNormalizedLocalImport(
      batch,
      { ...source, repository: fixture.repository },
      { environment: fixture.environment },
    );
  const direct = await prepare();
  expect(direct.preview.findings[0]!.evidence.details).toMatchObject({
    code: { end_line: 4 },
    repository: { url: url + ".git" },
  });
  expect((await direct.import()).counts.unchanged).toBe(1);
  expect((await (await fixture.prepare()).import()).counts.unchanged).toBe(1);

  const override = "https://github.com/Example/Project";
  evidence.details!.repository!.url = override;
  expect(
    (await prepare()).preview.findings[0]!.evidence.details?.repository?.url,
  ).toBe(override);
  evidence.details!.repository!.url = "https://github.com/example/other";
  await expect(prepare()).rejects.toThrow(/repository and ref/);
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
      findings: [{ ...code, id: "1.2e1", repository: { url, id: "1e1" } }],
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
  const raw =
    historical.findings[0]!.evidence.source_data?.[
      "semgrepPlatformFindingJson"
    ];
  expect(raw).toContain('"id":"1.2e1"');
  expect(raw).toContain('"id":"1e1"');
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
  const currentWitness = structuredClone(
    batch.findings[1]!.evidence.source_data!,
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
  const retained = {
    ...legacy,
    finding: native[0],
    sourceRepositoryUrl: url,
    operatorNote: "reviewed",
    repositoryWitnessJson: "stale",
    idEncoding: "stale",
    project: {
      ...scope.project,
      url: null,
      labels: { group: "demo", sequence: 1 },
    },
  };
  batch.findings[0]!.evidence.source_data = retained;
  batch.findings[0]!.evidence.title = "Title chosen by the caller";
  const first = await prepare(batch);
  const preparedData = first.preview.findings[0]!.evidence.source_data!;
  expect(preparedData["repositoryWitnessJson"]).toBe(
    JSON.stringify({ id: scope.project.id, name: label }),
  );
  expect(preparedData).not.toHaveProperty("idEncoding");
  expect((await first.import()).counts).toEqual({
    created: 2,
    updated: 0,
    unchanged: 0,
  });
  // A partially migrated batch retains the same independent repository proof.
  batch.findings[1]!.evidence.source_data = currentWitness;
  expect((await (await prepare(batch)).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 2,
  });
  expect(
    (await fixture.read()).find((row) => row.sourceFindingId === "retained-0"),
  ).toMatchObject({
    version: 1,
    evidence: {
      title: "Title chosen by the caller",
      source_data: {
        operatorNote: "reviewed",
        sourceRepositoryUrl: url,
        project: { url: null, labels: { group: "demo", sequence: 1 } },
      },
    },
  });
  expect(batch.findings[0]!.evidence.source_data?.["finding"]).toEqual(
    native[0],
  );

  retained.project.labels.sequence++;
  expect((await (await prepare(batch)).import()).counts).toEqual({
    created: 0,
    updated: 1,
    unchanged: 1,
  });
  expect((await (await prepare(batch)).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 2,
  });
  expect(
    (await fixture.read()).find((row) => row.sourceFindingId === "retained-0"),
  ).toMatchObject({
    version: 2,
    evidence: {
      source_data: { project: { labels: { group: "demo", sequence: 2 } } },
    },
  });

  for (const other of [
    { ...scope, deployment: "other" },
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

test("a stored decimal witness remains equivalent to its canonical binding on local replay", async () => {
  const source = { provider: "semgrep" as const, sourceKey: "demo/topic" };
  await using fixture = await localReportFixture("semgrep.json", source, {
    remote: url,
  });
  await fixture.writeJson({
    ...scope,
    format: "semgrep-platform-findings/v1",
    repositoryAliases: ["display"],
    findingCount: 2,
    findings: [
      { ...code, id: 12, repository: { name: "display", id: "1e1" } },
      { ...code, id: 13, repository: { name: "display" } },
    ],
  });
  const saved = await fixture.prepare();
  expect((await saved.import()).counts.created).toBe(2);
  const result = saved.preview;
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

  const previous = structuredClone(dependent!);
  Object.assign(previous.evidence.source_data!, {
    format: "semgrep-platform-findings/v1",
    idEncoding: "v1-decimal",
    repositoryWitnessJson: JSON.stringify({ name: "display", id: "1e1" }),
  });
  expect(semgrepPlatformFindingRepository(previous, "semgrep")).toBe(url);
  const direct = await prepareNormalizedLocalImport(
    { read: 1, findings: [previous], excluded: [] },
    { ...source, repository: fixture.repository },
    { environment: fixture.environment },
  );
  expect((await direct.import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 1,
  });
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 2,
  });
  expect(
    (await fixture.read()).find(
      (row) => row.sourceFindingId === previous.source_finding_id,
    )?.version,
  ).toBe(1);
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

test("early v1 repository labels retain decodeURI spellings without trusting unrelated labels", () => {
  const archive = {
    ...scope,
    format: "semgrep-platform-findings/v1",
    project: {
      ...scope.project,
      name: "logical",
      url: "https://scm.example.test/group/R%C3%A9po%2B",
    },
    findingCount: 1,
  };
  const name = "group/Répo%2B";
  const row = { ...code, id: 12, repository: { name } };
  const source = { ...archive, findings: [row] };
  const [finding] = normalizeSemgrepFindings(source, {}, "local").findings;
  expect(semgrepPlatformFindingRepository(finding!, "semgrep")).toBe(
    archive.project.url,
  );
  finding!.evidence.source_data = { ...archive, finding: row };
  expect(semgrepPlatformFindingRepository(finding!, "semgrep")).toBe(
    archive.project.url,
  );
  for (const invalid of [
    {
      ...source,
      findings: [{ ...row, repository: { name: "group/Other%2B" } }],
    },
    { ...source, findings: [{ ...row, repository: { name, id: 11 } }] },
    {
      ...source,
      findings: [
        {
          ...row,
          repository: { name, url: "https://scm.example.test/other/repo" },
        },
      ],
    },
    {
      ...source,
      format: "semgrep-platform-findings/v2",
      findings: [JSON.stringify(row)],
      repositoryAliases: [name],
    },
  ]) {
    expect(() => normalizeSemgrepFindings(invalid, {}, "local")).toThrow(
      /repository/,
    );
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

test("the chosen provider distinguishes unmarked v1 scopes from generic Wiz evidence", async () => {
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
      { ...options, provider: "semgrep" },
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
  const original = report(12, null, "semgrep-platform-findings/v1");
  await expect(
    prepareNormalizedExternalPublication(original, options, dependencies),
  ).rejects.toThrow("local import");
  const unmarked = report(12, null);
  await expect(
    prepareNormalizedExternalPublication(unmarked, options, dependencies),
  ).rejects.toThrow("Reached Cloud credential lookup");
  unmarked.findings[0]!.source_finding_id =
    "semgrep-platform:" + "1".repeat(64);
  await expect(
    prepareNormalizedExternalPublication(unmarked, options, dependencies),
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

const historicalPaths = [
  ["src\\service.ts", null, "src/service.ts", false],
  ["src\\backlog.ts", null, "src/backlog.ts", true],
  ["pkg:service.ts", "pkg:service.ts", null, false],
  ["src/", "src/", null, false],
] as const;

test.each(historicalPaths)(
  "migrates persisted Semgrep location %s once across historical and current replays",
  verifyLegacyLocationReplay,
);

async function verifyLegacyLocationReplay(
  path: string,
  oldPath: string | null,
  newPath: string | null,
  backlogOnly: boolean,
) {
  const locations = (path: string | null) => (path ? [{ path, line: 3 }] : []);

  const source = { provider: "semgrep" as const, sourceKey: "demo/topic" };
  await using fixture = await localReportFixture("semgrep.json", source, {
    remote: url,
  });
  const row = {
    repository: code.repository,
    rule: code.rule,
    ...(backlogOnly ? {} : { ref: scope.ref }),
    id: 12,
    severity: "HIGH",
    location: {
      file_path: path,
      line: backlogOnly ? "3" : 3,
      end_line: backlogOnly ? "5" : 5,
    },
  };
  const legacy = {
    ...scope,
    project: { ...scope.project, id: 10 },
    format: "semgrep-platform-findings/v1",
    findingCount: 1,
    findings: [row],
  };
  // The original object-row reader hashed numeric IDs, mapped HIGH to unknown, and used its hosted path rules.
  const id =
    "semgrep-platform:a7db3d7539422c25f776693a34ab2f916e31cc218f407c8c7faa7f209cad7ba3";
  const original = {
    source_finding_id: id,
    evidence: validateExternalEvidence(
      {
        title: code.rule.name,
        severity: "unknown",
        branch: scope.ref,
        locations: locations(oldPath),
        details: {
          kind: "sast",
          scanner_origin: "Semgrep",
          repository: { url },
          rule: { id: code.rule.name },
          code: { end_line: oldPath ? 5 : null },
        },
        source_data: {
          format: legacy.format,
          deployment: scope.deployment,
          project: legacy.project,
          ref: scope.ref,
          product: scope.product,
          finding: row,
        },
      },
      "local",
    ),
  };
  await runWorkbench(
    {
      pluginRoot: await bundledPluginRoot(),
      environment: fixture.environment,
      stateDirectory: fixture.stateDirectory,
    },
    ["store-external-findings"],
    JSON.stringify({
      ...source,
      repository: fixture.repository,
      findings: [original],
    }),
  );
  const [historical] = await fixture.read();
  expect(historical).toMatchObject({
    sourceFindingId: id,
    version: 1,
    evidence: { severity: "unknown", locations: locations(oldPath) },
  });
  const direct = (finding = original) =>
    prepareNormalizedLocalImport(
      { read: 1, excluded: [], findings: [finding] },
      { ...source, repository: fixture.repository },
      { environment: fixture.environment },
    );
  const next = await direct();
  expect((await next.import()).counts).toEqual({
    created: 0,
    updated: 1,
    unchanged: 0,
  });
  const [stored] = await fixture.read();
  expect(stored).toMatchObject({
    id: historical!.id,
    sourceFindingId: id,
    version: 2,
    evidence: {
      severity: "high",
      locations: locations(newPath),
      details: { code: { end_line: newPath ? 5 : null } },
    },
  });
  const raw = stored!.evidence.source_data!["semgrepPlatformFindingJson"];
  expect(JSON.parse(String(raw)).location).toEqual(row.location);
  const modern = {
    ...scope,
    repositoryAliases: [],
    findingCount: 1,
    findings: [JSON.stringify(row)],
    format: "semgrep-platform-findings/v2",
  };
  const selected = { ...modern, format: "semgrep-platform-selection/v1" };
  if (backlogOnly)
    expect(() => normalizeSemgrepFindings(selected, {}, "local")).toThrow(
      /ref/u,
    );
  const unchanged = { created: 0, updated: 0, unchanged: 1 };
  for (const report of [
    legacy,
    modern,
    ...(backlogOnly ? [] : [selected]),
    legacy,
  ]) {
    await fixture.writeJson(report);
    const file = await fixture.prepare();
    expect((await file.import()).counts).toEqual(unchanged);
    if (backlogOnly && report === modern)
      expect(
        (await (await direct(file.preview.findings[0]!)).import()).counts,
      ).toEqual(unchanged);
    expect((await (await direct()).import()).counts).toEqual(unchanged);
  }
  expect(await fixture.read()).toEqual([stored!]);
  if (oldPath) {
    const extended = structuredClone(original);
    extended.evidence.locations!.push({ path: "another.ts", line: 7 });
    expect(
      (await direct(extended)).preview.findings[0]!.evidence.locations,
    ).toEqual(extended.evidence.locations);
  }
  const custom = structuredClone(original);
  custom.evidence.severity = "low";
  custom.evidence.locations = [{ path: "manual.ts", line: 7 }];
  custom.evidence.details!.code!.end_line = 9;
  const manual = (await direct(custom)).preview.findings[0]!.evidence;
  expect(manual).toMatchObject({
    severity: "low",
    locations: custom.evidence.locations,
    details: { code: { end_line: 9 } },
  });
  await fixture.writeJson({
    ...modern,
    findings: [JSON.stringify({ ...row, severity: "CRITICAL" })],
  });
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 1,
    unchanged: 0,
  });
  expect((await (await fixture.prepare()).import()).counts).toEqual(unchanged);
  expect(await fixture.read()).toMatchObject([
    {
      id: historical!.id,
      sourceFindingId: id,
      version: 3,
      evidence: { severity: "critical" },
    },
  ]);
}
