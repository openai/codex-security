import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { semgrepJson } from "./support/semgrep-import-fixtures.js";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { isolatedGitReportFixture as localReportFixture } from "./external-findings-local-helpers.js";
import {
  normalizeSemgrepFindings,
  readSemgrepFindings,
} from "../src/semgrep-findings.js";
import { normalizeSemgrepPlatformFindings } from "../src/semgrep-platform-findings.js";

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

test("the standalone Cloud normalizer verifies the port on reader mappings", () => {
  const projectUrl = "https://scm.example.test:443/Example/Project";
  const report = {
    ...scope,
    format: "semgrep-platform-selection/v1",
    project: { ...scope.project, url: projectUrl },
    findings: [
      JSON.stringify({ ...code, id: 12, repository: { url: projectUrl } }),
    ],
  };
  const mapped = (url: string) => ({
    sourceRepositories: [{ url, platform: "github" as const }],
  });
  const different = mapped(projectUrl.replace(":443", ""));
  expect(() =>
    normalizeSemgrepPlatformFindings(report, different, "cloud"),
  ).toThrow(/reader's source repository/);
  expect(
    normalizeSemgrepPlatformFindings(report, different).findings,
  ).toHaveLength(1);
  expect(
    normalizeSemgrepPlatformFindings(
      report,
      mapped(projectUrl.toLowerCase()),
      "cloud",
    ).findings,
  ).toHaveLength(1);
});

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
  const weak = read(
    "semgrep-platform-findings/v2",
    rows.map((row) => JSON.stringify({ ...row, ref: undefined })),
  );
  expect(weak.excluded).toEqual([]);
  expect(weak.findings[0]!.evidence.severity).toBe("unknown");
  expect(weak.findings[1]!.evidence.locations?.[0]?.line).toBe(2);
  expect(weak.findings[2]!.evidence.details!.code!.end_line).toBe(3);
});

test("a GitHub mapping reprojects generated severity when a backlog finding becomes selectable", async () => {
  const url = "https://git.example.test/Team/Repo";
  const native = {
    ...code,
    id: 12,
    repository: { id: 10, name: "team/repo" },
    severity: "informational",
  };
  const rows = [
    native,
    { ...native, id: 13, location: { file_path: "src/service.ts", line: "3" } },
    {
      ...native,
      id: 14,
      location: { file_path: "src/service.ts", line: 3, end_line: "5" },
    },
  ];
  const report = {
    ...scope,
    project: { ...scope.project, name: "Project", url },
    format: "semgrep-platform-findings/v2",
    repositoryAliases: [native.repository.name],
    findingCount: rows.length,
    findings: rows.map((row) => JSON.stringify(row)),
  };
  const batch = normalizeSemgrepFindings(report, {}, "local");
  expect(batch.findings[0]!.evidence).toMatchObject({
    severity: "informational",
    source_data: { format: report.format },
  });
  const source = { provider: "semgrep" as const, sourceKey: "demo/topic" };
  await using fixture = await localReportFixture("semgrep.json", source, {
    remote: url,
  });
  const options = { ...source, repository: fixture.repository };
  const dependencies = {
    environment: fixture.environment,
    sourceRepositories: [{ url, platform: "github" as const }],
  };
  await fixture.writeJson(report);
  const file = await prepareLocalExternalImport(
    fixture.file,
    options,
    dependencies,
  );
  const direct = () =>
    prepareNormalizedLocalImport(batch, options, dependencies);
  expect(file.preview.findings[0]!.evidence).toMatchObject({
    severity: "unknown",
    source_data: { format: "semgrep-platform-selection/v1" },
  });
  for (const row of file.preview.findings.slice(1)) {
    expect(row.evidence).toMatchObject({
      severity: "informational",
      locations: [{ path: "src/service.ts", line: 3 }],
      source_data: { format: report.format },
    });
  }
  expect(file.preview.excluded).toEqual([]);
  expect((await file.import()).counts.created).toBe(rows.length);
  expect((await (await direct()).import()).counts.unchanged).toBe(rows.length);
  expect((await file.import()).counts.unchanged).toBe(rows.length);
  expect((await fixture.read()).map((row) => row.version)).toEqual([1, 1, 1]);
  batch.findings[0]!.evidence.severity = "high";
  expect((await direct()).preview.findings[0]!.evidence.severity).toBe("high");
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
    const prepare = () => fixture.prepareNormalized(result);
    const unchanged = { created: 0, updated: 0, unchanged: 1 };
    data["semgrepPlatformFindingJson"] = equivalent;
    expect((await (await prepare()).import()).counts).toEqual(unchanged);
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

test("retired object-row exports cannot be saved as current Platform findings", () => {
  expect(() =>
    normalizeSemgrepFindings(
      {
        ...scope,
        format: "semgrep-platform-findings/v1",
        findingCount: 1,
        findings: [{ ...code, id: 12 }],
      },
      {},
      "local",
    ),
  ).toThrow(/recollect/i);
});
