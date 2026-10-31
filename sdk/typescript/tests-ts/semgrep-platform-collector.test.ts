import { expect, mock, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { parse as parseYaml } from "yaml";
import { collectSemgrepPlatformFindings } from "../src/semgrep-platform-collector.js";
import { main } from "../src/cli.js";
import {
  isSemgrepPlatformEvidence,
  normalizeSelectedSemgrepPlatformFindings,
  normalizeSemgrepPlatformFindings,
  selectSemgrepPlatformFindings,
  semgrepPlatformFindingBinding,
  semgrepPlatformFindingRepository,
} from "../src/semgrep-platform-findings.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { hostedRepositoryUrlKey } from "../src/hosted-git-repository.js";
import { normalizeSemgrepFindings } from "../src/semgrep-findings.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { semgrepSarif } from "./support/semgrep-import-fixtures.js";
import { isolatedGitReportFixture as localReportFixture } from "./external-findings-local-helpers.js";

const url = "https://github.com/example/service";
const project = { name: "example/service", id: 77, url };
const options = {
  project: project.name,
  deployment: "example",
  ref: "refs/heads/topic",
};
const environment = {
  CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
  SEMGREP_APP_TOKEN: "synthetic",
};
const fullPage = Array.from({ length: 3000 }, (_, index) => ({
  id: index + 1,
}));

/** Serve a project lookup followed by consecutive findings responses. */
function responses(...pages: Response[]) {
  const pending = [Response.json({ project }), ...pages];
  return {
    environment,
    fetch: async () => {
      const next = pending.shift();
      if (!next) throw new Error("Unexpected additional request");
      return next;
    },
  };
}

test("the hosted collector preserves encoded query and fragment characters in a Git path", async () => {
  const native = {
    ...project,
    url: "https://git.example.test/team/tool%3Fone%23two",
  };
  const report = await collectSemgrepPlatformFindings(options, {
    environment,
    fetch: async (endpoint) =>
      Response.json(
        endpoint.pathname.endsWith("/findings")
          ? { findings: [] }
          : { project: native },
      ),
  });
  expect(report.project.url).toBe(native.url);
  expect(() =>
    selectSemgrepPlatformFindings({
      ...options,
      projectResponse: JSON.stringify({ project: native }),
      findingsResponses: [],
      findingIds: ["23"],
    }),
  ).toThrow(/repository path/);
});

test("a supplied empty repository URL remains bulk-only on capture and replay", async () => {
  const row = {
    id: 12,
    ref: options.ref,
    rule_name: "demo",
    repository: { ...project, url: "" },
  };
  const page = { findings: [row] };
  const selection = {
    ...options,
    sourceRepositoryUrl: url,
    projectResponse: JSON.stringify({ project }),
    findingsResponses: [JSON.stringify(page)],
    findingIds: ["12"],
  };
  expect(() => selectSemgrepPlatformFindings(selection)).toThrow(/repository/);
  expect(() => normalizeSelectedSemgrepPlatformFindings(selection)).toThrow(
    /repository/,
  );
  const bulk = await collectSemgrepPlatformFindings(
    options,
    responses(Response.json(page)),
  );
  expect(() =>
    normalizeSemgrepPlatformFindings({
      ...bulk,
      format: "semgrep-platform-selection/v1",
    }),
  ).toThrow(/repository/);
  for (const input of [
    bulk,
    { ...bulk, format: "semgrep-platform-findings/v1", findings: [row] },
  ]) {
    const [finding] = normalizeSemgrepPlatformFindings(input).findings;
    expect(finding!.evidence.source_data?.["format"]).toBe(bulk.format);
    expect(semgrepPlatformFindingRepository(finding!, "semgrep")).toBe(url);
  }
});

test("an opaque bulk finding ID still requires the original native occurrence ID", async () => {
  const report = await collectSemgrepPlatformFindings(
    options,
    responses(
      Response.json({ findings: [{ id: 9, rule_name: "example.rule" }] }),
    ),
  );
  const row = normalizeSemgrepFindings(report, {}, "local").findings[0]!;
  row.source_finding_id = "assigned-id";
  expect(semgrepPlatformFindingRepository(row, "semgrep")).toBe(url);
  row.evidence.source_data!["semgrepPlatformFindingJson"] = "{}";
  expect(() => semgrepPlatformFindingRepository(row, "semgrep")).toThrow(
    /exact, positive Semgrep Platform ID/,
  );
});

test("integer-valued native IDs replay identically through selected and bulk imports", async () => {
  const page = `{"findings":[{"id":1e1,"repository":{"id":77.0,"url":"${url}"},"ref":"${options.ref}","rule_name":"example.rule"}]}`;
  const input = {
    ...options,
    projectResponse: JSON.stringify({ project }),
    findingsResponses: [page],
    findingIds: ["10"],
    sourceRepositoryUrl: url,
  };
  const direct = normalizeSelectedSemgrepPlatformFindings(input);
  expect(direct.excluded).toEqual([]);
  expect(direct.findings).toHaveLength(1);
  const finding = direct.findings[0]!;
  expect(finding.evidence.source_data).toMatchObject({
    format: "semgrep-platform-selection/v1",
    semgrepPlatformFindingJson: JSON.stringify({
      id: 10,
      ref: options.ref,
      repository: { id: 77, url },
      rule_name: "example.rule",
    }),
  });
  const selected = selectSemgrepPlatformFindings(input);
  const bulk = await collectSemgrepPlatformFindings(
    options,
    responses(new Response(page)),
  );
  for (const saved of [selected, bulk]) {
    const replay = normalizeSemgrepFindings(saved, {}, "local");
    expect(replay.excluded).toEqual([]);
    expect(replay.findings).toEqual(direct.findings);
  }
  expect(semgrepPlatformFindingRepository(finding, "semgrep")).toBe(url);
});

test("a retagged Semgrep row still requires its provider after assigning an opaque ID", async () => {
  const report = await collectSemgrepPlatformFindings(
    options,
    responses(
      Response.json({
        findings: [
          {
            id: 9,
            ref: options.ref,
            repository: project,
            rule_name: "example.rule",
          },
        ],
      }),
    ),
  );
  const normalized = normalizeSemgrepFindings(report, {}, "local");
  const row = normalized.findings[0]!;
  row.source_finding_id = "assigned-id";
  row.evidence.source_data!["format"] = "snyk-rest-issues/v2";
  const source = { provider: "wiz" as const, sourceKey: "example/topic" };
  await using fixture = await localReportFixture("findings.json", source, {
    remote: url,
  });
  await expect(fixture.prepareNormalized(normalized)).rejects.toThrow(
    /semgrep provider/i,
  );

  row.evidence.source_data = {
    format: "snyk-rest-issues/v2",
    projectJson: "{}",
    targetJson: "{}",
    issueJson: '{"id":"native-issue","type":"issue"}',
  };
  expect(isSemgrepPlatformEvidence(row, "snyk")).toBe(false);
});

test("a normalized Platform report binds native rows even when both projects have checkout remotes", async () => {
  const report = await collectSemgrepPlatformFindings(
    options,
    responses(
      Response.json({ findings: [{ id: 9, rule_name: "example.rule" }] }),
    ),
  );
  const upstream = "https://git.example.test/service/upstream";
  const fork = "https://git.example.test/service/fork";
  const normalize = (
    url: string,
    id: string,
    scope: Partial<Pick<typeof report, "deployment" | "product" | "ref">> = {},
  ) =>
    normalizeSemgrepPlatformFindings({
      ...report,
      ...scope,
      project: { ...report.project, id, url },
    });
  const upstreamReport = normalize(upstream, "77");
  const forkReport = normalize(fork, "88");
  const source = { provider: "semgrep" as const, sourceKey: "example/topic" };
  await using fixture = await localReportFixture("findings.json", source, {
    remote: upstream,
  });
  execFileSync(
    "git",
    ["-C", fixture.repository, "remote", "add", "fork", fork],
    {
      env: fixture.environment,
    },
  );
  const prepare = fixture.prepareNormalized;
  await expect(
    prepare({ ...upstreamReport, findings: forkReport.findings }),
  ).rejects.toThrow(/report repository/i);
  for (const foreign of [
    normalize(upstream, "88"),
    normalize(upstream, "77", { deployment: "other" }),
    normalize(upstream, "77", { ref: "refs/heads/other" }),
    normalize(upstream, "77", { product: "ai_sast" }),
  ]) {
    await expect(
      prepare({
        ...upstreamReport,
        read: 2,
        findings: [...upstreamReport.findings, ...foreign.findings],
      }),
    ).rejects.toThrow(/scope|project|deployment|product|ref/i);
  }

  const incomplete = { ...upstreamReport, sourceFormat: undefined };
  await expect(prepare(incomplete)).rejects.toThrow(/scope.*source format/i);

  const ordinary = structuredClone(upstreamReport.findings[0]!);
  ordinary.source_finding_id = "ordinary";
  delete ordinary.evidence.source_data;
  ordinary.evidence.branch = "topic";
  expect(
    (
      await prepare({
        ...upstreamReport,
        read: 2,
        findings: [...upstreamReport.findings, ordinary],
      })
    ).preview.findings,
  ).toHaveLength(2);
  for (const claim of [{ url: fork }, { branch: "refs/heads/other" }]) {
    const projected = structuredClone(ordinary);
    if (claim.url) projected.evidence.details!.repository!.url = claim.url;
    if (claim.branch) projected.evidence.branch = claim.branch;
    const mixed = {
      read: 2,
      excluded: [],
      findings: [...upstreamReport.findings, projected],
    };
    expect((await prepare(mixed)).preview.findings).toHaveLength(2);
    await expect(prepare({ ...upstreamReport, ...mixed })).rejects.toThrow(
      /repository|scope|branch|ref/i,
    );
  }
  const duck = structuredClone(ordinary);
  duck.source_finding_id = `blackduck-bom:${"a".repeat(64)}`;
  duck.evidence.source_data = { sourceRepositoryUrl: fork };
  const nativeSarif = semgrepSarif();
  Object.assign(nativeSarif.runs[0]!, {
    versionControlProvenance: [{ repositoryUri: fork }],
  });
  const sarif = normalizeSemgrepFindings(
    nativeSarif,
    { sourceRepositoryUrl: fork },
    "local",
  ).findings[0]!;
  for (const projected of [duck, sarif]) {
    delete projected.evidence.details;
    await expect(
      prepare({ ...upstreamReport, findings: [projected] }),
    ).rejects.toThrow(/report repository/i);
  }
  const batch = {
    read: 2,
    excluded: [],
    findings: [...upstreamReport.findings, ...forkReport.findings],
  };
  expect((await prepare(batch)).preview.findings).toHaveLength(2);
});

test("a v1 normalized report binds its object rows and empty results to the declared checkout", async () => {
  const source = { provider: "semgrep" as const, sourceKey: "example/topic" };
  await using fixture = await localReportFixture("v1.json", source, {
    remote: url,
  });
  const prepare = (
    input: Parameters<typeof prepareNormalizedLocalImport>[0],
    provider: "semgrep" | "wiz" = "semgrep",
  ) =>
    prepareNormalizedLocalImport(
      input,
      { ...source, provider, repository: fixture.repository },
      { environment: fixture.environment },
    );

  const native = { id: 9, rule_name: "example.rule" };
  const scope = {
    deployment: options.deployment,
    ref: options.ref,
    project,
    product: "sast",
    format: "semgrep-platform-findings/v1",
  };
  const projected = normalizeSemgrepPlatformFindings({
    ...scope,
    findingCount: 1,
    findings: [native],
  }).findings[0]!;
  projected.evidence.source_data = { ...scope, finding: native };
  // This is the envelope returned by the v1 reader, including when it accepted no rows.
  const legacy = {
    sourceRepositoryUrl: url,
    read: 1,
    findings: [projected],
    excluded: [],
  };
  const other = "https://github.com/example/fork";
  expect((await prepare(legacy)).preview.findings).toHaveLength(1);
  const rowOnly = { ...legacy, sourceRepositoryUrl: undefined };
  expect((await prepare(rowOnly)).preview.findings).toHaveLength(1);
  for (const findings of [[projected], []]) {
    const wrong = {
      ...legacy,
      read: findings.length,
      findings,
      sourceRepositoryUrl: other,
    };
    await expect(prepare(wrong)).rejects.toThrow(/repository|remote/i);
  }
  const ordinary = structuredClone(projected);
  ordinary.source_finding_id = "generic";
  delete ordinary.evidence.source_data;
  const foreign = structuredClone(ordinary);
  foreign.evidence.details!.repository!.url = other;
  await expect(
    prepare({ ...legacy, read: 2, findings: [projected, foreign] }),
  ).rejects.toThrow(/report repository/i);
  expect(
    (await prepare({ ...legacy, findings: [ordinary] }, "wiz")).preview
      .findings,
  ).toHaveLength(1);
  const sarif = normalizeSemgrepFindings(
    semgrepSarif(),
    { sourceRepositoryUrl: url },
    "local",
  );
  expect(
    (await prepare({ ...legacy, ...sarif })).preview.findings,
  ).toHaveLength(1);
});

test("hosted repository comparison accepts an opaque Git remote alias", () => {
  expect(hostedRepositoryUrlKey("invalid alias")).toBe("invalid alias");
});

test("file and normalized Platform reports keep their Git binding with no accepted findings", async () => {
  const source = { provider: "semgrep" as const, sourceKey: "example/topic" };
  await using fixture = await localReportFixture("semgrep.json", source, {
    remote: "ssh://git@altssh.gitlab.com:443/example/service.git",
  });
  const prepare = fixture.prepareNormalized;
  for (const [findings, ready, excluded] of [
    [['{"id":42,"rule_name":"example.rule"}'], 1, 0],
    [['{"id":null}'], 0, 1],
    [[], 0, 0],
  ] as const) {
    const report = {
      ...options,
      format: "semgrep-platform-findings/v2",
      project: {
        ...project,
        id: String(project.id),
        url: "https://gitlab.com/example/service",
      },
      product: "sast",
      repositoryAliases: [],
      findingCount: findings.length,
      findings,
    };
    await fixture.writeJson(report);
    const { preview } = await fixture.prepare({
      sourceRepositoryUrl: "https://gitlab.com:443/example/service",
    });
    expect(preview.findings).toHaveLength(ready);
    expect(preview.excluded).toHaveLength(excluded);
    if (ready) continue;

    const native = normalizeSemgrepPlatformFindings(report);
    expect(native).toMatchObject({
      semgrepPlatformScope: {
        deployment: report.deployment,
        projectId: report.project.id,
        product: report.product,
        ref: report.ref,
      },
    });
    const replay = await prepare(JSON.parse(JSON.stringify(native)));
    expect(replay.preview.excluded).toHaveLength(excluded);
    expect((await replay.import()).counts).toEqual({
      created: 0,
      updated: 0,
      unchanged: 0,
    });

    const other = {
      ...report,
      project: { ...report.project, url: "https://gitlab.com/example/other" },
    };
    await fixture.writeJson(other);
    await expect(fixture.prepare()).rejects.toThrow("configured remote");
    await expect(
      prepare(structuredClone(normalizeSemgrepPlatformFindings(other))),
    ).rejects.toThrow("configured remote");
  }
});

test("walks the selected project and ref, then rechecks page zero for offset drift", async () => {
  const pages: string[] = [];
  const report = await collectSemgrepPlatformFindings(options, {
    environment,
    fetch: async (endpoint, init) => {
      expect(endpoint.origin).toBe("https://semgrep.dev");
      expect(init.redirect).toBe("error");
      expect(new Headers(init.headers).get("authorization")).toBe(
        "Bearer synthetic",
      );
      if (
        endpoint.pathname ===
        "/api/v1/deployments/example/projects/example%2Fservice"
      )
        return Response.json({ project });
      expect(endpoint.pathname).toBe("/api/v1/deployments/example/findings");
      const page = endpoint.searchParams.get("page")!;
      expect(Object.fromEntries(endpoint.searchParams)).toEqual({
        page,
        page_size: "3000",
        ref: options.ref,
        issue_type: "sast",
        repository_ids: "77",
        dedup: "false",
      });
      pages.push(page);
      return Response.json({
        findings: page === "1" ? [{ id: 3001 }] : fullPage,
      });
    },
  });
  expect(pages).toEqual(["0", "1", "0"]);
  expect(report.findingCount).toBe(3001);
  expect(JSON.parse(report.findings[3000]!)).toEqual({ id: 3001 });

  await expect(
    collectSemgrepPlatformFindings(
      options,
      responses(
        Response.json({ findings: fullPage }),
        Response.json({ findings: [] }),
        Response.json({ findings: [...fullPage.slice(1), { id: 3001 }] }),
      ),
    ),
  ).rejects.toThrow(/changed across pages/);
});

test("rejects numeric API finding rows before returning an unreadable export", async () => {
  await expect(
    collectSemgrepPlatformFindings(
      options,
      responses(Response.json({ findings: [{ id: 7 }, 42] })),
    ),
  ).rejects.toThrow("Semgrep finding must be an object");
});

test("an explicit SDK token respects the configured Semgrep origin", async () => {
  const fetch = mock(async () => {
    throw new Error("Unexpected HTTP request");
  });
  for (const setting of ["SEMGREP_URL", "SEMGREP_APP_URL"]) {
    await expect(
      collectSemgrepPlatformFindings(
        { ...options, token: "synthetic-explicit" },
        {
          environment: {
            CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
            [setting]: "https://private.example.test",
          },
          fetch,
        },
      ),
    ).rejects.toThrow(setting);
  }
  expect(fetch).not.toHaveBeenCalled();
});

test("rejects failed, overlapping or wrong-scope pages without returning a partial report", async () => {
  for (const [second, error] of [
    [new Response("rate limited", { status: 429 }), /HTTP 429/],
    [Response.json({ findings: [{ id: 3000 }] }), /repeated/],
    [
      Response.json({ findings: [{ id: 3001, ref: "refs/heads/main" }] }),
      /ref/,
    ],
    [
      Response.json({
        findings: [
          { id: 3001, repository: { url: "https://github.com/other/service" } },
        ],
      }),
      /repository/i,
    ],
  ] as const) {
    await expect(
      collectSemgrepPlatformFindings(
        options,
        responses(Response.json({ findings: fullPage }), second),
      ),
    ).rejects.toThrow(error);
  }
});

test.each([null, "git@github.com:example/service.git"])(
  "snapshots the requested project mapping and ref for native URL %s",
  checkProjectMapping,
);

async function checkProjectMapping(raw: string | null) {
  const resolved = raw ? url + ".git" : url;
  const row = {
    id: 1,
    rule_name: "example.rule",
    severity: "informational",
    ref: options.ref,
    repository: { url },
  };
  const requested = { ...options, sourceRepositoryUrl: url };
  const pending = collectSemgrepPlatformFindings(requested, {
    environment,
    fetch: async (endpoint) => {
      if (endpoint.pathname.endsWith("/findings")) {
        expect(endpoint.searchParams.get("ref")).toBe(options.ref);
        return Response.json({ findings: [row] });
      }
      return Response.json({ project: { ...project, url: raw } });
    },
  });
  requested.project = "other/service";
  requested.sourceRepositoryUrl = "https://github.com/other/service";
  requested.ref = "main";
  const saved = await pending;
  expect(saved.project).toEqual({
    ...project,
    id: String(project.id),
    url: resolved,
  });
  expect(saved.nativeProjectUrl).toBe(raw ?? undefined);
  expect(saved.ref).toBe(options.ref);
  expect(saved).toMatchObject({ sourceRepositoryUrl: url });
  const legacy = {
    deployment: options.deployment,
    ref: options.ref,
    sourceRepositoryUrl: url,
    product: "sast",
    findingCount: 1,
    format: "semgrep-platform-findings/v1",
    project: { ...saved.project, url: raw },
    findings: [row],
  };
  await using fixture = await localReportFixture(
    "semgrep.json",
    { provider: "semgrep", sourceKey: "example/topic" },
    { remote: url },
  );
  for (const report of [saved, legacy]) {
    await fixture.writeJson(report);
    const prepared = await fixture.prepare();
    expect(prepared.preview.findings[0]?.evidence).toMatchObject({
      severity: raw ? "unknown" : "informational",
      details: { repository: { url: resolved } },
      source_data: { project: { url: raw }, sourceRepositoryUrl: url },
    });
    expect((await prepared.import()).counts).toEqual(
      report === saved
        ? { created: 1, updated: 0, unchanged: 0 }
        : { created: 0, updated: 0, unchanged: 1 },
    );
  }
  if (raw)
    expect(() =>
      normalizeSemgrepFindings(
        { ...saved, nativeProjectUrl: "git@github.com:other/project" },
        {},
        "local",
      ),
    ).toThrow(/repository/);
  expect(() =>
    normalizeSemgrepFindings(
      { ...saved, sourceRepositoryUrl: "https://github.com/other/service" },
      {},
      "local",
    ),
  ).toThrow(/repository/);
}

test("a mapped project keeps backlog lines and severity with a private GitHub reference", async () => {
  const remote = "https://git.example.test/Team/Repo";
  const name = "team/repo";
  const row = {
    id: 1,
    ref: options.ref,
    repository: { id: project.id, name },
    rule_name: "example.rule",
    severity: "informational",
    location: { file_path: "src/app.ts", line: "3" },
  };
  const report = {
    ...options,
    format: "semgrep-platform-findings/v2",
    product: "sast",
    project: { ...project, id: String(project.id), url: remote },
    sourceRepositoryUrl: remote,
    repositoryAliases: [name],
    findings: [JSON.stringify(row)],
    findingCount: 1,
  };
  const sourceRepositories = [{ url: remote, platform: "github" as const }];
  const hinted = normalizeSemgrepFindings(
    report,
    { sourceRepositories },
    "local",
  );
  expect(hinted.findings[0]?.evidence).toMatchObject({
    severity: "informational",
    locations: [{ path: "src/app.ts", line: 3 }],
    source_data: { project: { url: null }, sourceRepositoryUrl: remote },
  });
  const source = { provider: "semgrep" as const, sourceKey: "example/topic" };
  await using fixture = await localReportFixture("semgrep.json", source, {
    remote,
  });
  await fixture.writeJson(report);
  const first = await fixture.prepare();
  expect((await first.import()).counts.created).toBe(1);
  const replay = await prepareNormalizedLocalImport(
    { read: 1, findings: first.preview.findings, excluded: [] },
    { ...source, repository: fixture.repository },
    { environment: fixture.environment, sourceRepositories },
  );
  expect(replay.preview.findings).toEqual(hinted.findings);
  expect((await replay.import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 1,
  });
});

test("replays a direct occurrence with a collector-style SSH project binding", () => {
  const report = {
    ...options,
    product: "sast",
    format: "semgrep-platform-findings/v2",
    project: { ...project, id: String(project.id), url: url + ".git" },
    nativeProjectUrl: "git@github.com:example/service.git",
    sourceRepositoryUrl: url,
    repositoryAliases: [],
    findingCount: 1,
    findings: ['{"id":2,"rule_name":"example.rule"}'],
  };
  const row = normalizeSemgrepPlatformFindings(report).findings[0]!;
  const canonical = { ...row.evidence.source_data, annotation: "reviewed" };
  const direct = {
    ...canonical,
    project: report.project,
    nativeProjectUrl: report.nativeProjectUrl,
  };
  row.evidence.source_data = direct;
  const rebound = semgrepPlatformFindingBinding(row, "semgrep")!;
  row.evidence.source_data = rebound.sourceData;
  expect(row.evidence.source_data).not.toHaveProperty("nativeProjectUrl");
  expect(row.evidence.source_data).toMatchObject({
    annotation: "reviewed",
    project: { url: report.nativeProjectUrl },
  });
  expect(semgrepPlatformFindingRepository(row, "semgrep")).toBe(
    report.project.url,
  );
  row.evidence.source_data = {
    ...direct,
    nativeProjectUrl: "git@github.com:example/other",
  };
  expect(() => semgrepPlatformFindingRepository(row, "semgrep")).toThrow(
    /repository/,
  );
});

test("matches GitHub project-path aliases across casing in collected, v1 and normalized rows", async () => {
  const name = "semgrep-logical/Prod";
  const native = {
    name,
    id: project.id,
    url: "https://github.com/Example/Service",
  };
  const row = {
    id: 1,
    rule_name: "example.rule",
    repository: { name: "example/service" },
  };
  async function collect(projectUrl: string, findings: unknown[] = [row]) {
    return collectSemgrepPlatformFindings(
      { ...options, project: name },
      {
        environment,
        fetch: async (endpoint) =>
          Response.json(
            endpoint.pathname.endsWith("/findings")
              ? { findings }
              : { project: { ...native, url: projectUrl } },
          ),
      },
    );
  }
  const saved = await collect(native.url);
  expect(saved.repositoryAliases).toEqual([row.repository.name]);
  const { repositoryAliases: _aliases, ...v1 } = saved;
  const legacy = {
    ...v1,
    format: "semgrep-platform-findings/v1",
    findings: [row],
  };
  // The Semgrep project label and any witnessed display label retain their original casing.
  const named = (name: string) => ({ ...row, repository: { name } });
  const exact = await collect(native.url, [named("Prod")]);
  expect(normalizeSemgrepFindings(exact, {}, "local").findings).toHaveLength(1);
  const proof = { id: 2, repository: { name: "Prod", url: native.url } };
  for (const label of ["prod", "SEMGREP-LOGICAL/PROD"]) {
    const findings = [proof, named(label)];
    await expect(collect(native.url, findings)).rejects.toThrow(/repository/);
    expect(() =>
      normalizeSemgrepFindings(
        {
          ...saved,
          repositoryAliases: ["Prod", label],
          findingCount: findings.length,
          findings: findings.map((row) => JSON.stringify(row)),
        },
        {},
        "local",
      ),
    ).toThrow(/repository/);
    expect(() =>
      selectSemgrepPlatformFindings({
        ...options,
        projectResponse: JSON.stringify({ project: native }),
        findingIds: ["1"],
        findingsResponses: JSON.stringify({
          findings: [
            {
              ...row,
              ref: options.ref,
              repository: { name: label, id: native.id },
            },
          ],
        }),
      }),
    ).toThrow(/repository/);
  }
  const custom = "https://git.example.test/Example/Service";
  await expect(collect(custom)).rejects.toThrow(/repository/);
  for (const report of [saved, legacy]) {
    const finding = normalizeSemgrepFindings(report, {}, "local").findings[0]!;
    expect(semgrepPlatformFindingRepository(finding, "semgrep")).toBe(
      native.url,
    );
    expect(
      finding.evidence.source_data?.["repositoryWitnessJson"],
    ).toBeUndefined();
    const mapped = { ...report, project: { ...report.project, url: custom } };
    expect(() => normalizeSemgrepFindings(mapped, {}, "local")).toThrow(
      /repository/,
    );
    const options = {
      sourceRepositories: [{ url: custom, platform: "github" as const }],
    };
    const verified = normalizeSemgrepFindings(mapped, options, "local")
      .findings[0]!;
    expect(
      semgrepPlatformFindingRepository(
        verified,
        "semgrep",
        options.sourceRepositories,
      ),
    ).toBe(custom);
  }
});

test("a URL-less SAST row uses its Git path for selection and keeps other verified labels in the full report", () => {
  const project = {
    id: "77",
    name: "Logical/Service",
    url: "https://github.com/team/service%2Bapi",
  };
  const selection = "semgrep-platform-selection/v1";
  const full = "semgrep-platform-findings/v2";
  for (const [name, expectedFormat, captureAllowed] of [
    ["team/service+api", selection, true],
    ["team/service%2Bapi", selection, false],
    [project.name, full, false],
  ] as const) {
    const row = {
      id: 8,
      ref: options.ref,
      rule_name: "example.rule",
      repository: { id: 77, name },
    };
    const saved = {
      ...options,
      project,
      product: "sast",
      format: full,
      repositoryAliases: [name],
      findingCount: 1,
      findings: [JSON.stringify(row)],
    };
    const read = (report: unknown) =>
      normalizeSemgrepFindings(report, {}, "local");
    const finding = read(saved).findings[0]!;
    expect(finding.evidence.source_data?.["format"]).toBe(expectedFormat);
    expect(semgrepPlatformFindingRepository(finding, "semgrep")).toBe(
      project.url,
    );
    const archive = () => read({ ...saved, format: selection });
    if (expectedFormat === selection)
      expect(archive().findings).toEqual([finding]);
    else expect(archive).toThrow("project and ref");
    const capture = () =>
      selectSemgrepPlatformFindings({
        ...options,
        projectResponse: JSON.stringify({ project }),
        findingsResponses: [JSON.stringify({ findings: [row] })],
        findingIds: ["8"],
      });
    if (captureAllowed) expect(read(capture()).findings).toEqual([finding]);
    else expect(capture).toThrow("project and ref");
  }
});

test("repository path aliases retain a literal .git suffix and use verified GitHub SSH bindings", () => {
  const project = {
    id: "77",
    name: "project-label",
    url: "https://git.example.test/team/Service.git",
  };
  const labels = ["team/Service.git", "Service.git", "team/service", "service"];
  const rows = labels.map((name, index) => ({
    id: index + 1,
    rule_name: "example.rule",
    repository: { name },
  }));
  const report = {
    format: "semgrep-platform-findings/v2",
    deployment: "example",
    ref: options.ref,
    product: "sast",
    project,
    repositoryAliases: labels,
    findingCount: rows.length,
    findings: rows.map((row) => JSON.stringify(row)),
  };
  const verified = {
    sourceRepositories: [{ url: project.url, platform: "github" as const }],
  };
  const publicReport = {
    ...report,
    project: { ...project, url: "https://github.com/team/Service.git" },
  };
  expect(
    normalizeSemgrepFindings(publicReport, {}, "local").findings,
  ).toHaveLength(4);
  expect(
    normalizeSemgrepFindings(report, verified, "local").findings,
  ).toHaveLength(4);
  const encodedRow = { ...rows[0], repository: { name: "C++" } };
  const encoded = {
    ...report,
    project: { ...project, url: "https://github.com/team/C%2B%2B" },
    repositoryAliases: ["C++"],
    findings: [JSON.stringify(encodedRow)],
    findingCount: 1,
  };
  expect(normalizeSemgrepFindings(encoded, {}, "local").findings).toHaveLength(
    1,
  );
  const firstRow = {
    ...rows[0],
    repository: { url: "git@git.example.test:team/service.git" },
  };
  const native = {
    ...report,
    findings: [JSON.stringify(firstRow)],
    findingCount: 1,
  };
  const result = normalizeSemgrepFindings(native, verified, "local")
    .findings[0]!;
  expect(
    semgrepPlatformFindingRepository(
      result,
      "semgrep",
      verified.sourceRepositories,
    ),
  ).toBe(project.url);
  for (const candidate of [report, native]) {
    expect(() => normalizeSemgrepFindings(candidate, {}, "local")).toThrow(
      /repository/,
    );
    expect(() =>
      normalizeSemgrepFindings(
        candidate,
        {
          sourceRepositories: [
            { url: "https://git.example.test/team/other", platform: "github" },
          ],
        },
        "local",
      ),
    ).toThrow(/repository/);
  }
});
test("blank display names replay when a native ID or URL binds the repository", async () => {
  const findings = [
    { id: project.id, url, name: "" },
    { id: project.id, name: "   " },
    { url, name: "" },
  ].map((repository, index) => ({
    id: index + 1,
    repository,
    ref: options.ref,
    rule_name: "example.rule",
  }));
  const page = JSON.stringify({ findings });
  const saved = await collectSemgrepPlatformFindings(
    options,
    responses(new Response(page)),
  );
  expect(saved.repositoryAliases).toEqual([]);
  const { repositoryAliases: _aliases, ...legacy } = saved;
  const prior = {
    ...legacy,
    format: "semgrep-platform-findings/v1",
    findings,
    project,
  };
  for (const report of [saved, prior]) {
    const normalized = normalizeSemgrepFindings(report, {}, "local");
    expect(normalized.excluded).toEqual([]);
    expect(
      normalized.findings.map((row) =>
        semgrepPlatformFindingRepository(row, "semgrep"),
      ),
    ).toEqual([url, url, url]);
  }
  const selected = {
    ...options,
    projectResponse: JSON.stringify({ project }),
    findingsResponses: [page],
  };
  expect(
    selectSemgrepPlatformFindings({ ...selected, findingIds: ["1"] }).findings,
  ).toHaveLength(1);
  expect(() =>
    selectSemgrepPlatformFindings({ ...selected, findingIds: ["2"] }),
  ).toThrow("project and ref");
  for (const repository of [
    { name: "" },
    { id: 999, url, name: "" },
    { id: project.id, url: "https://github.com/other/service", name: "" },
  ]) {
    await expect(
      collectSemgrepPlatformFindings(
        options,
        responses(
          Response.json({ findings: [{ ...findings[0], repository }] }),
        ),
      ),
    ).rejects.toThrow(/repository/);
  }
});

test("uses independently verified project aliases for name-only rows", async () => {
  const label = "display",
    alias = { name: label };
  for (const proof of [{ url }, { id: project.id }]) {
    const findings = [
      { id: 1, repository: { name: project.name } },
      { id: 2, repository: { name: "service" } },
      { id: 3, repository: { ...alias, ...proof } },
      { id: 4, repository: alias },
    ];
    const report = await collectSemgrepPlatformFindings(
      options,
      responses(Response.json({ findings })),
    );
    expect(report.repositoryAliases).toEqual([label, project.name, "service"]);
    expect(report.findingCount).toBe(4);
  }
  for (const repository of [
    2,
    alias,
    { ...alias, id: 99 },
    { ...alias, url: "https://github.com/other/service" },
  ]) {
    await expect(
      collectSemgrepPlatformFindings(
        options,
        responses(Response.json({ findings: [{ id: 1, repository }] })),
      ),
    ).rejects.toThrow(/repository/i);
  }
});

test("accepts a name-only repository alias verified on a later page", async () => {
  const name = "project display name";
  const first = [{ id: 1, repository: { name } }, ...fullPage.slice(1)];
  const report = await collectSemgrepPlatformFindings(
    options,
    responses(
      Response.json({ findings: first }),
      Response.json({
        findings: [{ id: 3001, repository: { name, id: project.id } }],
      }),
      Response.json({ findings: first }),
    ),
  );
  expect(report.repositoryAliases).toEqual([name]);
  expect(report.findingCount).toBe(3001);
});

test("cross-page ID-less findings compare original numeric values and member order", async () => {
  const first = [
    ...fullPage.slice(1),
    { vendor: { score: 1 }, rule_name: "example.rule" },
  ];
  const collect = (score: string) =>
    collectSemgrepPlatformFindings(
      options,
      responses(
        Response.json({ findings: first }),
        new Response(
          `{"findings":[{"rule_name":"example.rule","vendor":{"score":${score}}},{"id":3001}]}`,
        ),
        Response.json({ findings: first }),
      ),
    );
  await expect(collect("1.0")).rejects.toThrow(
    /repeated findings across pages/,
  );
  expect((await collect("2")).findingCount).toBe(3002);
});

test("keeps unrelated valid findings on a page with missing or duplicate source IDs", async () => {
  const findings = [null, 2, 2, 3].map((id) => ({
    id,
    rule_name: "example.rule",
  }));
  const saved = await collectSemgrepPlatformFindings(
    options,
    responses(Response.json({ findings })),
  );
  expect(saved.findingCount).toBe(4);
  const result = normalizeSemgrepFindings(saved, {}, "local");
  expect(result.findings).toHaveLength(1);
  expect(result.excluded.map((row) => row.position).sort()).toEqual([1, 2, 3]);
});

test("replaying two native SAST findings across selected and full imports leaves SQLite unchanged", async () => {
  const ids = ["9223372036854775805", "9223372036854775806"];
  const projectId = "9223372036854775807";
  const projectResponse = `{"project":{"id":${projectId},"name":"${project.name}","url":"${url}"}}`;
  const repositories = [
    JSON.stringify({ url }),
    `{"id":${projectId},"name":"${project.name}"}`,
  ];
  const rows = ids.map(
    (id, index) =>
      `{"id":${id},"score":10,"rule":{"name":"example.rule"},"status":"open","severity":"low","repository":${repositories[index]},"ref":"${options.ref}"}`,
  );
  const page = `{"findings":[${rows.join(",")}]}`;
  const input = {
    deployment: options.deployment,
    ref: options.ref,
    projectResponse,
    findingsResponses: [page],
    findingIds: ids,
  };
  const selection = selectSemgrepPlatformFindings(input);
  const selected = normalizeSelectedSemgrepPlatformFindings({
    ...input,
    sourceRepositoryUrl: url,
  });
  const collect = (data: string) =>
    collectSemgrepPlatformFindings(
      {
        ...options,
        sourceRepositoryUrl: "https://github.com/Example/Service.git",
      },
      {
        environment,
        fetch: async (endpoint) =>
          new Response(
            endpoint.pathname.endsWith("/findings") ? data : projectResponse,
          ),
      },
    );
  const report = await collect(page.replaceAll('"score":10', '"score":1e1'));
  await using fixture = await localReportFixture(
    "semgrep.json",
    {
      provider: "semgrep",
      sourceKey: "example/topic",
      sourceRepositoryUrl: url,
    },
    { remote: url },
  );
  await fixture.writeJson(selection);
  const prepared = await fixture.prepare();
  expect(prepared.preview.excluded).toEqual([]);
  expect((await prepared.import()).counts).toEqual({
    created: 2,
    updated: 0,
    unchanged: 0,
  });
  const direct = await prepareNormalizedLocalImport(
    selected,
    {
      provider: "semgrep",
      sourceKey: fixture.sourceKey,
      repository: fixture.repository,
    },
    { environment: fixture.environment, sourceRepositories: [{ url }] },
  );
  expect((await direct.import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 2,
  });
  const saved = await fixture.read();
  expect(new Set(saved.map((row) => row.sourceFindingId)).size).toBe(2);
  for (const replay of [report, selection, report]) {
    await fixture.writeJson(replay);
    expect((await (await fixture.prepare()).import()).counts).toEqual({
      created: 0,
      updated: 0,
      unchanged: 2,
    });
  }
  expect(await fixture.read()).toEqual(saved);
  const changedPage = page.replace('"severity":"low"', '"severity":"high"');
  const changed = await collect(changedPage);
  await fixture.writeJson(changed);
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 1,
    unchanged: 1,
  });
  const revised = await fixture.read();
  expect(
    revised.find((row) => row.evidence.severity === "high")?.sourceFindingId,
  ).toBe(prepared.preview.findings[0]!.source_finding_id);
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 2,
  });
  expect(await fixture.read()).toEqual(revised);
  for (const [index, id] of ids.entries())
    expect(report.findings[index]).toContain(`"id":${id}`);
});

test("excludes malformed Supply Chain dependencies and preserves findings without a package", async () => {
  const row = { id: 11, rule_name: "example.rule" };
  const report = await collectSemgrepPlatformFindings(
    { ...options, product: "sca" },
    responses(
      Response.json({
        findings: [
          { ...row, found_dependency: 42 },
          { ...row, id: 12, found_dependency: { package: 42 } },
          { ...row, id: 13, found_dependency: { package: " " } },
          { ...row, id: 14, found_dependency: { package: null } },
          { ...row, id: 15, found_dependency: { package: "example-package" } },
          { ...row, id: 16, found_dependency: {}, fix_recommendations: 42 },
        ],
      }),
    ),
  );
  const result = normalizeSemgrepFindings(report, {}, "local");
  expect(result.excluded).toMatchObject([
    { position: 1, reason: "Semgrep found dependency must be an object." },
    ...[2, 3, 4].map((position) => ({
      position,
      reason: "Semgrep package name must be nonempty text.",
    })),
  ]);
  expect(
    result.findings.map(({ evidence }) =>
      evidence.packages?.map(({ name }) => name),
    ),
  ).toEqual([["example-package"], []]);
});

test("projects Supply Chain evidence and distinguishes AI SAST from SAST on replay", async () => {
  await using fixture = await localReportFixture(
    "semgrep.json",
    {
      provider: "semgrep",
      sourceKey: "example/topic",
      sourceRepositoryUrl: url,
    },
    { remote: url },
  );
  const row = {
    id: 11,
    rule: { name: "example.rule", message: "Synthetic finding" },
    ref: options.ref,
    repository: { name: project.name, url },
  };
  async function read(product: "sast" | "ai_sast" | "sca") {
    const finding =
      product === "sca"
        ? {
            ...row,
            vulnerability_identifier: "CVE-2025-0001",
            found_dependency: {
              package: "example-package",
              ecosystem: "npm",
              version: "1.0.0",
            },
            fix_recommendations: [
              { package: "example-package", version: "1.1.0" },
              { package: "other", version: "2.0.0" },
            ],
          }
        : row;
    const report = await collectSemgrepPlatformFindings(
      { ...options, product },
      responses(Response.json({ findings: [finding] })),
    );
    await fixture.writeJson(report);
    const { preview } = await fixture.prepare();
    expect(preview.excluded).toEqual([]);
    return preview.findings[0]!;
  }
  const sca = await read("sca");
  expect(sca.evidence.packages).toEqual([
    {
      name: "example-package",
      ecosystem: "npm",
      installed_version: "1.0.0",
      manifest_path: null,
      fixed_versions: ["1.1.0"],
    },
  ]);
  expect(sca.evidence.advisory_ids).toEqual(["CVE-2025-0001"]);
  const ai = await read("ai_sast");
  const sast = await read("sast");
  expect(ai.evidence.details?.kind).toBe("sast");
  expect(
    new Set([ai, sast, sca].map((finding) => finding.source_finding_id)).size,
  ).toBe(3);
});

test.each(["gitlab.com", "bitbucket.org"])(
  "imports informational Semgrep findings through the %s SSH-over-443 checkout remote",
  async (host) => {
    const alternate = "altssh." + host;
    const native = `ssh://git@${alternate}:443/example/service.git`;
    const report = await collectSemgrepPlatformFindings(options, {
      environment,
      fetch: async (endpoint) =>
        Response.json(
          endpoint.pathname.endsWith("/findings")
            ? {
                findings: [
                  {
                    id: 9,
                    rule_name: "example.rule",
                    severity: "informational",
                  },
                ],
              }
            : { project: { ...project, url: native } },
        ),
    });
    expect(report.project.url).toBe(`https://${host}/example/service.git`);
    const source = { provider: "semgrep" as const, sourceKey: "example/topic" };
    // Git decodes the escaped path in an ssh:// URL before requesting upload-pack.
    await using fixture = await localReportFixture("semgrep.json", source, {
      remote: native.replace("/service.git", "/%73ervice.git"),
    });
    await fixture.writeJson(report);
    const { preview } = await fixture.prepare();
    expect(preview.findings[0]?.evidence.severity).toBe("informational");
    for (const remote of [
      native.replace("git@", "other@"),
      native.replace(":443/", ":22/"),
    ]) {
      await using other = await localReportFixture("semgrep.json", source, {
        remote,
      });
      await other.writeJson(report);
      await expect(other.prepare()).rejects.toThrow(/does not match/);
    }
  },
);

const cliArgs = [
  "import",
  "semgrep",
  options.project,
  "--semgrep-deployment",
  options.deployment,
  "--semgrep-ref",
  options.ref,
  "--semgrep-product",
  "ai_sast",
  "--format",
  "json",
];

test("CLI emits a replayable report for the requested product", async () => {
  const row = {
    id: 42,
    repository: { url },
    ref: options.ref,
    rule_name: "example.rule",
  };
  const cli = createCliTest(main);
  const code = await cli.runCli([...cliArgs, "--source-repository-url", url], {
    ...dependencies({ environment }),
    hostedScannerFetch: async (endpoint) =>
      Response.json(
        endpoint.pathname.endsWith("/findings")
          ? { findings: [row] }
          : { project: { ...project, url: null } },
      ),
  });
  expect(code).toBe(0);
  expect(cli.stderr.text()).toBe("");
  const report = JSON.parse(cli.stdout.text());
  expect(report).toMatchObject({
    project: { id: "77", name: project.name, url },
    ref: options.ref,
    product: "ai_sast",
    sourceRepositoryUrl: url,
    findingCount: 1,
  });
  expect(report.findings.map((raw: string) => JSON.parse(raw))).toEqual([row]);
});

test("CLI escapes human-readable output while retaining native JSON and YAML", async () => {
  const alias = "display\u001b[2Jname\u009b2J\u202e";
  const row = { id: 42, repository: { id: project.id, name: alias } };
  for (const [format, tty] of [
    [undefined, true],
    ["toon", true],
    ["toon", false],
    ["md", true],
    ["md", false],
    ["json", true],
    ["yaml", false],
  ] as const) {
    const cli = createCliTest(main, { stdout: tty });
    const args =
      format === undefined ? cliArgs.slice(0, -2) : cliArgs.with(-1, format);
    const code = await cli.runCli(args, {
      ...dependencies({ environment }),
      hostedScannerFetch: responses(Response.json({ findings: [row] })).fetch,
    });
    expect(code).toBe(0);
    const output = cli.stdout.text();
    if (format === undefined || format === "md" || (format === "toon" && tty)) {
      expect(output).not.toContain("\u001b");
      expect(output).not.toContain("\u009b");
      expect(output).not.toContain("\u202e");
      expect(output).toContain("\\u009b2J\\u202e");
    } else if (format === "toon") {
      expect(output).toContain("name\u009b2J\u202e");
    } else {
      const report = format === "json" ? JSON.parse(output) : parseYaml(output);
      expect(report.repositoryAliases).toEqual([alias]);
      expect(JSON.parse(report.findings[0]).repository.name).toBe(alias);
    }
  }
});

test("CLI escapes bidirectional controls in Semgrep error diagnostics", async () => {
  const cli = createCliTest(main);
  const code = await cli.runCli(cliArgs, {
    ...dependencies({ environment }),
    hostedScannerFetch: responses(
      new Response("scope \u202edenied", { status: 403 }),
    ).fetch,
  });
  expect(code).toBe(2);
  expect(cli.stderr.text()).toContain("scope \\u202edenied");
});

test("CLI checks opt-in and token origin before fetching", async () => {
  const fetch = mock(() => {
    throw new Error("Unexpected HTTP call");
  });
  for (const [env, diagnostic] of [
    [{}, "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS"],
    [
      { ...environment, SEMGREP_URL: "https://other.example.test" },
      "SEMGREP_URL",
    ],
  ] as const) {
    const cli = createCliTest(main);
    const code = await cli.runCli(cliArgs, {
      ...dependencies({ environment: env }),
      hostedScannerFetch: fetch,
    });
    expect(code).toBe(2);
    expect(cli.stdout.text() + cli.stderr.text()).toContain(diagnostic);
  }
  expect(fetch).not.toHaveBeenCalled();
});

test("saved v1 findings keep exact source IDs and original JSON numeric types on local replay", async () => {
  const ids = ["9007199254740992", "9007199254740993"];
  const tokens = [ids[0]!, "9.007199254740993e15"];
  const row = {
    rule: { name: "example.rule" },
    ref: options.ref,
    repository: { name: "service" },
  };
  const v1 = {
    format: "semgrep-platform-findings/v1",
    deployment: options.deployment,
    project: { name: project.name, id: ids[1], url: null },
    sourceRepositoryUrl: url,
    ref: options.ref,
    product: "sast",
    findingCount: 2,
    findings: tokens.map((id) => ({
      ...row,
      id,
      vendor: { score: ["1.00000000000000001"], label: id },
    })),
    numericFields: {
      project: { id: ids[1] },
      findings: Object.fromEntries(
        tokens.map((id, i) => [
          i,
          { id, vendor: { score: { 0: "1.00000000000000001" } } },
        ]),
      ),
    },
  };
  await using fixture = await localReportFixture(
    "semgrep.json",
    {
      provider: "semgrep",
      sourceKey: "example/topic",
    },
    { remote: url },
  );
  await fixture.writeJson(v1);
  const prepared = await fixture.prepare();
  const { preview } = prepared;
  expect(preview.excluded).toEqual([]);
  const numericRows = ids.map(
    (id) =>
      `{"id":${id},"rule":{"name":"example.rule"},"ref":"${options.ref}","repository":{"url":"${url}"}}`,
  );
  const selection = selectSemgrepPlatformFindings({
    deployment: options.deployment,
    ref: options.ref,
    projectResponse: `{"project":{"name":"${project.name}","id":${ids[1]},"url":"${url}"}}`,
    findingsResponses: [`{"findings":[${numericRows.join(",")}]}`],
    findingIds: ids,
  });
  const selected = normalizeSemgrepFindings(
    selection,
    { sourceRepositoryUrl: url },
    "local",
  );
  const sourceIds = (rows: typeof preview.findings) =>
    rows.map((row) => row.source_finding_id);
  expect(new Set(sourceIds(preview.findings)).size).toBe(2);
  expect(sourceIds(preview.findings)).toEqual(sourceIds(selected.findings));
  for (const [i, finding] of preview.findings.entries()) {
    const raw = finding.evidence.source_data?.["semgrepPlatformFindingJson"];
    expect(raw).toContain(`"id":${ids[i]}`);
    expect(raw).toContain('"score":[1.00000000000000001]');
    expect(raw).toContain(`"label":"${tokens[i]}"`);
  }
  expect((await prepared.import()).counts).toEqual({
    created: 2,
    updated: 0,
    unchanged: 0,
  });
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 2,
  });
  const v2 = {
    ...v1,
    format: "semgrep-platform-findings/v2",
    repositoryAliases: ["service"],
    findings: ids.map(
      (id, i) =>
        `{"id":${id},"rule":{"name":"example.rule"},"ref":"${options.ref}","repository":{"name":"service"},"vendor":{"score":[1.00000000000000001],"label":"${tokens[i]}"}}`,
    ),
  };
  for (const equivalent of [v2, v1]) {
    await fixture.writeJson(equivalent);
    expect((await (await fixture.prepare()).import()).counts).toEqual({
      created: 0,
      updated: 0,
      unchanged: 2,
    });
  }
  await fixture.writeJson({
    ...v1,
    numericFields: { findings: { 0: { id: ids[1] } } },
  });
  await expect(fixture.prepare()).rejects.toThrow(/exact scanner number/);
  await fixture.writeJson({
    ...v1,
    findings: v1.findings.map((row) => ({
      ...row,
      repository: { name: "other" },
    })),
  });
  await expect(fixture.prepare()).rejects.toThrow(/repository/);
  await fixture.writeJson({
    ...v1,
    project: { ...v1.project, url: "https://github.com/other/service" },
  });
  await expect(fixture.prepare()).rejects.toThrow(/repository/);
  expect(() =>
    normalizeSemgrepFindings(
      {
        ...v1,
        project: { ...v1.project, url: "git@git.example.test:team/service" },
        sourceRepositoryUrl: "https://git.example.test/team/service",
      },
      {},
      "local",
    ),
  ).toThrow(/HTTP\(S\) repository/);
});

test("a verified alias remains replayable with or without a reader platform hint", async () => {
  const remote = "https://git.example.test/Team/Repo";
  const repository = { name: "repo" };
  const dependent = { id: 1, repository, rule_name: "example.rule" };
  const proof = {
    id: 2,
    rule_name: "example.proof",
    repository: { ...repository, url: remote },
  };
  const report = {
    ...options,
    project: { name: "logical", id: "77", url: remote },
    format: "semgrep-platform-findings/v2",
    product: "sast",
    repositoryAliases: [repository.name],
    findingCount: 2,
    findings: [dependent, proof].map((row) => JSON.stringify(row)),
  };
  const source = { provider: "semgrep" as const, sourceKey: "example/topic" };
  await using fixture = await localReportFixture("semgrep.json", source, {
    remote,
  });
  const settings = { ...source, repository: fixture.repository };
  const sourceRepositories = [{ url: remote, platform: "github" as const }];
  const dependencies = { environment: fixture.environment, sourceRepositories };
  await fixture.writeJson(report);
  const first = await fixture.prepare();
  expect((await first.import()).counts.created).toBe(2);
  const row = first.preview.findings[0]!;
  const input = { read: 1, findings: [row], excluded: [] };
  const direct = await prepareNormalizedLocalImport(
    input,
    settings,
    dependencies,
  );
  expect((await direct.import()).counts.unchanged).toBe(1);
  expect(
    semgrepPlatformFindingRepository(direct.preview.findings[0]!, "semgrep"),
  ).toBe(remote);
  expect(
    JSON.parse(
      row.evidence.source_data!["semgrepPlatformFindingJson"] as string,
    ),
  ).toEqual(dependent);
  const read = (saved: typeof report) =>
    normalizeSemgrepFindings(saved, { sourceRepositories }, "local");
  expect(read(report).findings[0]).toEqual(row);

  const withoutProof = read({
    ...report,
    findingCount: 1,
    findings: [report.findings[0]!],
  }).findings[0]!;
  expect(withoutProof.evidence.source_data).not.toHaveProperty(
    "repositoryWitnessJson",
  );
  expect(() =>
    semgrepPlatformFindingRepository(withoutProof, "semgrep"),
  ).toThrow(/witness/);
  for (const witness of [
    { name: "other", id: "77" },
    { ...repository, id: "99" },
  ]) {
    const forged = structuredClone(input);
    forged.findings[0]!.evidence.source_data!["repositoryWitnessJson"] =
      JSON.stringify(witness);
    await expect(
      prepareNormalizedLocalImport(forged, settings, dependencies),
    ).rejects.toThrow(/alias|repository/);
  }
});

test("changing the proof for an alias leaves its dependent SQLite finding unchanged", async () => {
  const label = "display label";
  const id = "9007199254740993";
  const byUrl = JSON.stringify({
    id: 1,
    rule_name: "example.url",
    repository: { name: label, url },
  });
  const byId = `{"id":2,"rule_name":"example.id","repository":{"name":"${label}","id":${id}}}`;
  const both = `{"id":3,"rule_name":"example.both","repository":{"metadata":"vendor-only","id":${id},"name":"${label}","url":"${url}"}}`;
  const dependent = (message: string) =>
    JSON.stringify({
      id: 4,
      rule_message: message,
      repository: { name: label },
    });
  const original = dependent("original");
  await using fixture = await localReportFixture(
    "semgrep.json",
    { provider: "semgrep", sourceKey: "example/topic" },
    { remote: url },
  );
  async function importRows(findings: string[]) {
    await fixture.writeJson({
      ...options,
      format: "semgrep-platform-findings/v2",
      project: { ...project, id },
      product: "sast",
      repositoryAliases: [label],
      findingCount: findings.length,
      findings,
    });
    const prepared = await fixture.prepare();
    expect(prepared.preview.excluded).toEqual([]);
    return (await prepared.import()).counts;
  }
  expect(await importRows([byUrl, original])).toEqual({
    created: 2,
    updated: 0,
    unchanged: 0,
  });
  const initial = (await fixture.read()).find(
    (row) => row.evidence.title === "original",
  )!;
  expect(initial.version).toBe(1);
  expect(initial.evidence.source_data?.["repositoryWitnessJson"]).toBe(
    JSON.stringify({ id, name: label }),
  );

  for (const rows of [
    [original, byUrl, byId, both],
    [both, byId, original, byUrl],
    [byId, original],
    [original, both],
  ]) {
    expect((await importRows(rows)).updated).toBe(0);
  }
  const stored = await fixture.read();
  expect(stored.find((row) => row.id === initial.id)).toEqual(initial);
  const native = stored.find((row) => row.evidence.title === "example.both")!
    .evidence.source_data?.["semgrepPlatformFindingJson"];
  expect(native).toContain('"metadata":"vendor-only"');
  expect(native).toContain(`"id":${id}`);

  const revised = [dependent("revised"), both];
  expect(await importRows(revised)).toEqual({
    created: 0,
    updated: 1,
    unchanged: 1,
  });
  expect(await importRows(revised)).toEqual({
    created: 0,
    updated: 0,
    unchanged: 2,
  });
  expect(
    (await fixture.read()).find((row) => row.id === initial.id),
  ).toMatchObject({
    version: 2,
    evidence: { title: "revised" },
  });
});

test("collects private GitHub and GitLab rows with an independently supplied repository", async () => {
  const name = "scanner-project";
  const native = "https://git.example.test/Org/Repo";
  const rowUrl = "https://git.example.test/org/repo.git";
  const findings = [
    { id: 1, rule_name: "example.rule", repository: { url: rowUrl } },
    { id: 2, rule_name: "example.rule", repository: { name: "repo" } },
  ];
  function collect(
    projectUrl: string,
    sourceRepositories: { url: string; platform: "github" | "gitlab" }[] = [],
    rows = findings,
  ) {
    return collectSemgrepPlatformFindings(
      { ...options, project: name, sourceRepositories },
      {
        environment,
        fetch: async (endpoint) =>
          Response.json(
            endpoint.pathname.endsWith("/findings")
              ? { findings: rows }
              : { project: { id: project.id, name, url: projectUrl } },
          ),
      },
    );
  }
  const scp = "git@git.example.test:Org/Repo";
  const ssh = "ssh://git@git.example.test/org/repo.git";
  for (const [projectUrl, referenceUrl] of [
    [native, rowUrl],
    [scp, rowUrl],
    [scp, ssh],
    [ssh, scp],
  ] as const) {
    const reference = {
      url: referenceUrl as string,
      platform: "github" as const,
    };
    const pending = collect(projectUrl, [reference]);
    reference.url = "https://git.example.test/Org/Other";
    const report = await pending;
    expect(report.project.url).toBe(projectUrl === ssh ? rowUrl : native);
    expect(JSON.parse(report.findings[0]!)).toEqual(findings[0]);
    expect(
      normalizeSemgrepFindings(
        report,
        { sourceRepositories: [{ url: rowUrl, platform: "github" }] },
        "local",
      ).findings,
    ).toHaveLength(2);
    await expect(collect(projectUrl)).rejects.toThrow(/repository/);
    await expect(collect(projectUrl, [reference])).rejects.toThrow(
      /repository/,
    );
  }
  const gitlabRows = [{ ...findings[0]!, repository: { url: scp } }];
  for (const url of [native, "https::" + native]) {
    const gitlab = { url, platform: "gitlab" as const };
    const report = await collect(scp, [gitlab], gitlabRows);
    expect(
      normalizeSemgrepFindings(
        report,
        { sourceRepositories: [gitlab] },
        "local",
      ).findings,
    ).toHaveLength(1);
    for (const other of [
      url.toLowerCase(),
      url.replace("/Repo", "/Other"),
      url.replace("git.example", "other.example"),
    ]) {
      await expect(
        collect(scp, [{ ...gitlab, url: other }], gitlabRows),
      ).rejects.toThrow(/repository/);
    }
  }
  await expect(
    collect(scp, [
      { url: ssh.replace("git.example", "other.example"), platform: "github" },
    ]),
  ).rejects.toThrow(/repository/);
});
