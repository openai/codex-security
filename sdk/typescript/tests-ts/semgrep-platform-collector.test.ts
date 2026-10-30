import { expect, mock, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { parse as parseYaml } from "yaml";
import { collectSemgrepPlatformFindings } from "../src/semgrep-platform-collector.js";
import { main } from "../src/cli.js";
import {
  isSemgrepPlatformEvidence,
  normalizeSemgrepPlatformFindings,
  selectSemgrepPlatformFindings,
  semgrepPlatformFindingRepository,
} from "../src/semgrep-platform-findings.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { hostedRepositoryUrlKey } from "../src/hosted-git-repository.js";
import { normalizeSemgrepFindings } from "../src/semgrep-findings.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
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

test("an opaque bulk finding ID still requires the original native occurrence ID", async () => {
  const report = await collectSemgrepPlatformFindings(
    options,
    responses(Response.json({ findings: [{ id: 9 }] })),
  );
  const row = normalizeSemgrepFindings(report, {}, "local").findings[0]!;
  row.source_finding_id = "assigned-id";
  expect(semgrepPlatformFindingRepository(row, "semgrep")).toBe(url);
  row.evidence.source_data!["semgrepPlatformFindingJson"] = "{}";
  expect(() => semgrepPlatformFindingRepository(row, "semgrep")).toThrow(
    /exact, positive Semgrep Platform ID/,
  );
});

test("a retagged Semgrep row still requires its provider after assigning an opaque ID", async () => {
  const report = await collectSemgrepPlatformFindings(
    options,
    responses(
      Response.json({
        findings: [{ id: 9, ref: options.ref, repository: project }],
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
  await expect(
    prepareNormalizedLocalImport(
      normalized,
      { ...source, repository: fixture.repository },
      { environment: fixture.environment },
    ),
  ).rejects.toThrow(/semgrep provider/i);

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
    responses(Response.json({ findings: [{ id: 9 }] })),
  );
  const upstream = "https://git.example.test/service/upstream";
  const fork = "https://git.example.test/service/fork";
  const normalize = (url: string, id: string) =>
    normalizeSemgrepPlatformFindings({
      ...report,
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
  const prepare = (input: Parameters<typeof prepareNormalizedLocalImport>[0]) =>
    prepareNormalizedLocalImport(
      input,
      { ...source, repository: fixture.repository },
      { environment: fixture.environment },
    );
  await expect(
    prepare({ ...upstreamReport, findings: forkReport.findings }),
  ).rejects.toThrow(/report repository/i);
  const batch = {
    read: 2,
    excluded: [],
    findings: [...upstreamReport.findings, ...forkReport.findings],
  };
  expect((await prepare(batch)).preview.findings).toHaveLength(2);
});

test("hosted repository comparison accepts an opaque Git remote alias", () => {
  expect(hostedRepositoryUrlKey("invalid alias")).toBe("invalid alias");
});

test("file and normalized Platform reports keep their Git binding with no accepted findings", async () => {
  const source = { provider: "semgrep" as const, sourceKey: "example/topic" };
  await using fixture = await localReportFixture("semgrep.json", source, {
    remote: "ssh://git@altssh.gitlab.com:443/example/service.git",
  });
  const prepare = (input: Parameters<typeof prepareNormalizedLocalImport>[0]) =>
    prepareNormalizedLocalImport(
      input,
      { ...source, repository: fixture.repository },
      { environment: fixture.environment },
    );
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

test("snapshots the requested project mapping and ref before the first request", async () => {
  const requested = { ...options, sourceRepositoryUrl: url };
  const pending = collectSemgrepPlatformFindings(requested, {
    environment,
    fetch: async (endpoint) => {
      if (endpoint.pathname.endsWith("/findings")) {
        expect(endpoint.searchParams.get("ref")).toBe(options.ref);
        return Response.json({ findings: [] });
      }
      return Response.json({ project: { ...project, url: null } });
    },
  });
  requested.project = "other/service";
  requested.sourceRepositoryUrl = "https://github.com/other/service";
  requested.ref = "main";
  const saved = await pending;
  expect(saved.project).toEqual({ ...project, id: String(project.id) });
  expect(saved.ref).toBe(options.ref);
});

test("matches GitHub project-path aliases across casing in collected, v1 and normalized rows", async () => {
  const name = "Example/Service";
  const native = {
    name,
    id: project.id,
    url: "https://github.com/Example/Service",
  };
  const row = {
    id: 1,
    rule_name: "example.rule",
    repository: { name: name.toLowerCase() },
  };
  async function collect(projectUrl: string) {
    return collectSemgrepPlatformFindings(
      { ...options, project: name },
      {
        environment,
        fetch: async (endpoint) =>
          Response.json(
            endpoint.pathname.endsWith("/findings")
              ? { findings: [row] }
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

test("detects a repeated ID-less finding on mixed pages despite reordered JSON members", async () => {
  const matching = { vendor: { a: 1, b: 2 }, rule_name: "example.rule" };
  const reordered = { rule_name: "example.rule", vendor: { b: 2, a: 1 } };
  const first = [...fullPage.slice(1), matching];
  await expect(
    collectSemgrepPlatformFindings(
      options,
      responses(
        Response.json({ findings: first }),
        Response.json({ findings: [reordered, { id: 3001 }] }),
        Response.json({ findings: first }),
      ),
    ),
  ).rejects.toThrow(/repeated findings across pages/);
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
  const ids = ["9007199254740992", "9007199254740993"];
  const repositories = [{ url }, { id: project.id, name: project.name }];
  const rows = ids.map(
    (id, index) =>
      `{"id":${id},"rule":{"name":"example.rule"},"status":"open","severity":"low","repository":${JSON.stringify(repositories[index])},"ref":"${options.ref}"}`,
  );
  const page = `{"findings":[${rows.join(",")}]}`;
  const selection = selectSemgrepPlatformFindings({
    deployment: options.deployment,
    ref: options.ref,
    projectResponse: JSON.stringify({ project }),
    findingsResponses: [page],
    findingIds: ids,
  });
  const report = await collectSemgrepPlatformFindings(
    {
      ...options,
      sourceRepositoryUrl: "https://github.com/Example/Service.git",
    },
    responses(new Response(page)),
  );
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
  const changed = await collectSemgrepPlatformFindings(
    options,
    responses(new Response(changedPage)),
  );
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
  const code = await cli.runCli(cliArgs, {
    ...dependencies({ environment }),
    hostedScannerFetch: responses(Response.json({ findings: [row] })).fetch,
  });
  expect(code).toBe(0);
  expect(cli.stderr.text()).toBe("");
  const report = JSON.parse(cli.stdout.text());
  expect(report).toMatchObject({
    project: { id: "77", name: project.name, url },
    ref: options.ref,
    product: "ai_sast",
    findingCount: 1,
  });
  expect(report.findings.map((raw: string) => JSON.parse(raw))).toEqual([row]);
});

test("CLI escapes human-readable output while retaining native JSON and YAML", async () => {
  const alias = "display\u001b[2Jname\u009b2J\u202e";
  const row = { id: 42, repository: { id: project.id, name: alias } };
  for (const [format, tty] of [
    [undefined, true],
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
    if (format === undefined || format === "md") {
      expect(output).not.toContain("\u001b");
      expect(output).not.toContain("\u009b");
      expect(output).not.toContain("\u202e");
      expect(output).toContain("\\u009b2J\\u202e");
    } else {
      const report = format === "json" ? JSON.parse(output) : parseYaml(output);
      expect(report.repositoryAliases).toEqual([alias]);
      expect(JSON.parse(report.findings[0]).repository.name).toBe(alias);
    }
  }
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
    expect(raw).toContain(`"id":${tokens[i]}`);
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

test("changing the proof for an alias leaves its dependent SQLite finding unchanged", async () => {
  const label = "display label";
  const id = "9007199254740993";
  const byUrl = JSON.stringify({ id: 1, repository: { name: label, url } });
  const byId = `{"id":2,"repository":{"name":"${label}","id":${id}}}`;
  const both = `{"id":3,"repository":{"metadata":"vendor-only","id":${id},"name":"${label}","url":"${url}"}}`;
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
  const native = stored.find(
    (row) => row.evidence.title === "Semgrep finding 3",
  )!.evidence.source_data?.["semgrepPlatformFindingJson"];
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

test("collects Enterprise GitHub rows with a matching repository reference captured before lookup", async () => {
  const name = "scanner-project";
  const native = "https://git.example.test/Org/Repo";
  const rowUrl = "https://git.example.test/org/repo.git";
  const findings = [
    { id: 1, rule_name: "example.rule", repository: { url: rowUrl } },
    { id: 2, rule_name: "example.rule", repository: { name: "repo" } },
  ];
  function collect(
    projectUrl: string,
    sourceRepositories: { url: string; platform: "github" }[] = [],
  ) {
    return collectSemgrepPlatformFindings(
      { ...options, project: name, sourceRepositories },
      {
        environment,
        fetch: async (endpoint) =>
          Response.json(
            endpoint.pathname.endsWith("/findings")
              ? { findings }
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
  await expect(
    collect(scp, [
      { url: ssh.replace("git.example", "other.example"), platform: "github" },
    ]),
  ).rejects.toThrow(/repository/);
});
