import { expect, mock, test } from "bun:test";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { prepareNormalizedExternalPublication } from "../src/external-findings-publish.js";
import { collectSelectedSemgrepGuardianFindings } from "../src/semgrep-guardian-findings.js";
import { stableId } from "../src/scanner-import.js";
import { normalizeSemgrepFindings } from "../src/semgrep-findings.js";
import { collectSemgrepPlatformFindings } from "../src/semgrep-platform-collector.js";
import { isolatedGitReportFixture } from "./external-findings-local-helpers.js";

const sourceRepositoryUrl = "https://github.com/example/service";
const ref = "refs/heads/topic";
const project = "example/service";
const deployment = "example";
const id = "9007199254740993";
const selection = {
  request: {
    name: "get_semgrep_sast_findings" as const,
    arguments: {
      deployment_name: deployment,
      repository_name: project,
      ref,
      states: ["fixed"],
    },
  },
  sourceRepositoryUrl,
  findingIds: [id],
};
const row = {
  id,
  repository: { name: project },
  ref,
  issueType: "sast",
  rulePath: "example.rule",
  message: "Example match",
  status: "fixed",
  severity: "HIGH",
  filePath: "src/main.ts",
  line: 3,
};
const capture = {
  format: "semgrep-guardian-selection/v1",
  ...selection,
  structuredContent: { findings: [row] },
};

test("a signed-in Guardian selection and Web API collection keep independent rows on replay", async () => {
  const callTool = mock(async (_request: unknown) => ({
    structuredContent: { findings: [{ ...row, id: "9007199254740992" }, row] },
  }));
  const selected = await collectSelectedSemgrepGuardianFindings(selection, {
    callTool,
  });
  expect(callTool.mock.calls).toEqual([[selection.request]]);
  expect(selected).toEqual(capture);

  await using fixture = await isolatedGitReportFixture(
    "report.json",
    { provider: "semgrep", sourceKey: "example/topic" },
    { remote: sourceRepositoryUrl },
  );
  await fixture.writeJson(selected);
  const preview = await fixture.prepare();
  expect(preview.preview.excluded).toEqual([]);
  expect(preview.preview.findings[0]!.evidence).toMatchObject({
    title: row.rulePath,
    severity: "high",
    branch: ref,
    locations: [{ path: row.filePath, line: 3 }],
    source_data: { finding: row },
  });
  expect(await fixture.read()).toHaveLength(0);
  expect((await preview.import()).counts.created).toBe(1);
  const replay = await prepareNormalizedLocalImport(
    preview.preview,
    {
      repository: fixture.repository,
      provider: "semgrep",
      sourceKey: fixture.sourceKey,
    },
    {
      environment: fixture.environment,
      sourceRepositories: [{ url: sourceRepositoryUrl }],
    },
  );
  expect((await replay.import()).counts.unchanged).toBe(1);

  // Guardian returns a string; the Web API can send the same digits as a JSON integer.
  const webId = (JSON as JSON & { rawJSON(value: string): unknown }).rawJSON(
    id,
  );
  const web = await collectSemgrepPlatformFindings(
    { deployment, project, ref },
    {
      environment: { SEMGREP_APP_TOKEN: "synthetic" },
      fetch: async (url) =>
        Response.json(
          url.pathname.endsWith("/findings")
            ? {
                findings: [
                  {
                    id: webId,
                    repository: {
                      id: 4,
                      name: project,
                      url: sourceRepositoryUrl,
                    },
                    ref,
                    rule: {
                      name: row.rulePath,
                      message: row.message,
                      cwe_names: ["CWE-79"],
                    },
                    location: { file_path: row.filePath, line: 3, end_line: 5 },
                  },
                ],
              }
            : { project: { id: 4, name: project, url: sourceRepositoryUrl } },
        ),
    },
  );
  await fixture.writeJson(web);
  expect((await (await fixture.prepare()).import()).counts.created).toBe(1);
  await fixture.writeJson(selected);
  expect((await (await fixture.prepare()).import()).counts.unchanged).toBe(1);
  const stored = await fixture.read();
  expect(stored).toHaveLength(2);
  const platform = stored.find((item) =>
    item.sourceFindingId.startsWith("semgrep-platform:"),
  );
  expect(
    platform?.evidence.source_data?.["semgrepPlatformFindingJson"],
  ).toContain(`"id":${id},`);
  expect(platform?.evidence.details?.code?.end_line).toBe(5);
  expect(stored.every((item) => item.version === 1)).toBe(true);
});

test("the capture reader selects exact IDs and rejects missing, ambiguous or conflicting evidence", () => {
  function read(findings: unknown[]) {
    return normalizeSemgrepFindings(
      { ...capture, structuredContent: { findings } },
      {},
      "local",
    );
  }
  expect(read([row, { ...row, id: "other", ref: "unrelated" }]).read).toBe(1);
  expect(() => read([{ ...row, id: "9007199254740992" }])).toThrow(
    /did not return/,
  );
  expect(() => read([row, row])).toThrow(/duplicate/);
  expect(() => read([{ ...row, id: "0" + id }])).toThrow(/did not return/);
  expect(() =>
    read([{ ...row, repository: { name: "other/project" } }]),
  ).toThrow(/repository and ref/);
  expect(() => read([{ ...row, ref: "refs/tags/topic" }])).toThrow(
    /repository and ref/,
  );
  expect(() => read([{ ...row, issueType: "secrets" }])).toThrow(/product/);
});

test("Guardian Supply Chain retains its summary and checks the operator's checkout mapping", async () => {
  const sca = {
    ...capture,
    request: {
      ...selection.request,
      name: "get_semgrep_supply_chain_findings",
    },
    structuredContent: {
      findings: [
        { ...row, issueType: "ISSUE_TYPE_SCA", filePath: "../outside" },
      ],
    },
  };
  const normalized = normalizeSemgrepFindings(sca, {}, "local");
  expect(normalizeSemgrepFindings(sca).findings).toEqual(normalized.findings);
  expect(normalized.findings[0]!.evidence).toMatchObject({
    locations: [],
    source_data: { finding: sca.structuredContent.findings[0] },
  });
  await using wrongProvider = await isolatedGitReportFixture(
    "guardian.json",
    { provider: "wiz", sourceKey: "test" },
    { remote: "https://github.com/other/service" },
  );
  for (const input of [normalized, { ...normalized, report: undefined }]) {
    await expect(wrongProvider.prepareNormalized(input)).rejects.toThrow(
      /semgrep provider/,
    );
  }
  const original = normalized.findings[0]!;
  await using source = await isolatedGitReportFixture(
    "guardian.json",
    { provider: "semgrep", sourceKey: "test" },
    { remote: sourceRepositoryUrl },
  );
  const otherUrl = "https://github.com/other/service";
  source.git("remote", "add", "upstream", otherUrl);
  await expect(
    source.prepareNormalized({
      ...normalized,
      report: { ...normalized.report, repositoryUrl: otherUrl },
    }),
  ).rejects.toThrow(/recorded selection/);
  await expect(
    source.prepareNormalized({
      ...normalized,
      findings: [
        {
          ...original,
          source_finding_id: "semgrep-guardian:" + "0".repeat(64),
        },
      ],
    }),
  ).rejects.toThrow(/original Guardian finding/);
  expect(normalized.findings[0]!.evidence.packages ?? []).toEqual([]);
  expect(normalized.findings[0]!.source_finding_id).not.toBe(
    normalizeSemgrepFindings(capture, {}, "local").findings[0]!
      .source_finding_id,
  );
  const other = "https://github.com/other/service";
  expect(() =>
    normalizeSemgrepFindings(sca, { sourceRepositoryUrl: other }, "local"),
  ).toThrow(/declared source/);
  await using fixture = await isolatedGitReportFixture(
    "guardian.json",
    { provider: "semgrep", sourceKey: "test" },
    { remote: other },
  );
  await fixture.writeJson(sca);
  await expect(fixture.prepare()).rejects.toThrow(/configured remote/);
  expect(await fixture.read()).toHaveLength(0);
});

test("normalized Guardian imports verify the original finding against the selected scope", async () => {
  await using fixture = await isolatedGitReportFixture(
    "guardian.json",
    { provider: "semgrep", sourceKey: "test" },
    { remote: sourceRepositoryUrl },
  );
  const normalized = normalizeSemgrepFindings(capture, {}, "local");
  const original = normalized.findings[0]!;
  await expect(
    fixture.prepareNormalized({
      ...normalized,
      findings: [{ ...original, source_finding_id: "another-source-id" }],
    }),
  ).rejects.toThrow(/original Guardian finding/);
  for (const changed of [
    { ...row, repository: { name: "other/service" } },
    { ...row, ref: "refs/heads/other" },
    { ...row, issueType: "ISSUE_TYPE_SCA" },
  ]) {
    await expect(
      fixture.prepareNormalized({
        ...normalized,
        findings: [
          {
            ...original,
            evidence: {
              ...original.evidence,
              source_data: {
                ...original.evidence.source_data,
                finding: changed,
              },
            },
          },
        ],
      }),
    ).rejects.toThrow(/does not match the selected/);
  }
});

test("normalized Guardian rows require a real selection scope even with a matching hash", async () => {
  await using fixture = await isolatedGitReportFixture(
    "guardian.json",
    { provider: "semgrep", sourceKey: "test" },
    { remote: sourceRepositoryUrl },
  );
  const normalized = normalizeSemgrepFindings(capture, {}, "local");
  for (const [override, nativeId, error] of [
    [{ tool: "list_findings" }, id, /Guardian SAST or Supply Chain/],
    [{ deployment: null }, id, /Guardian deployment/],
    [{ repository: "" }, id, /Guardian repository/],
    [{ ref: "main" }, id, /fully qualified Semgrep ref/],
    [{}, 12, /Guardian finding ID/],
    [{}, "  ", /Guardian finding ID/],
  ] as const) {
    const input = structuredClone(normalized);
    const finding = input.findings[0]!;
    const data = finding.evidence.source_data!;
    Object.assign(data, override);
    // Each malformed row agrees with its stored scope and ID. A matching hash alone is insufficient.
    data["finding"] = {
      id: nativeId,
      repository: { name: data["repository"] },
      ref: data["ref"],
    };
    finding.evidence.branch = String(data["ref"]);
    finding.source_finding_id = stableId("semgrep-guardian", [
      data["deployment"],
      data["repository"],
      data["tool"],
      data["ref"],
      nativeId,
    ]);
    await expect(fixture.prepareNormalized(input)).rejects.toThrow(error);
  }
});

test("normalized Guardian repository claims use the checkout's HTTP port identity", async () => {
  await using fixture = await isolatedGitReportFixture(
    "guardian.json",
    { provider: "semgrep", sourceKey: "test" },
    { remote: sourceRepositoryUrl },
  );
  const normalized = normalizeSemgrepFindings(capture, {}, "local");
  const withReportPort = (port: number) => ({
    ...normalized,
    report: {
      ...normalized.report,
      repositoryUrl: sourceRepositoryUrl.replace(
        "github.com/",
        `github.com:${port}/`,
      ),
    },
  });
  expect(
    (await (await fixture.prepareNormalized(withReportPort(443))).import())
      .counts.created,
  ).toBe(1);
  await expect(fixture.prepareNormalized(withReportPort(8443))).rejects.toThrow(
    /recorded selection/,
  );
});

test("SDK exports containing Guardian findings require their original provider", async () => {
  const guardian = normalizeSemgrepFindings(capture, {}, "local");
  const normalized = {
    read: 1,
    excluded: [],
    findings: [
      {
        source_finding_id: "example",
        evidence: { title: "Example", severity: "high" as const },
      },
    ],
  };
  const credentials = mock(async () => {
    throw new Error("Unexpected credential lookup");
  });
  for (const input of [
    { ...normalized, toJSON: () => guardian },
    {
      ...normalized,
      findings: [
        { ...normalized.findings[0]!, toJSON: () => guardian.findings[0] },
      ],
    },
  ]) {
    await expect(
      prepareNormalizedExternalPublication(
        input,
        {
          repository: project,
          provider: "wiz",
          sourceKey: "example/topic",
        },
        { credentials },
      ),
    ).rejects.toThrow(/semgrep provider/);
  }
  expect(credentials).not.toHaveBeenCalled();
});

test("Guardian validates the selection before calling the tool and preserves tool errors", async () => {
  const callTool = mock(async () => ({
    isError: true,
    content: [{ type: "text", text: "Guardian login expired" }],
  }));
  await expect(
    collectSelectedSemgrepGuardianFindings(
      { ...selection, findingIds: [] },
      { callTool },
    ),
  ).rejects.toThrow(/at least one/);
  expect(callTool).not.toHaveBeenCalled();
  await expect(
    collectSelectedSemgrepGuardianFindings(selection, {
      callTool,
    }),
  ).rejects.toThrow("Guardian login expired");
});

test("Guardian binds the collection, saved selection and normalized replay to the same custom Git repository", async () => {
  const url = "https://git.example.test/example/service";
  const collected = await collectSelectedSemgrepGuardianFindings(
    { ...selection, sourceRepositoryUrl: url },
    {
      callTool: async () => ({ structuredContent: { findings: [row] } }),
    },
  );
  const other = url + ".git";
  for (const options of [
    { sourceRepositoryUrl: other },
    { sourceRepositories: [{ url: other }] },
  ]) {
    expect(() => normalizeSemgrepFindings(collected, options, "local")).toThrow(
      /does not match/,
    );
  }
  const normalized = normalizeSemgrepFindings(collected, {}, "local");
  await using fixture = await isolatedGitReportFixture(
    "guardian.json",
    { provider: "semgrep", sourceKey: "example/topic" },
    { remote: other },
  );
  await fixture.writeJson(collected);
  await expect(fixture.prepare()).rejects.toThrow(/configured remote/);
  await expect(fixture.prepareNormalized(normalized)).rejects.toThrow(
    /configured remote/,
  );
  expect(await fixture.read()).toEqual([]);
  fixture.git("remote", "set-url", "origin", url);
  expect((await (await fixture.prepare()).import()).counts.created).toBe(1);
  expect(
    (await (await fixture.prepareNormalized(normalized)).import()).counts
      .unchanged,
  ).toBe(1);

  await expect(
    prepareNormalizedLocalImport(
      normalized,
      {
        repository: fixture.repository,
        sourceKey: fixture.sourceKey,
        provider: "github",
      },
      { environment: fixture.environment },
    ),
  ).rejects.toThrow(/semgrep provider/);

  // Multiple configured remotes cannot justify substituting a different retained mapping.
  fixture.git("remote", "add", "second", other);
  const changed = structuredClone(normalized);
  changed.findings[0]!.evidence.source_data!["sourceRepositoryUrl"] = other;
  await expect(fixture.prepareNormalized(changed)).rejects.toThrow(
    /recorded selection/,
  );
  const wrongProjection = structuredClone(normalized);
  wrongProjection.findings[0]!.evidence.details!.repository!.url = other;
  await expect(fixture.prepareNormalized(wrongProjection)).rejects.toThrow(
    /recorded selection/,
  );
});

test("Guardian accepts the clone URL of an independently identified self-managed GitLab project", () => {
  const url = "https://git.example.test/example/service";
  const result = normalizeSemgrepFindings(
    { ...capture, sourceRepositoryUrl: url },
    {
      sourceRepositoryUrl: url + ".git",
      sourceRepositories: [{ url, platform: "gitlab" }],
    },
    "local",
  );
  expect(result.excluded).toEqual([]);
  expect(result.findings[0]!.evidence.details?.repository?.url).toBe(url);
});
