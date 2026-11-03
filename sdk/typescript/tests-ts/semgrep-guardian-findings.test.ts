import { expect, mock, test } from "bun:test";
import { prepareNormalizedExternalPublication } from "../src/external-findings-publish.js";
import { collectSelectedSemgrepGuardianFindings } from "../src/semgrep-guardian-findings.js";
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
const environment = { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" };
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
    environment,
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

  // Guardian returns a string; the Web API can send the same digits as a JSON integer.
  const webId = (JSON as JSON & { rawJSON(value: string): unknown }).rawJSON(
    id,
  );
  const web = await collectSemgrepPlatformFindings(
    { deployment, project, ref },
    {
      environment: { ...environment, SEMGREP_APP_TOKEN: "synthetic" },
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
  expect(() => normalizeSemgrepFindings(sca)).toThrow(/local workbench/);
  await expect(
    prepareNormalizedExternalPublication(
      {
        ...normalized,
        report: {},
        findings: [{ ...normalized.findings[0]!, source_finding_id: "custom" }],
      },
      { repository: project, provider: "semgrep", sourceKey: "example/topic" },
      {
        environment,
        credentials: async () => {
          throw new Error("Unexpected credential lookup");
        },
      },
    ),
  ).rejects.toThrow(/local import/);
  expect(normalized.findings[0]!.evidence).toMatchObject({
    locations: [],
    source_data: { finding: sca.structuredContent.findings[0] },
  });
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

test("SDK exports containing Guardian findings fail before Cloud credential lookup", async () => {
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
          provider: "semgrep",
          sourceKey: "example/topic",
        },
        { environment, credentials },
      ),
    ).rejects.toThrow(/local import/);
  }
  expect(credentials).not.toHaveBeenCalled();
});

test("empty selections and disabled imports do not call Guardian; tool errors retain their message", async () => {
  const callTool = mock(async () => ({
    isError: true,
    content: [{ type: "text", text: "Guardian login expired" }],
  }));
  await expect(
    collectSelectedSemgrepGuardianFindings(
      { ...selection, findingIds: [] },
      { callTool, environment },
    ),
  ).rejects.toThrow(/at least one/);
  await expect(
    collectSelectedSemgrepGuardianFindings(selection, {
      callTool,
      environment: {},
    }),
  ).rejects.toThrow(/disabled/);
  expect(callTool).not.toHaveBeenCalled();
  await expect(
    collectSelectedSemgrepGuardianFindings(selection, {
      callTool,
      environment,
    }),
  ).rejects.toThrow("Guardian login expired");
});
