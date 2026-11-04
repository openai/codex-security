import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { readCheckmarxFindings } from "../src/checkmarx-findings.js";
import { main } from "../src/cli.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { dependencies } from "./cli-fixtures.js";
import {
  createAndReplayFinding,
  localReportFixture,
  updateStoredFinding,
} from "./external-findings-local-helpers.js";
import { createCliTest } from "./support/cli-run.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const repositoryUrl = "https://github.com/example/project";

function oneReport(severity: string) {
  return JSON.stringify({
    scanID: "00000000-0000-4000-8000-000000000001",
    totalCount: 1,
    results: [
      {
        type: "sast",
        id: "101",
        similarityId: "-202",
        status: "NEW",
        state: "TO_VERIFY",
        severity,
        description: "Input reaches a query",
        vulnerabilityDetails: { cweId: 89 },
        data: {
          queryName: "SQL_Injection",
          queryId: 17,
          resultHash: "a1b2c3",
          nodes: [{ fileName: "/src/query.ts", line: 3, column: 7 }],
        },
      },
    ],
  });
}

function xmlReport(severity: string) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<CxXMLResults ScanId="100" ProjectId="7">
  <Query id="17" name="SQL_Injection" cweId="89" Severity="${severity}" Language="JavaScript">
    <Result NodeId="1001" FileName="src/query.ts" Line="3" Column="7" Severity="${severity}" Status="New" FalsePositive="False" state="0">
      <Path ResultId="100" PathId="1" SimilarityId="-202">
        <PathNode><FileName>src/query.ts</FileName><Line>3</Line><Column>7</Column><NodeId>1</NodeId><Name>input</Name><Type>String</Type><Length>5</Length></PathNode>
      </Path>
    </Result>
  </Query>
</CxXMLResults>`;
}

for (const [format, report] of [
  ["json", oneReport],
  ["xml", xmlReport],
] as const) {
  test(`Checkmarx ${format} previews in the CLI and replays one unassessed finding in the workbench`, async () => {
    await using fixture = await localReportFixture(
      `checkmarx.${format}.gz`,
      {
        provider: "checkmarx",
        sourceKey: `example/project/main/${format}`,
        sourceRepositoryUrl: repositoryUrl,
      },
      { remote: repositoryUrl },
    );
    await writeFile(fixture.file, gzipSync(report("High")));
    const cli = createCliTest(main);
    const code = await cli.runCli(
      [
        "publish",
        "findings",
        fixture.file,
        "--to",
        "local",
        "--repository",
        fixture.repository,
        "--provider",
        "checkmarx",
        "--source-key",
        fixture.sourceKey,
        "--source-repository-url",
        repositoryUrl,
        "--dry-run",
        "--format",
        "json",
      ],
      dependencies({ environment: fixture.environment }),
    );
    expect({ code, stderr: cli.stderr.text() }).toEqual({
      code: 0,
      stderr: "",
    });
    expect(JSON.parse(cli.stdout.text())).toMatchObject({
      dryRun: true,
      source: { provider: "checkmarx", source_key: fixture.sourceKey },
      read: 1,
      excluded: [],
      findings: [{ evidence: { severity: "high", details: { kind: "sast" } } }],
    });
    await expect(
      fixture.prepare({
        sourceRepositoryUrl: "https://github.com/example/other",
      }),
    ).rejects.toThrow(/does not match/iu);
    const stored = await createAndReplayFinding(fixture);
    expect(stored.evidence.locations).toEqual([]);
    await writeFile(fixture.file, gzipSync(report("Medium")));
    expect((await updateStoredFinding(fixture, stored)).evidence.severity).toBe(
      "medium",
    );
  });
}

test.each([
  ["git@ssh.dev.azure.com:v3/team/project/repo", "project"],
  ["ssh://git@ssh.dev.azure.com:22/v3/team/My%20Project/repo", "My%20Project"],
  ["git@ssh.dev.azure.com:v3/team/My%20Project/repo", "My%20Project"],
])(
  "Checkmarx matches its HTTPS repository to Azure Repos clone %s",
  async (remote, project) => {
    const url = `https://dev.azure.com/team/${project}/_git/repo`;
    await using fixture = await localReportFixture(
      "checkmarx.json",
      {
        provider: "checkmarx",
        sourceKey: "team/project/main",
        sourceRepositoryUrl: url,
      },
      { remote },
    );
    await writeFile(fixture.file, oneReport("High"));
    expect((await fixture.prepare()).matchesRepositoryRemote).toBe(true);
    await expect(
      fixture.prepare({ sourceRepositoryUrl: url + "-other" }),
    ).rejects.toThrow(/does not match a configured remote/);
  },
);

test("Wiz imports match Azure SSH remotes for their projected Checkmarx rows", async () => {
  const url = "https://dev.azure.com/team/project/_git/repo";
  const remote = "git@ssh.dev.azure.com:v3/team/project/repo";
  await using fixture = await localReportFixture(
    "wiz.json",
    { provider: "wiz", sourceKey: "team/project" },
    { remote },
  );
  const row = (url: string, scanner_origin: string | null = null) => ({
    source_finding_id: url,
    evidence: {
      title: "Synthetic issue",
      severity: "low" as const,
      details: { kind: "sast" as const, scanner_origin, repository: { url } },
    },
  });
  const prepare = (...findings: ReturnType<typeof row>[]) =>
    fixture.prepareNormalized({
      read: findings.length,
      excluded: [],
      findings,
    });
  expect((await prepare(row(url, "CxSAST"))).matchesRepositoryRemote).toBe(
    true,
  );
  await expect(prepare(row(url + "-other", "CxSAST"))).rejects.toThrow(
    /does not match a configured remote/,
  );
  fixture.git("remote", "add", "second", remote + "-other");
  const sibling = {
    ...row(url + "-other"),
    source_finding_id: "blackduck-bom:" + "a".repeat(64),
  };
  await expect(prepare(row(url, "CxSAST"), sibling)).rejects.toThrow(
    /repo-other.*does not match a configured remote/,
  );
});

test("reads plain and gzipped UTF-16 CxSAST XML while keeping Checkmarx One JSON UTF-8", async () => {
  await using dir = await scopedTemporaryDirectory("checkmarx-encodings-");
  const file = join(dir.path, "report");
  const read = () => readCheckmarxFindings(file, repositoryUrl, "local");
  const xml = xmlReport("High").replaceAll("src/query.ts", "src/résumé.ts");
  await writeFile(file, xml);
  const expected = await read();
  expect(expected.findings).toHaveLength(1);

  for (const order of ["LE", "BE"]) {
    for (const prefix of ["", "\uFEFF"]) {
      const declaration = prefix ? "UTF-16" : "UTF-16" + order;
      const bytes = Buffer.from(
        prefix + xml.replace("UTF-8", declaration),
        "utf16le",
      );
      if (order === "BE") bytes.swap16();
      for (const report of [bytes, gzipSync(bytes)]) {
        await writeFile(file, report);
        expect(await read()).toEqual(expected);
      }
    }
  }
  await writeFile(file, Buffer.from("\uFEFF" + oneReport("High"), "utf16le"));
  await expect(read()).rejects.toThrow();

  const malformed = Buffer.from(
    "\uFEFF" + xml.replace("UTF-8", "UTF-16"),
    "utf16le",
  );
  malformed.writeUInt16LE(
    0xd800,
    malformed.indexOf(Buffer.from("résumé.ts", "utf16le")),
  );
  await writeFile(file, malformed);
  await expect(read()).rejects.toMatchObject({
    code: "ERR_ENCODING_INVALID_ENCODED_DATA",
  });
});

test.each(["secondary URL", "embedded newline"])(
  "Checkmarx binds only an effective Git fetch URL, even for projections (%s)",
  async (kind) => {
    const primary = "https://github.com/example/primary";
    await using fixture = await localReportFixture(
      "checkmarx.json",
      {
        provider: "checkmarx",
        sourceKey: "example/project/main",
        sourceRepositoryUrl: repositoryUrl,
      },
      { remote: primary },
    );
    await writeFile(fixture.file, oneReport("High"));
    if (kind === "secondary URL")
      fixture.git("config", "--add", "remote.origin.url", repositoryUrl);
    else
      fixture.git(
        "config",
        "remote.origin.url",
        primary + "\n" + repositoryUrl,
      );
    const expected =
      kind === "secondary URL"
        ? /does not match a configured remote/
        : /contains a line break/;
    const project = () =>
      prepareNormalizedLocalImport(
        {
          read: 1,
          excluded: [],
          report: { format: "sdk-selection" },
          findings: [
            {
              source_finding_id: "projected-row",
              evidence: {
                title: "Example finding",
                severity: "low",
                details: {
                  kind: "sast",
                  scanner_origin: "CxSAST",
                  repository: { url: repositoryUrl },
                },
              },
            },
          ],
        },
        {
          provider: "wiz",
          sourceKey: fixture.sourceKey,
          repository: fixture.repository,
        },
        { environment: fixture.environment },
      );
    await expect(project()).rejects.toThrow(expected);
    await expect(fixture.prepare()).rejects.toThrow(expected);
    fixture.git(
      "config",
      "--replace-all",
      "remote.origin.url",
      "alias:example/project",
    );
    fixture.git("config", "url.https://github.com/.insteadOf", "alias:");
    expect((await fixture.prepare()).matchesRepositoryRemote).toBe(true);
    expect((await project()).matchesRepositoryRemote).toBe(true);
  },
);
