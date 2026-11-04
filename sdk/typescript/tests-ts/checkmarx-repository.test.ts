import { expect, test } from "bun:test";
import { normalizeCheckmarxOne } from "../src/checkmarx-one.js";
import { normalizeCheckmarxXml } from "../src/checkmarx-xml.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import type {
  ExternalFinding,
  ExternalFindings,
} from "../src/external-findings.js";
import type { Provider } from "../src/external-import-models.js";
import { normalizeSemgrepPlatformFindings } from "../src/semgrep-platform-findings.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";

const source = "https://github.com/example/project";
const other = source + "-other";
const projectedId = "checkmarx-one:" + "a".repeat(64);
const viewer = "https://one.example/CxWebClient/ViewerMain.aspx?";
type Report = ExternalFindings["report"];
const conflictingScope = /same product, project and scan/i;
const mismatchedRemote = /does not match a configured remote/i;

async function selectionFixture(remote?: string) {
  const fixture = await localFindingsFixture({ remote, isolatedGit: true });
  // Every admitted selection in these tests must preserve every supplied row.
  async function check(
    findings: ExternalFinding[],
    {
      provider = "checkmarx",
      report,
      reader,
    }: {
      provider?: Provider;
      report?: Report;
      reader?: string;
    } = {},
  ) {
    const { preview } = await prepareNormalizedLocalImport(
      { findings, report, read: findings.length, excluded: [] },
      {
        provider,
        repository: fixture.repository,
        sourceKey: "example/project/main",
      },
      {
        environment: fixture.environment,
        sourceRepositories: reader ? [{ url: reader }] : [],
      },
    );
    expect(preview.findings).toHaveLength(findings.length);
    return preview;
  }
  return { ...fixture, check };
}

function sdk(
  id: string,
  evidence: Partial<ExternalFinding["evidence"]> = {},
): ExternalFinding {
  return {
    source_finding_id: id,
    evidence: { title: "SDK finding", severity: "low", ...evidence },
  };
}

const one = (scanID: string, resultHash: string) =>
  normalizeCheckmarxOne(
    JSON.stringify({
      scanID,
      totalCount: 1,
      results: [
        {
          type: "sast",
          severity: "LOW",
          similarityId: "7",
          data: { resultHash, queryName: "Example_Query" },
        },
      ],
    }),
    source,
    "local",
  );

function xml(projectId: string, scanId = "1", similarity = "7", names = "") {
  return normalizeCheckmarxXml(
    `<CxXMLResults ScanId="${scanId}" ProjectId="${projectId}" ${names}>
      <Query id="3" name="Example_Query"><Result Severity="Low" FileName="src/read.ts" Line="3">
        <Path SimilarityId="${similarity}"><PathNode><FileName>src/read.ts</FileName><Line>3</Line></PathNode></Path>
      </Result></Query></CxXMLResults>`,
    source,
    "local",
  );
}

test("native Checkmarx batches without report metadata belong to one scan", async () => {
  await using selection = await selectionFixture(source);
  for (const make of [one, (scan: string, id: string) => xml("1", scan, id)]) {
    const first = make("1", "7").findings[0]!;
    const second = make("2", "8").findings[0]!;
    expect(first.source_finding_id).not.toBe(second.source_finding_id);
    await expect(selection.check([first, second])).rejects.toThrow(
      conflictingScope,
    );
    await selection.check([first, make("1", "8").findings[0]!]);
    const later = make("2", "7").findings[0]!;
    expect(later.source_finding_id).toBe(first.source_finding_id);
    await selection.check([later]);
    delete first.evidence.source_scan_id;
    await expect(selection.check([first])).rejects.toThrow(/source scan ID/i);
  }
  await expect(
    selection.check([...xml("1").findings, ...xml("2").findings]),
  ).rejects.toThrow(conflictingScope);
});

test("SDK-only Checkmarx rows compare declared scan IDs, repositories and instances", async () => {
  await using selection = await selectionFixture();
  const row = (scan: string, url: string) =>
    sdk(scan + url, {
      source_scan_id: scan,
      details: { kind: "sast", repository: { url } },
    });
  const first = row("1", source);
  const partial = sdk("sdk-unspecified");
  await expect(
    selection.check([partial, first, row("2", source)]),
  ).rejects.toThrow(conflictingScope);
  await expect(
    selection.check([partial, first, row("1", other)]),
  ).rejects.toThrow(/repository/i);
  await selection.check([partial, first, row("1", source + ".git")]);
  await selection.check([first, row("2", other)], { provider: "wiz" });

  const withInstance = (instance: unknown) =>
    sdk(String(instance), {
      ...first.evidence,
      source_data: { projectId: "17", instance },
    });
  const deployment = withInstance("https://one.example/sast");
  const second = withInstance("https://one.example/other");
  const alternate = "https://ONE.EXAMPLE:443/sast";
  const preview = await selection.check([deployment, withInstance(alternate)]);
  expect(preview.findings[1]!.evidence.source_data?.["instance"]).toBe(
    alternate,
  );
  await selection.check([
    withInstance("https://one.example"),
    withInstance("https://ONE.EXAMPLE:443/"),
  ]);
  await expect(selection.check([deployment, second])).rejects.toThrow(
    /same instance/i,
  );
  await selection.check([
    deployment,
    withInstance(2),
    withInstance("worker-17"),
    withInstance(alternate),
  ]);
  await selection.check([deployment, second], { provider: "wiz" });
  await selection.check(
    ["alpha", "beta"].map((projectName) =>
      sdk(projectName, { source_data: { projectName } }),
    ),
  );
});

test("a projected Checkmarx report under Wiz binds the configured Git fetch URL", async () => {
  await using selection = await selectionFixture(source + "?other=target");
  for (const format of [undefined, "custom-projection"]) {
    const report = {
      ...(format && { format }),
      sourceRepositoryUrl: source,
      scanId: "123",
    };
    await expect(
      selection.check([sdk(projectedId)], { provider: "wiz", report }),
    ).rejects.toThrow(mismatchedRemote);
  }
});

test("a projected Checkmarx row under Wiz retains the report and original asset repositories", async () => {
  await using selection = await selectionFixture(source);
  const check = (rows: ExternalFinding[], url?: string) =>
    selection.check(rows, {
      provider: "wiz",
      report: url
        ? { format: "custom-projection", sourceRepositoryUrl: url }
        : undefined,
    });
  const asset = (id: string, url: string) =>
    sdk(id, {
      source_data: {
        vulnerableAsset: {
          type: "REPOSITORY_BRANCH",
          cloudProviderURL: url + "/tree/main",
        },
      },
    });
  const retained = (id: string, url: string) =>
    sdk(id, { source_data: { sourceRepositoryUrl: url } });
  const anchor = sdk(projectedId);
  await expect(check([asset(projectedId, other)], source)).rejects.toThrow(
    /does not match/,
  );
  await expect(check([asset(projectedId, other)])).rejects.toThrow(
    mismatchedRemote,
  );
  await expect(
    check([anchor, asset("wiz-row", other)], source),
  ).rejects.toThrow(/does not match/);
  await check([asset(projectedId, source)], source);
  await check([asset("sdk-row", other)], other);
  for (const id of ["wiz-row", "checkmarx-one:" + "b".repeat(64)]) {
    await expect(check([anchor, retained(id, other)], source)).rejects.toThrow(
      /does not match/,
    );
    await check([anchor, retained(id, source)], source);
  }
  await check([sdk("sdk-row"), retained("wiz-row", other)], source);
});

test("a projected Checkmarx report must match a hosted Semgrep project even with both Git remotes", async () => {
  await using selection = await selectionFixture(source);
  selection.git("remote", "add", "other", other);
  const scan = normalizeSemgrepPlatformFindings({
    format: "semgrep-platform-findings/v2",
    deployment: "example",
    project: { id: "1", name: "example/project", url: source },
    ref: "refs/heads/main",
    product: "sca",
    repositoryAliases: [],
    findingCount: 1,
    findings: [JSON.stringify({ id: 9, rule_name: "example.rule" })],
  });
  const check = (sourceRepositoryUrl: string) =>
    selection.check([...scan.findings, sdk(projectedId)], {
      provider: "semgrep",
      report: { sourceRepositoryUrl },
    });
  await expect(check(other)).rejects.toThrow(/Checkmarx report repository/);
  await check(source);
});

test("selected native Checkmarx rows bind explicit SDK and reader claims without remotes", async () => {
  await using selection = await selectionFixture();
  const check = (
    claim: Partial<ExternalFinding["evidence"]>,
    reader?: string,
  ) =>
    selection.check([sdk("sdk-id", claim), ...xml("1").findings], { reader });
  await check({}, source);
  for (const claim of [
    { source_scan_id: "2" },
    { source_data: { projectId: "2" } },
    {
      details: { kind: "sast" as const, scanner_origin: "Checkmarx One SAST" },
    },
    { details: { kind: "sast" as const, repository: { url: other } } },
    { source_data: { sourceRepositoryUrl: other } },
  ]) {
    await expect(check(claim)).rejects.toThrow(
      /same product|retained Checkmarx report/i,
    );
  }
  await expect(check({}, other)).rejects.toThrow(/retained Checkmarx report/i);
  await check({ source_scan_id: "1", source_data: { projectId: "1" } });
});

function resultAttributes(finding: ExternalFinding) {
  return finding.evidence.source_data!["result"] as Record<string, unknown>;
}

test("normalized CxSAST batches compare the known viewer instances, including linkless rows", async () => {
  await using selection = await selectionFixture();
  const first = xml("1", "1", "1");
  const second = xml("1", "1", "2").findings[0]!;
  const third = xml("1", "1", "3").findings[0]!;
  resultAttributes(second)["DeepLink"] = viewer + "scanid=1";
  resultAttributes(third)["DeepLink"] =
    "https://two.example/CxWebClient/ViewerMain.aspx?scanid=1";
  const batch = [...first.findings, second, third];
  await expect(selection.check(batch)).rejects.toThrow(/same instance/i);
  resultAttributes(third)["DeepLink"] = resultAttributes(second)["DeepLink"];
  await selection.check(batch);
  await expect(
    selection.check(batch, {
      report: { ...first.report, instance: "https://two.example" },
    }),
  ).rejects.toThrow(/same instance/i);

  const projected = (query: string, pathId?: string) =>
    sdk("projected", {
      source_data: {
        result: { DeepLink: viewer + query },
        ...(pathId && { path: { PathId: pathId } }),
      },
    });
  await expect(
    selection.check([projected("scanid=2"), second]),
  ).rejects.toThrow(conflictingScope);
  await expect(
    selection.check([second, projected("projectid=2")]),
  ).rejects.toThrow(conflictingScope);
  await expect(
    selection.check([second, projected("pathid=2", "1")]),
  ).rejects.toThrow(/DeepLink/);
  await selection.check([second, projected("scanid=1&projectid=1")]);
});

test("recognized native rows retain their occurrence IDs and require the Checkmarx provider", async () => {
  await using selection = await selectionFixture(source);
  for (const input of [one("scan-a", "abc"), xml("1")]) {
    const { findings, report } = input;
    const row = findings[0]!;
    const originalId = row.source_finding_id;
    const originalScanner = row.evidence.details!.scanner_origin;
    const data = row.evidence.source_data!;
    const asWiz = (report?: Report) =>
      selection.check(findings, { provider: "wiz", report });
    await selection.check(findings, { report });
    await expect(asWiz(report)).rejects.toThrow(/checkmarx provider/i);
    delete data["format"];
    await selection.check(findings, { report });
    for (const format of [null, "other-format"]) {
      data["format"] = format;
      await expect(selection.check(findings, { report })).rejects.toThrow(
        /retained report/i,
      );
    }
    delete data["format"];
    await expect(asWiz()).rejects.toThrow(/checkmarx provider/i);
    row.source_finding_id = "sdk-key";
    await expect(asWiz()).rejects.toThrow(/checkmarx provider/i);
    await expect(selection.check(findings)).rejects.toThrow(
      /source finding ID/i,
    );
    await expect(selection.check(findings, { report })).rejects.toThrow(
      /source finding ID/i,
    );
    delete data["sourceRepositoryUrl"];
    await expect(asWiz()).rejects.toThrow(/checkmarx provider/i);
    await expect(selection.check(findings)).rejects.toThrow(
      /source finding ID/i,
    );
    delete row.evidence.details!.scanner_origin;
    await expect(selection.check(findings)).rejects.toThrow(
      /source finding ID/i,
    );
    await asWiz();

    // A projection without the native payload still has to honor explicit URLs.
    row.source_finding_id = originalId;
    row.evidence.source_data = { sourceRepositoryUrl: other };
    await expect(asWiz()).rejects.toThrow(/retained scanner repository/i);
    row.source_finding_id = "sdk-projection";
    row.evidence.details!.scanner_origin = originalScanner;
    delete row.evidence.details!.repository;
    await expect(asWiz()).rejects.toThrow(mismatchedRemote);
    row.evidence.source_data = { sourceRepositoryUrl: source };
    await asWiz();
    delete row.evidence.source_data;
    await asWiz();
  }
});

test("Checkmarx rows must match the report scan, format, project and repository", async () => {
  await using selection = await selectionFixture(source);
  for (const input of [one("scan-a", "abc"), xml("1")]) {
    const { findings, report } = input;
    await expect(
      selection.check(findings, { report: { sourceRepositoryUrl: other } }),
    ).rejects.toThrow(/retained Checkmarx report/i);
    for (const change of [
      { scanId: "another-scan" },
      { sourceRepositoryUrl: other },
      {
        format:
          report!["format"] === "cxsast-xml"
            ? "checkmarx-one-json"
            : "cxsast-xml",
        projectId: "1",
      },
    ]) {
      await expect(
        selection.check(findings, { report: { ...report, ...change } }),
      ).rejects.toThrow(
        /retained Checkmarx report|does not match the retained report/i,
      );
    }
    findings[0]!.evidence.details!.repository!.url = other;
    await expect(selection.check(findings, { report })).rejects.toThrow(
      /retained scanner repository/i,
    );
  }
  const typed = [sdk("sdk-id")];
  await selection.check(typed);
  const oneReport = one("scan-a", "abc").report;
  await expect(selection.check(typed, { report: oneReport })).rejects.toThrow(
    /retained report/i,
  );
  await expect(
    selection.check([], {
      report: { ...oneReport, totalCount: 0, sourceRepositoryUrl: other },
    }),
  ).rejects.toThrow(mismatchedRemote);

  const native = xml("1");
  await expect(
    selection.check(native.findings, {
      report: { ...native.report, projectId: "2" },
    }),
  ).rejects.toThrow(/retained report/i);
  resultAttributes(native.findings[0]!)["DeepLink"] =
    viewer + "scanid=2&projectid=1";
  await expect(selection.check(native.findings)).rejects.toThrow(/scan/i);
  const viewerOnly = sdk("sdk-viewer", {
    source_data: {
      sourceRepositoryUrl: other,
      result: { DeepLink: viewer + "scanid=1&projectid=1" },
    },
  });
  await expect(
    selection.check([viewerOnly], { provider: "wiz" }),
  ).rejects.toThrow(mismatchedRemote);
});

test("Checkmarx One scan UUIDs compare by value and retain their original spellings", async () => {
  await using selection = await selectionFixture(source);
  const id = "e074e307-135b-4185-9b4d-d249dcf70559";
  const upper = id.toUpperCase();
  const first = one(id, "7");
  const second = one(upper, "8");
  const row = (scan: string) => sdk(scan, { source_scan_id: scan });
  const preview = await selection.check(
    [...first.findings, ...second.findings],
    {
      report: second.report,
    },
  );
  expect(preview.report!["scanId"]).toBe(upper);
  expect(
    preview.findings.map(({ evidence }) => evidence.source_scan_id),
  ).toEqual([id, upper]);
  await selection.check([row(upper), ...first.findings]);
  await selection.check([row(id), row(upper)]);
  await expect(
    selection.check([row("scan-key"), row("SCAN-KEY")]),
  ).rejects.toThrow(conflictingScope);
  await expect(
    selection.check([row(upper), ...xml("1", id).findings]),
  ).rejects.toThrow(conflictingScope);
});

test("linkless CxSAST selections compare named project and team claims", async () => {
  await using selection = await selectionFixture(source);
  const first = xml(
    "3",
    "10",
    "1",
    'ProjectName="Project" TeamFullPathOnReportDate="/CxServer\\BuildÉ/"',
  );
  const second = (project: string, team: string) =>
    xml(
      "3",
      "10",
      "2",
      `ProjectName="${project}" TeamFullPathOnReportDate="${team}"`,
    ).findings;
  for (const report of [undefined, first.report]) {
    for (const rows of [
      second("project", "cxserver/buildÉ"),
      second("Project", "cxserver/buildé"),
    ]) {
      await expect(
        selection.check([...first.findings, ...rows], { report }),
      ).rejects.toThrow(/same product|retained report/i);
    }
    const team = "CXSERVER/BUILDÉ\\";
    const preview = await selection.check(
      [...first.findings, ...second("Project", team)],
      { report },
    );
    expect(
      preview.findings[1]!.evidence.source_data?.["teamFullPathOnReportDate"],
    ).toBe(team);
    await selection.check(
      [...first.findings, ...xml("3", "10", "2").findings],
      {
        report,
      },
    );
  }
});
