import { expect, test } from "bun:test";
import { normalizeCheckmarxOne } from "../src/checkmarx-one.js";
import { normalizeCheckmarxXml } from "../src/checkmarx-xml.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import type { ExternalFindings } from "../src/external-findings.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";

test("normalized Checkmarx replay binds the retained occurrence to its repository and provider", async () => {
  const source = "https://github.com/example/project";
  await using fixture = await localFindingsFixture({ remote: source });
  const options = {
    provider: "checkmarx" as const,
    repository: fixture.repository,
    sourceKey: "example/project/main",
  };
  const dependencies = { environment: fixture.environment };
  const normal = normalizeCheckmarxOne(
    JSON.stringify({
      scanID: "scan-a",
      totalCount: 1,
      results: [
        {
          type: "sast",
          severity: "LOW",
          similarityId: "7",
          data: {
            resultHash: "abc",
            queryName: "Example_Query",
          },
        },
      ],
    }),
    source,
    "local",
  );
  const xml = (projectId: string) =>
    normalizeCheckmarxXml(
      `<CxXMLResults ScanId="1" ProjectId="${projectId}"><Query id="3" name="Example_Query"><Result Severity="Low" FileName="src/read.ts" Line="3"><Path SimilarityId="7"><PathNode><FileName>src/read.ts</FileName><Line>3</Line></PathNode></Path></Result></Query></CxXMLResults>`,
      source,
      "local",
    );
  const prepare = (input: ExternalFindings) =>
    prepareNormalizedLocalImport(input, options, dependencies);
  for (const input of [normal, xml("1")]) {
    expect((await prepare(input)).preview.findings).toHaveLength(1);
    const otherRepository = structuredClone(input);
    otherRepository.findings[0]!.evidence.details!.repository!.url =
      "https://github.com/example/another";
    await expect(prepare(otherRepository)).rejects.toThrow(
      /retained scanner repository/i,
    );
    const otherId = structuredClone(input);
    otherId.findings[0]!.source_finding_id = "different-id";
    await expect(prepare(otherId)).rejects.toThrow(/source finding ID/i);
    await expect(
      prepareNormalizedLocalImport(
        input,
        { ...options, provider: "wiz" },
        dependencies,
      ),
    ).rejects.toThrow(/checkmarx provider/i);
    const unmarked = structuredClone(input);
    delete unmarked.report;
    delete unmarked.findings[0]!.evidence.source_data!["format"];
    const relabeled = () =>
      prepareNormalizedLocalImport(
        unmarked,
        { ...options, provider: "wiz" },
        dependencies,
      );
    await expect(relabeled()).rejects.toThrow(/checkmarx provider/i);
    delete unmarked.findings[0]!.evidence.source_data;
    expect((await relabeled()).preview.findings).toHaveLength(1);

    for (const change of [
      { scanId: "another-scan" },
      { sourceRepositoryUrl: "https://github.com/example/another" },
      {
        format:
          input.report!["format"] === "cxsast-xml"
            ? "checkmarx-one-json"
            : "cxsast-xml",
        projectId: "1",
      },
    ]) {
      await expect(
        prepare({ ...input, report: { ...input.report, ...change } }),
      ).rejects.toThrow(
        /retained Checkmarx report|does not match the retained report/i,
      );
    }
  }
  const typed = {
    read: 1,
    excluded: [],
    findings: [
      {
        source_finding_id: "sdk-id",
        evidence: { title: "Example", severity: "low" as const },
      },
    ],
  };
  expect((await prepare(typed)).preview.findings).toHaveLength(1);
  await expect(prepare({ ...typed, report: normal.report })).rejects.toThrow(
    /retained report/i,
  );
  const firstXml = xml("1");
  await expect(
    prepare({ ...firstXml, report: { ...firstXml.report, projectId: "2" } }),
  ).rejects.toThrow(/retained report/i);
  const empty = {
    ...normal,
    read: 0,
    findings: [],
    report: {
      ...normal.report,
      totalCount: 0,
      sourceRepositoryUrl: "https://github.com/example/another",
    },
  };
  await expect(prepare(empty)).rejects.toThrow(
    /does not match a configured remote/i,
  );
  const combined = [...xml("1").findings, ...xml("2").findings];
  await expect(
    prepare({ findings: combined, read: combined.length, excluded: [] }),
  ).rejects.toThrow(/same product and project/i);
});
