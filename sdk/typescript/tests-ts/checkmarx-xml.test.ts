import { expect, test } from "bun:test";
import {
  checkmarxXmlId,
  checkmarxXmlScope,
  normalizeCheckmarxXml,
} from "../src/checkmarx-xml.js";

const repository = "https://github.com/example/sample";
const normalize = (xml: string) =>
  normalizeCheckmarxXml(xml, repository, "local");
const linkAttribute = (url?: string) =>
  url ? ` DeepLink="${url.replaceAll("&", "&amp;")}"` : "";
const node = (file: string, line: number, name: string) =>
  `<PathNode><FileName>${file}</FileName><Line>${line}</Line><Column>2</Column>
     <Name>${name}</Name><Type>Reference</Type><NodeId>1</NodeId>
     <Snippet><Line><Number>${line}</Number><Code><![CDATA[work(a < b);]]></Code></Line></Snippet>
   </PathNode>`;
const result = (middleLine: number, url?: string) =>
  `<Result${linkAttribute(url)} FileName="src/input.ts" Line="5" Column="2" Severity="Medium" Status="Recurrent" FalsePositive="True" state="1" NodeId="1001">
     <Path ResultId="100" PathId="1" SimilarityId="-17">
       ${node("src/input.ts", 5, "input")}
       ${node("src/query.ts", middleLine, "build")}
       ${node("src/db.ts", 22, "execute")}
     </Path>
   </Result>`;
const report = (results: string, url?: string) =>
  `<CxXMLResults${linkAttribute(url)} ScanId="100" ProjectId="8" Owner="report owner">
     <Query id="12" name="SQL_Injection" cweId="89" Severity="High">${results}</Query>
   </CxXMLResults>`;

test("retains native triage and ordered flow with snippets for each CxSAST result", () => {
  const output = normalize(report(result(13)));
  expect(output.read).toBe(1);
  expect(output.excluded).toEqual([]);
  const { evidence } = output.findings[0]!;
  expect(evidence).toMatchObject({
    title: "SQL_Injection",
    source_scan_id: "100",
    severity: "medium",
    locations: [],
    details: {
      repository: { url: repository },
      source_status: "Recurrent",
      scanner_verdict: "False positive",
      weakness_ids: ["CWE-89"],
    },
    source_data: {
      projectId: "8",
      query: { id: "12" },
      result: { NodeId: "1001", FalsePositive: "True", state: "1" },
      path: { SimilarityId: "-17" },
      nodes: [
        { FileName: "src/input.ts", Line: "5" },
        {
          FileName: "src/query.ts",
          Line: "13",
          Snippet: [{ Number: "13", Code: "work(a < b);" }],
        },
        { FileName: "src/db.ts", Line: "22" },
      ],
    },
  });
  expect(JSON.stringify(evidence)).not.toContain("report owner");
});

test("retains optional CxSAST project and team names without changing occurrence IDs", () => {
  const xml = report(result(13));
  const original = normalize(xml);
  const row = original.findings[0]!;
  const names = {
    projectName: "Source & API",
    teamFullPathOnReportDate: "CxServer\\SP\\Café",
  };
  for (const field of Object.keys(names)) {
    expect(original.report).not.toHaveProperty(field);
    expect(row.evidence.source_data).not.toHaveProperty(field);
  }
  const scoped = normalize(
    xml.replace(
      "<CxXMLResults ",
      '<CxXMLResults ProjectName="Source &amp; API" TeamFullPathOnReportDate="CxServer\\SP\\Café" ',
    ),
  );
  expect(scoped.report).toEqual({ ...original.report, ...names });
  expect(scoped.findings[0]!.evidence.source_data).toEqual({
    ...row.evidence.source_data,
    ...names,
  });
  expect(scoped.findings[0]!.source_finding_id).toBe(row.source_finding_id);
});

test("checks explicit scan, project and path IDs in native viewer links", () => {
  const viewer = "https://sast.example/CxWebClient/ViewerMain.aspx";
  const scanLink = viewer + "?projectid=8&scanid=100";
  const matching = scanLink + "&pathid=1";
  const rows = [
    matching,
    viewer + "?scanid=101",
    viewer + "?projectid=9",
    viewer + "?pathid=2",
  ].map((link) => result(13, link));
  const output = normalize(report(rows.join(""), scanLink));
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]!.evidence.source_data).toMatchObject({
    result: { DeepLink: matching },
  });
  expect(output.excluded).toMatchObject([
    { position: 2, reason: expect.stringContaining("DeepLink") },
    { position: 3, reason: expect.stringContaining("DeepLink") },
    { position: 4, reason: expect.stringContaining("DeepLink") },
  ]);
  const noPathId = result(13, matching).replace('PathId="1"', "");
  expect(normalize(report(noPathId)).excluded).toEqual([]);
  expect(checkmarxXmlScope({ result: { DeepLink: matching } })).toEqual({
    instance: "https://sast.example",
    scanId: "100",
    projectId: "8",
  });
  for (const field of ["scanid", "projectid", "pathid"]) {
    const DeepLink = viewer + `?${field}=1&${field.toUpperCase()}=2`;
    expect(() => checkmarxXmlScope({ result: { DeepLink } })).toThrow(
      /DeepLink/u,
    );
  }
  const unrelated = "https://sast.example/issue?scanid=101";
  expect(normalize(report(result(13, unrelated))).excluded).toEqual([]);
  expect(() => normalize(report("", viewer + "?scanid=101"))).toThrow(
    /DeepLink/u,
  );
});

test("requires all known CxSAST viewer instances to agree", () => {
  const instance = "https://sast.example/tenant";
  const viewer = instance + "/CxWebClient/ViewerMain.aspx";
  const linked = result(13, viewer + "?pathid=1");
  const unlinked = result(15);
  for (const xml of [
    report(unlinked, viewer),
    report(linked + unlinked),
    report(unlinked + linked),
  ]) {
    const parsed = normalize(xml);
    expect(parsed.excluded).toEqual([]);
    expect(parsed.report?.["instance"]).toBe(instance);
    for (const { evidence } of parsed.findings)
      expect(evidence.source_data?.["instance"]).toBe(instance);
  }
  for (const other of [
    viewer.replace("sast.example", "other.example"),
    viewer.replace("/tenant/", "/other/"),
  ]) {
    expect(() => normalize(report(linked, other))).toThrow(/same instance/u);
    expect(() =>
      normalize(report(linked + unlinked + result(19, other))),
    ).toThrow(/same instance/u);
  }
});

test("compares retained CxSAST instance URLs without rewriting the evidence", () => {
  const viewer = "https://sast.example/Team/CxWebClient/ViewerMain.aspx";
  const row = normalize(report(result(13, viewer))).findings[0]!;
  const instance = "https://SAST.EXAMPLE:443/Team";
  const retained = { ...row.evidence.source_data, instance };
  expect(checkmarxXmlScope(retained).instance).toBe(instance);
  expect(checkmarxXmlId(retained)).toBe(row.source_finding_id);
  for (const different of [
    "https://sast.example/team",
    "https://sast.example/Team/other",
    "https://sast.example:8443/Team",
  ]) {
    expect(() =>
      checkmarxXmlScope({ ...retained, instance: different }),
    ).toThrow(/same instance/u);
  }
});

test("excluded results cannot select the instance of a linkless report", () => {
  const unlinked = result(15);
  const viewer = "https://other.example/CxWebClient/ViewerMain.aspx";
  const wrongScan = result(17, viewer + "?scanid=999");
  const duplicate = result(19, viewer + "?scanid=100");
  const parsed = normalize(
    report(wrongScan + duplicate + unlinked + duplicate),
  );
  expect(parsed.excluded.map((item) => item.position)).toEqual([1, 2, 4]);
  expect(parsed.findings).toHaveLength(1);
  expect(parsed.report).not.toHaveProperty("instance");
  expect(parsed.findings[0]!.evidence.source_data).not.toHaveProperty(
    "instance",
  );
});

test("retains distinct intermediate paths and replays their identity across scans", () => {
  const first = result(13);
  const other = result(19);
  const original = normalize(report(first + other));
  expect(original.excluded).toEqual([]);
  const ids = original.findings.map((finding) => finding.source_finding_id);
  expect(new Set(ids).size).toBe(2);
  const changed = report(other + first)
    .replaceAll('="100"', '="200"')
    .replaceAll('PathId="1"', 'PathId="42"')
    .replaceAll('NodeId="1001"', 'NodeId="2001"')
    .replaceAll('Severity="Medium"', 'Severity="Low"');
  expect(
    normalize(changed).findings.map((finding) => finding.source_finding_id),
  ).toEqual(ids.toReversed());
  const overlap = normalize(report(first + other + first + "<Result/>"));
  expect(overlap.read).toBe(4);
  expect(overlap.findings.map((finding) => finding.source_finding_id)).toEqual([
    ids[1]!,
  ]);
  expect(overlap.excluded).toMatchObject([
    { position: 1, source_finding_id: ids[0] },
    { position: 3, source_finding_id: ids[0] },
    { position: 4, source_finding_id: null },
  ]);
});

test("retains project-wide results and paths without nodes", () => {
  const projectWide =
    '<Result FileName="" Line="1"><Path SimilarityId="17"><PathNode><FileName/><Line>1</Line><Column>0</Column></PathNode></Path></Result>';
  const emptyPath =
    '<Result FileName="src/app.ts" Line="7"><Path SimilarityId="-3"/></Result>';
  const output = normalize(report(projectWide + emptyPath));
  expect(output.excluded).toEqual([]);
  expect(output.findings.map(({ evidence }) => evidence.locations)).toEqual([
    [],
    [],
  ]);
  expect(output.findings[1]?.evidence.source_data).toMatchObject({
    result: { FileName: "src/app.ts", Line: "7" },
    nodes: [],
  });
});

test("handles empty reports and rejects other XML and truncated reports", () => {
  expect(normalize('<CxXMLResults ScanId="100" ProjectId="8"/>')).toMatchObject(
    {
      read: 0,
      findings: [],
      excluded: [],
      report: { scanId: "100", projectId: "8" },
    },
  );
  for (const input of [
    "<Other/>",
    "<CxXMLResults/>",
    report(`<Results>${result(13)}</Results>`),
    report(result(13)).slice(0, -1),
  ])
    expect(() => normalize(input)).toThrow();
});
