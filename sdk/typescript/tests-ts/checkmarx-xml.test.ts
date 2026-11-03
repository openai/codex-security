import { expect, test } from "bun:test";
import {
  checkmarxXmlId,
  checkmarxXmlScope,
  normalizeCheckmarxXml,
} from "../src/checkmarx-xml.js";

const repository = "https://github.com/example/sample";
const normalize = (xml: string) =>
  normalizeCheckmarxXml(xml, repository, "local");
const node = (file: string, line: number, name: string) =>
  `<PathNode><FileName>${file}</FileName><Line>${line}</Line><Column>2</Column>
     <Name>${name}</Name><Type>Reference</Type><NodeId>1</NodeId>
     <Snippet><Line><Number>${line}</Number><Code><![CDATA[work(a < b);]]></Code></Line></Snippet>
   </PathNode>`;
const result = (middleLine: number) =>
  `<Result FileName="src/input.ts" Line="5" Column="2" Severity="Medium" Status="Recurrent" FalsePositive="True" state="1" NodeId="1001">
     <Path ResultId="100" PathId="1" SimilarityId="-17">
       ${node("src/input.ts", 5, "input")}
       ${node("src/query.ts", middleLine, "build")}
       ${node("src/db.ts", 22, "execute")}
     </Path>
   </Result>`;
const report = (results: string) =>
  `<CxXMLResults ScanId="100" ProjectId="8" Owner="report owner">
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
    },
  });
  expect(evidence.source_data?.["nodes"]).toMatchObject([
    { FileName: "src/input.ts", Line: "5" },
    {
      FileName: "src/query.ts",
      Line: "13",
      Snippet: [{ Number: "13", Code: "work(a < b);" }],
    },
    { FileName: "src/db.ts", Line: "22" },
  ]);
  expect(JSON.stringify(evidence)).not.toContain("report owner");
});

const withLink = (xml: string, tag: string, link: string) =>
  xml.replace(
    `<${tag} `,
    `<${tag} DeepLink="${link.replaceAll("&", "&amp;")}" `,
  );

test("checks explicit scan, project and path IDs in native viewer links", () => {
  const viewer = "https://sast.example/CxWebClient/ViewerMain.aspx";
  const matching = viewer + "?pathid=1&projectid=8&scanid=100";
  const rows = [
    matching,
    viewer + "?scanid=101",
    viewer + "?projectid=9",
    viewer + "?pathid=2",
  ].map((link) => withLink(result(13), "Result", link));
  const output = normalize(
    withLink(
      report(rows.join("")),
      "CxXMLResults",
      viewer + "?scanid=100&projectid=8",
    ),
  );
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]!.evidence.source_data).toMatchObject({
    result: { DeepLink: matching },
  });
  expect(output.excluded).toMatchObject([
    { position: 2, reason: expect.stringContaining("DeepLink") },
    { position: 3, reason: expect.stringContaining("DeepLink") },
    { position: 4, reason: expect.stringContaining("DeepLink") },
  ]);
  const data = output.findings[0]!.evidence.source_data!;
  expect(() =>
    checkmarxXmlId(
      { ...data, result: { DeepLink: viewer + "?pathid=2" } },
      "100",
    ),
  ).toThrow(/DeepLink/u);
  expect(
    normalize(
      report(
        withLink(result(13).replace('PathId="1"', ""), "Result", matching),
      ),
    ).excluded,
  ).toEqual([]);
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
  expect(
    normalize(report(withLink(result(13), "Result", unrelated))).excluded,
  ).toEqual([]);
  expect(() =>
    normalize(withLink(report(""), "CxXMLResults", viewer + "?scanid=101")),
  ).toThrow(/DeepLink/u);
});

test("requires all known CxSAST viewer instances to agree", () => {
  const viewer = "https://sast.example/tenant/CxWebClient/ViewerMain.aspx";
  const linked = withLink(result(13), "Result", viewer + "?pathid=1");
  const unlinked = result(15);
  for (const xml of [
    withLink(report(unlinked), "CxXMLResults", viewer),
    report(linked + unlinked),
    report(unlinked + linked),
  ]) {
    const parsed = normalize(xml);
    expect(parsed.excluded).toEqual([]);
    expect(parsed.report).toMatchObject({
      instance: "https://sast.example/tenant",
    });
    for (const { evidence } of parsed.findings)
      expect(evidence.source_data?.["instance"]).toBe(
        "https://sast.example/tenant",
      );
  }
  for (const other of [
    viewer.replace("sast.example", "other.example"),
    viewer.replace("/tenant/", "/other/"),
  ]) {
    expect(() =>
      normalize(withLink(report(linked), "CxXMLResults", other)),
    ).toThrow(/same instance/u);
    expect(() =>
      normalize(
        report(linked + unlinked + withLink(result(19), "Result", other)),
      ),
    ).toThrow(/same instance/u);
  }
});

test("compares retained CxSAST instance URLs without rewriting the evidence", () => {
  const viewer = "https://sast.example/Team/CxWebClient/ViewerMain.aspx";
  const row = normalize(report(withLink(result(13), "Result", viewer)))
    .findings[0]!;
  const instance = "https://SAST.EXAMPLE:443/Team";
  const retained = { ...row.evidence.source_data, instance };
  expect(checkmarxXmlScope(retained).instance).toBe(instance);
  expect(checkmarxXmlId(retained, "100")).toBe(row.source_finding_id);
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
  const wrongScan = withLink(result(17), "Result", viewer + "?scanid=999");
  const duplicate = withLink(result(19), "Result", viewer + "?scanid=100");
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

test("imports a project-wide result without a source location", () => {
  const output = normalize(
    report(
      '<Result FileName="" Line="1"><Path SimilarityId="17"><PathNode><FileName/><Line>1</Line><Column>0</Column></PathNode></Path></Result>',
    ),
  );
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]?.evidence.locations).toEqual([]);
});

test("handles empty reports and empty paths; rejects other XML and truncated reports", () => {
  expect(normalize('<CxXMLResults ScanId="100" ProjectId="8"/>')).toMatchObject(
    {
      read: 0,
      findings: [],
      excluded: [],
      report: { scanId: "100", projectId: "8" },
    },
  );
  const one = normalize(
    report(
      '<Result FileName="src/app.ts" Line="7"><Path SimilarityId="-3"/></Result>',
    ),
  );
  expect(one.findings[0]?.evidence).toMatchObject({
    locations: [],
    source_data: { result: { FileName: "src/app.ts", Line: "7" }, nodes: [] },
  });
  for (const input of [
    "<Other/>",
    "<CxXMLResults/>",
    report(`<Results>${result(13)}</Results>`),
    report(result(13)).slice(0, -1),
  ])
    expect(() => normalize(input)).toThrow();
});
