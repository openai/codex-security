import { expect, test } from "bun:test";
import { normalizeCheckmarxXml } from "../src/checkmarx-xml.js";

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

test("projects the ordered flow and retains native triage and snippets for each CxSAST result", () => {
  const output = normalize(report(result(13)));
  expect(output.read).toBe(1);
  expect(output.excluded).toEqual([]);
  const { evidence } = output.findings[0]!;
  expect(evidence).toMatchObject({
    title: "SQL_Injection",
    source_scan_id: "100",
    severity: "medium",
    locations: [
      { path: "src/input.ts", line: 5 },
      { path: "src/query.ts", line: 13 },
      { path: "src/db.ts", line: 22 },
    ],
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
  const nodes = evidence.source_data?.["nodes"] as Record<string, unknown>[];
  expect(nodes[1]).toMatchObject({
    FileName: "src/query.ts",
    Line: "13",
    Snippet: [{ Number: "13", Code: "work(a < b);" }],
  });
  expect(JSON.stringify(evidence)).not.toContain("report owner");
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
  expect(one.findings[0]?.evidence.locations).toEqual([
    { path: "src/app.ts", line: 7 },
  ]);
  for (const input of [
    "<Other/>",
    "<CxXMLResults/>",
    report(`<Results>${result(13)}</Results>`),
    report(result(13)).slice(0, -1),
  ])
    expect(() => normalize(input)).toThrow();
});
