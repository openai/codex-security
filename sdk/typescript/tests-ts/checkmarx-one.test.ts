import { expect, test } from "bun:test";
import { normalizeCheckmarxOne } from "../src/checkmarx-one.js";

const repository = "https://github.com/example/sample";
const scanID = "71000000-0000-4000-8000-000000000001";
const sast = {
  type: "sast",
  id: "101",
  similarityId: "-2001",
  status: "RECURRENT",
  state: "TO_VERIFY",
  severity: "HIGH",
  description: "Input flows to the database call.",
  data: {
    queryId: 101,
    queryName: "SQL_Injection",
    resultHash: "cGF0aC1vbmU=",
    nodes: [
      { fileName: "/src/input.ts", line: 12, column: 3 },
      { fileName: "/src/database.ts", line: 27, column: 5 },
    ],
  },
  vulnerabilityDetails: { cweId: 89 },
};

function report(results: unknown[]) {
  return JSON.stringify({ scanID, results, totalCount: results.length });
}

test("retains native SAST flow and vendor triage from mixed-engine CLI JSON", () => {
  // A query ID emitted as a JSON integer can exceed JavaScript's exact range.
  const contents = report([{ type: "sca" }, sast, { type: "kics" }]).replace(
    '"queryId":101',
    '"queryId":9007199254740993',
  );
  const normalized = normalizeCheckmarxOne(contents, repository, "local");
  expect(normalized.read).toBe(3);
  expect(normalized.excluded.map(({ position }) => position)).toEqual([1, 3]);
  expect(normalized.findings).toHaveLength(1);
  expect(normalized.findings[0]!.evidence).toMatchObject({
    title: "SQL_Injection",
    severity: "high",
    description: sast.description,
    source_scan_id: scanID,
    locations: [],
    details: {
      repository: { url: repository },
      source_status: "RECURRENT",
      scanner_verdict: "TO_VERIFY",
      rule: { id: "9007199254740993" },
      weakness_ids: ["CWE-89"],
    },
    source_data: {
      row: { ...sast, data: { ...sast.data, queryId: "9007199254740993" } },
    },
  });
});

test("separates paths sharing a similarity ID and excludes every exact identity collision", () => {
  const anotherPath = {
    ...sast,
    data: { ...sast.data, resultHash: "cGF0aC10d28=" },
  };
  const initial = normalizeCheckmarxOne(
    report([sast, anotherPath]),
    repository,
    "local",
  );
  expect(initial.excluded).toEqual([]);
  const firstId = initial.findings[0]!.source_finding_id;
  const secondId = initial.findings[1]!.source_finding_id;
  expect(firstId).not.toBe(secondId);
  const changed = normalizeCheckmarxOne(
    report([{ ...sast, id: "202", severity: "MEDIUM" }]).replace(
      scanID,
      "71000000-0000-4000-8000-000000000002",
    ),
    repository,
    "local",
  );
  expect(changed.findings[0]!.source_finding_id).toBe(firstId);
  const overlap = normalizeCheckmarxOne(
    report([sast, anotherPath, sast]),
    repository,
    "local",
  );
  expect(overlap.findings.map((f) => f.source_finding_id)).toEqual([secondId]);
  expect(overlap.excluded).toMatchObject([
    { position: 1, source_finding_id: firstId },
    { position: 3, source_finding_id: firstId },
  ]);
});

test("rejects partial and other JSON formats while accepting the CLI's empty collection", () => {
  for (const results of [[], null]) {
    expect(
      normalizeCheckmarxOne(
        JSON.stringify({ scanID, results, totalCount: 0 }),
        repository,
        "local",
      ),
    ).toMatchObject({
      read: 0,
      findings: [],
      excluded: [],
    });
  }
  for (const document of [
    { results: [], totalCount: 0 },
    { scanID, totalCount: 0 },
    { scanID, results: [sast], totalCount: 2 },
    { scanID, results: null, totalCount: 3 },
    { ScanSummary: {}, ScanResults: [] },
  ]) {
    expect(() =>
      normalizeCheckmarxOne(JSON.stringify(document), repository, "local"),
    ).toThrow();
  }
});

test("reports malformed SAST identities and evidence at their original positions", () => {
  const malformed = normalizeCheckmarxOne(
    report([
      { ...sast, similarityId: "" },
      { ...sast, data: { ...sast.data, resultHash: null } },
      {
        ...sast,
        data: { ...sast.data, resultHash: "another-hash", nodes: {} },
      },
      sast,
    ]),
    repository,
    "local",
  );
  expect(malformed.read).toBe(4);
  expect(malformed.findings).toHaveLength(1);
  expect(malformed.excluded).toMatchObject([
    {
      position: 1,
      source_finding_id: null,
      reason: expect.stringContaining("similarityId"),
    },
    {
      position: 2,
      source_finding_id: null,
      reason: expect.stringContaining("resultHash"),
    },
    {
      position: 3,
      source_finding_id: expect.any(String),
      reason: expect.stringContaining("nodes"),
    },
  ]);
});
