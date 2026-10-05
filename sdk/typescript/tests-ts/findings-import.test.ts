import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import {
  bindImportedFindings,
  parseImportedFindings,
} from "../src/findings-import.js";
import type { Finding, FindingsDocument } from "../src/models.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { PYTHON } from "./support/security-policy.js";

const BYTE_ORDER_MARK = "\uFEFF";
const CSV_SOURCE =
  "occurrence_id,finding_id,title,summary,severity,confidence,status," +
  "close_reason,note,remediation,path,start_line,end_line\r\n" +
  "occ_000000000000000000000001,csf_000000000000000000000001," +
  "Reported CSV import issue,Reported summary,high,high,open,,," +
  "Validate archive entry destinations.,src/extract.ts,41,44\r\n";

async function sourceDocument(): Promise<FindingsDocument> {
  return JSON.parse(
    await readFile(
      join(PLUGIN_ROOT, "examples", "completed-scan", "findings.json"),
      "utf8",
    ),
  );
}

function exportCsv(findings: Finding[]): string {
  return execFileSync(
    PYTHON,
    [
      "-c",
      "import json, sys; sys.path.insert(0, sys.argv[1]); from finalize_scan_contract import build_csv_projection; sys.stdout.buffer.write(build_csv_projection(json.load(sys.stdin.buffer), {}))",
      join(PLUGIN_ROOT, "scripts"),
    ],
    {
      cwd: join(PLUGIN_ROOT, "scripts"),
      input: JSON.stringify({ findings }),
      encoding: "utf8",
    },
  );
}

describe("findings import formats", () => {
  test("retains distinct occurrences of a shared finding in CSV and JSON", async () => {
    const {
      findings: [finding],
    } = await sourceDocument();
    const rows = [
      finding!,
      { ...finding!, occurrenceId: "occ_111111111111111111111111" },
    ];
    for (const format of ["csv", "json"] as const) {
      const source =
        format === "csv" ? exportCsv(rows) : JSON.stringify({ findings: rows });
      const parsed = await parseImportedFindings(source, format, PLUGIN_ROOT);
      expect(
        parsed.map(({ findingId, occurrenceId }) => [findingId, occurrenceId]),
      ).toEqual(
        rows.map(({ findingId, occurrenceId }) => [findingId, occurrenceId]),
      );
      expect(
        new Set(
          bindImportedFindings(parsed, format, "scan", "target").map(
            (row) => row.occurrenceId,
          ),
        ).size,
      ).toBe(2);
    }
    await expect(
      parseImportedFindings(
        exportCsv([finding!, finding!]),
        "csv",
        PLUGIN_ROOT,
      ),
    ).rejects.toThrow("duplicate occurrence_id");
  });

  test("round-trips literal apostrophes and spreadsheet escapes through the exporter", async () => {
    const {
      findings: [finding],
    } = await sourceDocument();
    const values = [
      "'--no-verify' skips hooks",
      "''=literal",
      "'Literal",
      "ordinary λ",
      "=formula",
      "\u0085=formula",
      "\u001c=formula",
      "\u001d=formula",
      "\u001e=formula",
      "\u001f=formula",
      "\uFEFF=formula",
      " +formula",
      "-option",
      "@owner",
      "\tTabbed",
      "\nNewline",
      "  ＝wide",
      " ＋wide",
      "－wide",
      "＠wide",
    ];
    for (const value of values) {
      const source = {
        ...finding!,
        title: value,
        summary: value,
        remediation: value,
        locations: [
          {
            path: value.replace(/[\u0000-\u001F]/gu, "") + ".ts",
            startLine: 1,
          },
        ],
      };
      const [imported] = await parseImportedFindings(
        exportCsv([source]),
        "csv",
        PLUGIN_ROOT,
      );
      expect(imported).toMatchObject({
        title: source.title,
        summary: source.summary,
        remediation: source.remediation,
        locations: source.locations,
      });
    }
  });

  test("retains a literal apostrophe before a non-whitespace byte order mark", async () => {
    const title = "'\uFEFF=formula";
    const [imported] = await parseImportedFindings(
      CSV_SOURCE.replace("Reported CSV import issue", title),
      "csv",
      PLUGIN_ROOT,
    );

    expect(imported!.title).toBe(title);
  });

  test("accepts full findings documents and findings-service payloads", async () => {
    const document = await sourceDocument();
    document.findings[0]!.summary =
      'Full description\nwith "quotes", commas, and unicode: λ.';
    const payloads = [document, { findings: document.findings }];
    for (const payload of payloads) {
      expect(
        await parseImportedFindings(
          JSON.stringify(payload),
          "json",
          PLUGIN_ROOT,
        ),
      ).toEqual(document.findings);
    }
    expect(
      await parseImportedFindings('{"findings":[]}', "json", PLUGIN_ROOT),
    ).toEqual([]);
  });

  test("accepts a UTF-8 byte order mark in either import format", async () => {
    const document = await sourceDocument();
    expect(
      await parseImportedFindings(
        `${BYTE_ORDER_MARK}${JSON.stringify(document)}`,
        "json",
        PLUGIN_ROOT,
      ),
    ).toEqual(document.findings);
    const csv = await parseImportedFindings(
      `${BYTE_ORDER_MARK}${CSV_SOURCE}`,
      "csv",
      PLUGIN_ROOT,
    );
    expect(csv).toHaveLength(1);
    expect(csv[0]!.title).toBe("Reported CSV import issue");
  });

  test("binds separate source occurrences and retains source metadata without following report paths", async () => {
    const document = await sourceDocument();
    const finding = document.findings[0]!;
    finding.writeup = { reportPath: "findings/source-report/source-report.md" };
    finding.extensions = {
      candidateId: "ISSUE-42",
      import: { sourceSystem: "synthetic" },
    };
    const sibling: Finding = {
      ...structuredClone(finding),
      occurrenceId: "occ_111111111111111111111111",
    };
    const source = JSON.stringify({ findings: [finding, sibling] });
    const parsed = await parseImportedFindings(source, "json", PLUGIN_ROOT);
    const bound = bindImportedFindings(parsed, "json", "scan_first", "dataset");
    const rerun = bindImportedFindings(
      parsed,
      "json",
      "scan_second",
      "dataset",
    );
    expect(new Set(bound.map((row) => row.findingId)).size).toBe(2);
    expect(new Set(bound.map((row) => row.occurrenceId)).size).toBe(2);
    expect(bound.map((row) => row.findingId)).toEqual(
      rerun.map((row) => row.findingId),
    );
    expect(bound[0]!.occurrenceId).not.toBe(rerun[0]!.occurrenceId);
    expect(bound[0]).toMatchObject({
      ruleId: "import.json",
      identity: { anchor: finding.occurrenceId },
      title: finding.title,
      summary: finding.summary,
      locations: finding.locations,
      provenance: { source: "json_import" },
      extensions: {
        candidateId: "ISSUE-42",
        import: {
          format: "json",
          sourceFindingId: finding.findingId,
          sourceOccurrenceId: finding.occurrenceId,
          sourceRuleId: finding.ruleId,
          sourceIdentity: finding.identity,
          sourceFingerprints: finding.fingerprints,
          sourceProvenance: finding.provenance,
          sourceWriteup: finding.writeup,
          previousImport: { sourceSystem: "synthetic" },
        },
      },
    });
    expect(bound[0]).not.toHaveProperty("writeup");
    expect(parsed[0]!.writeup).toEqual(finding.writeup);
    expect(JSON.stringify({ findings: parsed })).toBe(source);
  });

  test("rejects malformed JSON, noncanonical finding shapes, and repeated source occurrences", async () => {
    const document = await sourceDocument();
    const invalidPayloads = [
      { ...document, schemaVersion: "2.0" },
      { findings: [{ title: "Missing finding fields" }] },
      document.findings,
      {
        findings: [{ ...document.findings[0], severity: { level: "urgent" } }],
      },
    ];
    for (const payload of invalidPayloads) {
      await expect(
        parseImportedFindings(JSON.stringify(payload), "json", PLUGIN_ROOT),
      ).rejects.toThrow("Findings JSON");
    }
    await expect(
      parseImportedFindings("{", "json", PLUGIN_ROOT),
    ).rejects.toThrow("could not be parsed");
    await expect(
      parseImportedFindings(
        JSON.stringify({
          findings: [document.findings[0], document.findings[0]],
        }),
        "json",
        PLUGIN_ROOT,
      ),
    ).rejects.toThrow("duplicate occurrenceId");
  });
});
import { execFileSync } from "node:child_process";
