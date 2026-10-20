import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { parseImportedFindings } from "../src/findings-import.js";
import type { FindingsDocument } from "../src/models.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { PYTHON } from "./support/security-policy.js";

const HEADER =
  "occurrence_id,finding_id,title,summary,severity,confidence,status," +
  "close_reason,note,remediation,path,start_line,end_line";
const ROW =
  "occ_000000000000000000000001,csf_000000000000000000000001," +
  "Reported issue,Reported summary,high,high,open,,," +
  "Check destinations.,src/extract.ts,41,44";
const ROWS = [
  ROW,
  ROW.replace("occ_000000000000000000000001", "occ_000000000000000000000002"),
];
const OCCURRENCE_IDS = ROWS.map((row) => row.split(",")[0]!);

describe("findings CSV record endings", () => {
  test.each([false, true])(
    "round-trips a large quoted field through the exporter (deep=%j)",
    async (deep) => {
      const document: FindingsDocument = JSON.parse(
        await readFile(
          join(PLUGIN_ROOT, "examples", "completed-scan", "findings.json"),
          "utf8",
        ),
      );
      // The closing quote falls beyond Papa Parse's newline-detection sample.
      const summary = "A\rB\rC\r" + "x".repeat(1024 * 1024);
      const finding = document.findings[0]!;
      document.findings = [
        { ...finding, summary, extensions: { candidateId: "candidate-one" } },
        {
          ...finding,
          occurrenceId: "occ_111111111111111111111111",
          summary: "Following ordinary summary.",
          extensions: { candidateId: "candidate-two" },
        },
      ];
      const csv = execFileSync(
        PYTHON,
        [
          "-c",
          [
            "import json, sys",
            "sys.path.insert(0, sys.argv[1])",
            "from finalize_scan_contract import build_csv_projection",
            "payload = json.load(sys.stdin.buffer)",
            'sys.stdout.buffer.write(build_csv_projection(payload["document"], payload["coverage"]))',
          ].join("\n"),
          join(PLUGIN_ROOT, "scripts"),
        ],
        {
          cwd: join(PLUGIN_ROOT, "scripts"),
          input: JSON.stringify({
            document,
            coverage: deep ? { mode: "deep_repository" } : {},
          }),
          encoding: "utf8",
          maxBuffer: 2 * 1024 * 1024,
        },
      );
      const header = deep
        ? HEADER.replace("finding_id,", "finding_id,candidate_id,")
        : HEADER;
      expect(csv.startsWith(`${header}\r\n${finding.occurrenceId},`)).toBe(
        true,
      );
      for (const prefix of ["", "\uFEFF"]) {
        const imported = await parseImportedFindings(
          prefix + csv,
          "csv",
          PLUGIN_ROOT,
        );
        expect(imported.map(({ summary }) => summary)).toEqual(
          document.findings.map(({ summary }) => summary),
        );
        expect(
          imported.map(({ findingId, occurrenceId }) => [
            findingId,
            occurrenceId,
          ]),
        ).toEqual(
          document.findings.map(({ findingId, occurrenceId }) => [
            findingId,
            occurrenceId,
          ]),
        );
        if (deep) {
          expect(
            imported.map((item) => item.extensions?.["candidateId"]),
          ).toEqual(["candidate-one", "candidate-two"]);
        }
      }
    },
  );

  test.each(["\r\n", "\n", "\r"])(
    "preserves canonical rows separated by %j",
    async (newline) => {
      const imported = await parseImportedFindings(
        [HEADER, ...ROWS, ""].join(newline),
        "csv",
        PLUGIN_ROOT,
      );
      expect(imported.map((finding) => finding.occurrenceId)).toEqual(
        OCCURRENCE_IDS,
      );
      expect(imported.map((finding) => finding.summary)).toEqual([
        "Reported summary",
        "Reported summary",
      ]);
    },
  );

  test("preserves external layouts and mixed endings with a skipped empty record", async () => {
    const columns = HEADER.split(",");
    const reordered = [1, 0, ...columns.slice(2).map((_, index) => index + 2)];
    const sources = [
      `${columns.map((column) => `"${column}"`).join(",")}\r\n${ROWS.join("\r\n")}\r\n`,
      `${reordered.map((index) => columns[index]).join(",")}\r\n${ROWS.map(
        (row) => {
          const values = row.split(",");
          return reordered.map((index) => values[index]).join(",");
        },
      ).join("\r\n")}\r\n`,
      `${HEADER}\r\n${ROWS.map((row) => row.replace(/^([^,]+)/u, '"$1"')).join("\r\n")}\r\n`,
      `${HEADER}\r\n\r${ROWS.join("\r")}\r`,
    ];
    for (const source of sources) {
      const imported = await parseImportedFindings(source, "csv", PLUGIN_ROOT);
      expect(imported.map((finding) => finding.occurrenceId)).toEqual(
        OCCURRENCE_IDS,
      );
      expect(imported.map((finding) => finding.summary)).toEqual([
        "Reported summary",
        "Reported summary",
      ]);
    }
  });
});
