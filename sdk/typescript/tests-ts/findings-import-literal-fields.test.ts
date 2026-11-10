import { expect, test } from "bun:test";
import {
  bindImportedFindings,
  parseImportedFindings,
} from "../src/findings-import.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

function csvSource(fields: Record<string, string> = {}): string {
  const row = {
    occurrence_id: "occ_000000000000000000000001",
    finding_id: "csf_000000000000000000000001",
    title: "Synthetic finding",
    summary: "Reported summary",
    severity: "high",
    confidence: "high",
    status: "open",
    close_reason: "",
    note: "",
    remediation: "Validate the input.",
    path: "source.ts",
    start_line: "1",
    end_line: "",
    ...fields,
  };
  return (
    [Object.keys(row), Object.values(row)]
      .map((cells) =>
        cells.map((cell) => `"${cell.replaceAll('"', '""')}"`).join(","),
      )
      .join("\r\n") + "\r\n"
  );
}

test.each(
  (["title", "summary", "remediation"] as const).flatMap((field) =>
    [" \t\r\n", "\u0085", "\u001c\u001d\u001e\u001f"].map(
      (value) => [field, value] as const,
    ),
  ),
)("rejects canonical whitespace in CSV %s %j", async (field, value) => {
  await expect(
    parseImportedFindings(csvSource({ [field]: value }), "csv", PLUGIN_ROOT),
  ).rejects.toThrow(`requires ${field}`);
});

test.each([" ", "  ", "\u00A0", "\u2003", "\u2028", "\u2029", "\uFEFF"])(
  "preserves the literal CSV path %j",
  async (path) => {
    const [finding] = await parseImportedFindings(
      csvSource({ path }),
      "csv",
      PLUGIN_ROOT,
    );
    expect(finding!.locations[0]!.path).toBe(path);
  },
);

test.each([
  "",
  ".",
  "..",
  "../source.ts",
  "dir/../source.ts",
  "/source.ts",
  "C:source.ts",
  "C:/source.ts",
  "dir\\source.ts",
  "\t",
  "\n",
  "\0",
])("still rejects an unsafe or empty CSV path %j", async (path) => {
  await expect(
    parseImportedFindings(csvSource({ path }), "csv", PLUGIN_ROOT),
  ).rejects.toThrow("has an invalid path");
});

test.each([
  [undefined, undefined],
  ["", undefined],
  [" \t\r\n\u00A0", undefined],
  ["candidate-1", "candidate-1"],
  ["  candidate-1  ", "  candidate-1  "],
  ["\u0085", "\u0085"],
  ["\u001C\u001D\u001E\u001F", "\u001C\u001D\u001E\u001F"],
  ["\uFEFF", "\uFEFF"],
  [" \t\uFEFF \t", " \t\uFEFF \t"],
  ["\uFEFF\uFEFF", "\uFEFF\uFEFF"],
] as const)("preserves optional candidate ID %j", async (value, expected) => {
  const source = csvSource(value === undefined ? {} : { candidate_id: value });
  for (const bom of ["", "\uFEFF"]) {
    const parsed = await parseImportedFindings(
      bom + source,
      "csv",
      PLUGIN_ROOT,
    );
    const bound = bindImportedFindings(parsed, "csv", "scan", "target");
    for (const finding of [parsed[0]!, bound[0]!]) {
      expect(finding.extensions?.["candidateId"]).toBe(expected);
    }
  }
});

test.each([
  ["", undefined],
  [" \t\r\n\u00A0", undefined],
  ["  ordinary λ  ", "  ordinary λ  "],
  ["\uFEFF", "\uFEFF"],
  [" \t\uFEFF \t", " \t\uFEFF \t"],
  ["\u0085", "\u0085"],
  ["\u001C\u001D\u001E\u001F", "\u001C\u001D\u001E\u001F"],
  ["'\u0085=formula", "\u0085=formula"],
  ["'\uFEFF=formula", "'\uFEFF=formula"],
] as const)("preserves original decoded note %j", async (note, expected) => {
  for (const closeReason of [
    "",
    "already_fixed",
    "false_positive",
    "wont_fix",
  ]) {
    const parsed = parseImportedFindings(
      "\uFEFF" +
        csvSource({
          note,
          status: closeReason === "" ? "open" : "closed",
          close_reason: closeReason,
        }),
      "csv",
      PLUGIN_ROOT,
    );
    if (
      expected === undefined &&
      ["false_positive", "wont_fix"].includes(closeReason)
    ) {
      await expect(parsed).rejects.toThrow(
        "requires a note for its close_reason",
      );
      continue;
    }
    const [finding] = bindImportedFindings(
      await parsed,
      "csv",
      "scan",
      "target",
    );
    if (expected === undefined) {
      expect(finding!.validation!.summary).not.toContain("Source note:");
    } else {
      expect(finding!.validation!.summary).toEndWith(
        `Source note: ${expected}`,
      );
    }
  }
});
