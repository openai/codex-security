import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isAbsolute, join, posix } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import { z } from "incur";
import Papa from "papaparse";
import { CodexSecurityError } from "./errors.js";
import type { Finding, FindingsDocument } from "./models.js";

export const CSV_TARGET_ID = "codex-security-csv-import";
export type FindingsImportFormat = "csv" | "json";

const EXPORTED_CSV_ESCAPE = /^'(?:[\t\r\n]|\s*[=+\-@＝＋－＠])/u;
const csvFindingRowSchema = z
  .object({
    occurrence_id: z.string().regex(/^occ_[a-f0-9]{24}$/u, {
      error: "has an invalid occurrence_id",
    }),
    finding_id: z.string().regex(/^csf_[a-f0-9]{24}$/u, {
      error: "has an invalid finding_id",
    }),
    candidate_id: z
      .string()
      .optional()
      .transform((value) =>
        value === undefined || value.trim() === "" ? undefined : value,
      ),
    title: requiredCsvText("title"),
    summary: requiredCsvText("summary"),
    severity: z.enum(["critical", "high", "medium", "low", "informational"], {
      error: "has an invalid severity",
    }),
    confidence: z.enum(["high", "medium", "low"], {
      error: "has an invalid confidence",
    }),
    status: z.enum(["open", "closed"], {
      error: "has an invalid status",
    }),
    close_reason: z
      .union(
        [
          z.literal(""),
          z.enum(["already_fixed", "wont_fix", "false_positive"]),
        ],
        { error: "has an invalid close_reason" },
      )
      .transform((value) => (value === "" ? undefined : value)),
    note: z
      .string()
      .transform((value) => (value.trim() === "" ? undefined : value)),
    remediation: requiredCsvText("remediation"),
    path: z.string().refine(safeFindingPath, {
      error: "has an invalid path",
    }),
    start_line: z
      .string()
      .refine(validCsvLine, { error: "has an invalid start_line" })
      .transform(Number),
    end_line: z
      .string()
      .refine((value) => value === "" || validCsvLine(value), {
        error: "has an invalid end_line",
      })
      .transform((value) => (value === "" ? undefined : Number(value))),
  })
  .superRefine((row, context) => {
    if (
      (row.status === "open" && row.close_reason !== undefined) ||
      (row.status === "closed" && row.close_reason === undefined)
    ) {
      context.addIssue({
        code: "custom",
        path: ["close_reason"],
        message: "has an invalid close_reason",
      });
    }
    if (
      row.status === "closed" &&
      (row.close_reason === "false_positive" ||
        row.close_reason === "wont_fix") &&
      row.note === undefined
    ) {
      context.addIssue({
        code: "custom",
        path: ["note"],
        message: "requires a note for its close_reason",
      });
    }
    if (row.end_line !== undefined && row.end_line < row.start_line) {
      context.addIssue({
        code: "custom",
        path: ["end_line"],
        message: "has end_line before start_line",
      });
    }
  });
type CsvFindingRow = z.infer<typeof csvFindingRowSchema>;
type CsvColumn = keyof typeof csvFindingRowSchema.shape;
const CSV_COLUMNS = Object.keys(csvFindingRowSchema.shape) as CsvColumn[];
const REQUIRED_CSV_COLUMNS = CSV_COLUMNS.filter(
  (column) => !csvFindingRowSchema.shape[column].isOptional(),
);

export async function parseImportedFindings(
  source: string,
  format: FindingsImportFormat,
  pluginRoot: string,
): Promise<Finding[]> {
  if (format === "csv") {
    return parseFindingsCsv(source).map((row) => ({
      ...csvRowFinding(row, "import"),
      findingId: row.finding_id,
      occurrenceId: row.occurrence_id,
    }));
  }

  let payload: unknown;
  try {
    // Exported findings files often start with a UTF-8 byte order mark, which
    // the CSV parser already skips.
    payload = JSON.parse(source.replace(/^\uFEFF/u, ""));
  } catch (error) {
    throw new CodexSecurityError("Findings JSON could not be parsed.", {
      cause: error,
    });
  }
  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    throw new CodexSecurityError(
      "Findings JSON must contain a findings document or an object with a findings array.",
    );
  }
  const hasDocumentMetadata = ["documentType", "schemaVersion", "scanId"].some(
    (key) => Object.hasOwn(payload, key),
  );
  const document = hasDocumentMetadata
    ? payload
    : {
        documentType: "codex-security.findings",
        schemaVersion: "1.0",
        scanId: "import",
        ...payload,
      };
  const schema = JSON.parse(
    await readFile(join(pluginRoot, "schemas", "findings.schema.json"), "utf8"),
  );
  const validate = new Ajv2020({ strict: false }).compile<FindingsDocument>(
    schema,
  );
  if (!validate(document)) {
    const error = validate.errors?.[0];
    throw new CodexSecurityError(
      `Findings JSON does not match the Codex Security findings schema${error ? ` at ${error.instancePath || "/"}: ${error.message}` : ""}.`,
    );
  }
  const occurrenceIds = new Set<string>();
  for (const [index, finding] of document.findings.entries()) {
    if (occurrenceIds.has(finding.occurrenceId)) {
      throw new CodexSecurityError(
        `Findings JSON finding ${index + 1} has a duplicate occurrenceId.`,
      );
    }
    occurrenceIds.add(finding.occurrenceId);
  }
  return document.findings;
}

export function bindImportedFindings(
  findings: Finding[],
  format: FindingsImportFormat,
  scanId: string,
  targetId: string,
): Finding[] {
  return findings.map((finding) => {
    const ruleId = `import.${format}`;
    const anchor = finding.occurrenceId;
    const fingerprint = `codex-security/v1:sha256:${sha256(
      ["codex-security/v1", targetId, ruleId, anchor, ""].join("\0"),
    )}`;
    // A source report path names another scan's artifact. Preserve it as
    // provenance without treating the imported path as permission to read it.
    const { writeup, ...content } = finding;
    return {
      ...content,
      findingId: `csf_${sha256(fingerprint).slice(0, 24)}`,
      occurrenceId: `occ_${sha256([scanId, fingerprint].join("\0")).slice(0, 24)}`,
      ruleId,
      identity: { anchor },
      fingerprints: {
        algorithm: "codex-security/v1",
        primary: fingerprint,
      },
      provenance: { source: `${format}_import` },
      extensions: {
        ...finding.extensions,
        import: {
          format,
          sourceFindingId: finding.findingId,
          sourceOccurrenceId: finding.occurrenceId,
          sourceRuleId: finding.ruleId,
          sourceIdentity: finding.identity,
          sourceFingerprints: finding.fingerprints,
          sourceProvenance: finding.provenance,
          ...(writeup === undefined ? {} : { sourceWriteup: writeup }),
          ...(finding.extensions?.["import"] === undefined
            ? {}
            : { previousImport: finding.extensions["import"] }),
        },
      },
    };
  });
}

export function parseFindingsCsv(source: string): CsvFindingRow[] {
  const {
    data: rows,
    errors,
    meta,
  } = Papa.parse<Record<string, string>>(source, {
    header: true,
    delimiter: ",",
    skipEmptyLines: "greedy",
    transform: decodeExportedCsvCell,
  });
  const fieldMismatch = errors.find(
    (error) => error.code === "TooFewFields" || error.code === "TooManyFields",
  );
  if (fieldMismatch?.row !== undefined) {
    throw csvRowError(fieldMismatch.row + 2, "must match the header columns");
  }
  if (errors.length > 0) {
    throw new CodexSecurityError(
      `Findings CSV could not be parsed: ${errors[0]!.message}`,
    );
  }
  const headers = meta.fields;
  const allowed = new Set<string>(CSV_COLUMNS);
  if (
    headers === undefined ||
    !REQUIRED_CSV_COLUMNS.every((name) => headers.includes(name)) ||
    headers.some((name) => !allowed.has(name)) ||
    new Set(headers).size !== headers.length
  ) {
    throw new CodexSecurityError(
      `Findings CSV must use the Codex Security export columns: ${REQUIRED_CSV_COLUMNS.join(", ")} (candidate_id is optional).`,
    );
  }
  if (rows.length === 0) {
    throw new CodexSecurityError(
      "Findings CSV must contain at least one finding.",
    );
  }

  const findingIds = new Set<string>();
  const occurrenceIds = new Set<string>();
  return rows.map((record, index) => {
    const rowNumber = index + 2;
    const parsed = csvFindingRowSchema.safeParse(record);
    if (!parsed.success) {
      throw csvRowError(rowNumber, parsed.error.issues[0]!.message);
    }
    const row = parsed.data;
    if (findingIds.has(row.finding_id)) {
      throw csvRowError(rowNumber, "has a duplicate finding_id");
    }
    if (occurrenceIds.has(row.occurrence_id)) {
      throw csvRowError(rowNumber, "has a duplicate occurrence_id");
    }
    findingIds.add(row.finding_id);
    occurrenceIds.add(row.occurrence_id);
    return row;
  });
}

function decodeExportedCsvCell(value: string): string {
  return EXPORTED_CSV_ESCAPE.test(value) ? value.slice(1) : value;
}

export function csvRowFinding(row: CsvFindingRow, scanId: string): Finding {
  const ruleId = "import.csv";
  const anchor = row.finding_id;
  const fingerprint = `codex-security/v1:sha256:${sha256(
    ["codex-security/v1", CSV_TARGET_ID, ruleId, anchor, ""].join("\0"),
  )}`;
  const findingId = `csf_${sha256(fingerprint).slice(0, 24)}`;
  const occurrenceId = `occ_${sha256([scanId, fingerprint].join("\0")).slice(
    0,
    24,
  )}`;
  return {
    findingId,
    occurrenceId,
    ruleId,
    identity: { anchor },
    fingerprints: {
      algorithm: "codex-security/v1",
      primary: fingerprint,
    },
    title: row.title,
    summary: row.summary,
    severity: { level: row.severity },
    confidence: {
      level: row.confidence,
      rationale: "Imported from a Codex Security findings CSV.",
    },
    taxonomy: { category: "imported", cwe: [] },
    locations: [
      {
        path: row.path,
        startLine: row.start_line,
        ...(row.end_line === undefined ? {} : { endLine: row.end_line }),
      },
    ],
    remediation: row.remediation,
    validation: {
      method: "Source-reported CSV import metadata",
      status: row.status,
      summary: [
        `Source finding ID: ${row.finding_id}`,
        `Source occurrence ID: ${row.occurrence_id}`,
        `Source status: ${row.status}`,
        ...(row.close_reason === undefined
          ? []
          : [`Source close reason: ${row.close_reason}`]),
        ...(row.note === undefined ? [] : [`Source note: ${row.note}`]),
      ].join("\n"),
    },
    provenance: { source: "csv_import" },
    extensions: {
      ...(row.candidate_id === undefined
        ? {}
        : { candidateId: row.candidate_id }),
    },
  };
}

function requiredCsvText(column: string) {
  return z.string().refine((value) => value.trim().length > 0, {
    error: `requires ${column}`,
  });
}

function validCsvLine(value: string): boolean {
  if (!/^[1-9]\d*$/u.test(value)) return false;
  const line = Number(value);
  return Number.isSafeInteger(line);
}

function safeFindingPath(value: string): boolean {
  if (
    value.trim().length === 0 ||
    value === "." ||
    isAbsolute(value) ||
    /^[A-Za-z]:/u.test(value) ||
    value.includes("\\") ||
    /[\u0000-\u001F]/u.test(value) ||
    value.split("/").includes("..")
  ) {
    return false;
  }
  const normalized = posix.normalize(value).replace(/\/+$/u, "");
  return normalized !== "." && !normalized.startsWith("../");
}

function csvRowError(rowNumber: number, detail: string): CodexSecurityError {
  return new CodexSecurityError(`Findings CSV row ${rowNumber} ${detail}.`);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
