import { DatabaseSync } from "node:sqlite";
import { parseJson, stringifyJson } from "../helpers/json";
import { requireSqliteText } from "./database";
import type { Finding } from "./findings";
import { transaction } from "./transaction";

const fields = {
  findingId: "finding_id",
  occurrenceId: "occurrence_id",
  inputSha256: "input_sha256",
  rubricSha256: "rubric_sha256",
  knowledgeBaseSha256: "knowledge_base_sha256",
  assessedAt: "assessed_at",
  source: "source",
  decision: "decision",
  level: "level",
  rubricLabel: "rubric_label",
  rationale: "rationale",
  confidence: "confidence",
  reviewTrigger: "review_trigger",
} as const;

type Assessment = Record<keyof typeof fields, string | null>;

export type SeverityCheckpoint =
  | {
      action: "begin";
      scanId: string;
      findingIds: string[];
      assessedAt: string;
      rubricSha256: string | null;
      knowledgeBaseSha256: string | null;
    }
  | {
      action: "save";
      scanId: string;
      finding: Finding;
      assessment: Assessment;
    };

export function assessments(
  database: DatabaseSync,
  findingIds: string[],
  scanId?: string,
): Assessment[] {
  requireSqliteText([...findingIds, scanId]);
  const table =
    scanId === undefined
      ? "finding_severity_assessments"
      : "scan_severity_assessments";
  const scope = scanId === undefined ? "" : "WHERE assessment.scan_id = ?";
  // JSON preserves embedded NULs across Node 22 SQLite TEXT results.
  const projection = Object.entries(fields)
    .map(([key, column]) => `'${key}', assessment.${column}`)
    .join(", ");
  // Keep selected IDs first so each assessment is a primary-key lookup.
  const rows = database
    .prepare(
      `SELECT json_object(${projection}) AS value FROM json_each(?) AS selected
       CROSS JOIN ${table} AS assessment ON assessment.finding_id = selected.value
       ${scope} ORDER BY selected.key`,
    )
    .all(
      stringifyJson(findingIds, 0),
      ...(scanId === undefined ? [] : [scanId]),
    );
  return rows.map((row) => parseJson(String(row.value)) as Assessment);
}

export function severityCheckpoint(
  database: DatabaseSync,
  payload: SeverityCheckpoint,
  timestamp: string,
): { assessments?: Assessment[] } {
  requireSqliteText([payload.scanId, timestamp]);
  return transaction(database, "BEGIN IMMEDIATE", () => {
    if (payload.action === "begin") {
      requireSqliteText([
        ...payload.findingIds,
        payload.assessedAt,
        payload.rubricSha256,
        payload.knowledgeBaseSha256,
      ]);
      database
        .prepare(
          `INSERT INTO scan_severity_classifications (
            scan_id, finding_ids_json, assessed_at, rubric_sha256, knowledge_base_sha256
          ) VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(scan_id) DO UPDATE SET
            finding_ids_json = excluded.finding_ids_json,
            assessed_at = excluded.assessed_at,
            rubric_sha256 = excluded.rubric_sha256,
            knowledge_base_sha256 = excluded.knowledge_base_sha256`,
        )
        .run(
          payload.scanId,
          stringifyJson(payload.findingIds, 0),
          payload.assessedAt,
          payload.rubricSha256,
          payload.knowledgeBaseSha256,
        );
      // Cache hits are not saved again by the classifier. Keep each scan's own assessments.
      database
        .prepare(
          `INSERT INTO scan_severity_assessments
           SELECT ?, assessment.* FROM json_each(?) AS selected
           JOIN finding_severity_assessments AS assessment
             ON assessment.finding_id = selected.value
           WHERE true
           ON CONFLICT(scan_id, finding_id) DO NOTHING`,
        )
        .run(payload.scanId, stringifyJson(payload.findingIds, 0));
      return {
        assessments: assessments(database, payload.findingIds, payload.scanId),
      };
    }
    if (payload.action !== "save")
      throw new Error("Unknown severity checkpoint action.");
    const { finding } = payload;
    const assessment = { ...payload.assessment, assessedAt: timestamp };
    const values = Object.fromEntries(
      Object.entries(fields).map(([key, column]) => [
        column,
        assessment[key as keyof Assessment],
      ]),
    );
    requireSqliteText([finding.findingId, ...Object.values(values)]);
    // External scan directories may not have been indexed on this machine.
    if (
      !database
        .prepare("SELECT 1 FROM findings WHERE id = ?")
        .get(finding.findingId)
    ) {
      requireSqliteText([
        finding.fingerprints.primary,
        finding.ruleId,
        finding.identity.anchor,
        finding.identity.instance,
      ]);
      database
        .prepare(
          `INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, identity_instance,
          details_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          finding.findingId,
          finding.fingerprints.primary,
          finding.ruleId,
          finding.identity.anchor,
          finding.identity.instance ?? null,
          stringifyJson(finding, 0),
          timestamp,
          timestamp,
        );
    }
    for (const [table, key, row] of [
      ["finding_severity_assessments", "finding_id", values],
      [
        "scan_severity_assessments",
        "scan_id, finding_id",
        { scan_id: payload.scanId, ...values },
      ],
    ] as const) {
      const columns = Object.keys(row);
      database
        .prepare(
          `INSERT INTO ${table} (${columns.join(", ")})
         VALUES (${columns.map(() => "?").join(", ")})
         ON CONFLICT(${key}) DO UPDATE SET ${columns.map((column) => `${column} = excluded.${column}`).join(", ")}`,
        )
        .run(...Object.values(row));
    }
    return {};
  });
}

export function readSeverityClassification(
  databasePath: string,
  scanId: string,
): unknown {
  requireSqliteText([scanId]);
  const database = new DatabaseSync(databasePath, { readOnly: true });
  try {
    database.exec("PRAGMA busy_timeout = 5000");
    return transaction(database, "BEGIN", () => {
      if (
        !database
          .prepare(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'scan_severity_classifications'",
          )
          .get()
      )
        return {};
      const row = database
        .prepare(
          `SELECT json_object(
            'findingIds', json(finding_ids_json), 'assessedAt', assessed_at,
            'rubricSha256', rubric_sha256, 'knowledgeBaseSha256', knowledge_base_sha256
          ) AS value FROM scan_severity_classifications WHERE scan_id = ?`,
        )
        .get(scanId);
      if (!row) return {};
      const classification = parseJson(String(row.value)) as {
        findingIds: string[];
      };
      const hasScanAssessments = database
        .prepare(
          "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'scan_severity_assessments'",
        )
        .get();
      return {
        scanId,
        ...classification,
        assessments: assessments(
          database,
          classification.findingIds,
          hasScanAssessments ? scanId : undefined,
        ),
      };
    });
  } finally {
    database.close();
  }
}
