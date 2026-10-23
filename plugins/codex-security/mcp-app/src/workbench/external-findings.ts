import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { isDeepStrictEqual } from "node:util";
import {
  object,
  parseJson,
  requireFiniteNumbers,
  stringifyJson,
} from "../helpers/json";
import { requireSqliteText } from "./database";
import { transaction } from "./transaction";

export interface ExternalFindingInput {
  source_finding_id: string;
  evidence: Record<string, unknown>;
}

export interface ExternalFindingsImport {
  repository: string;
  provider: string;
  sourceKey: string;
  findings: ExternalFindingInput[];
}

export interface StoredExternalFinding {
  id: string;
  repository: string;
  provider: string;
  sourceKey: string;
  sourceFindingId: string;
  evidence: Record<string, unknown>;
  assessment: { state: "not_assessed" };
  version: number;
  createdAt: string;
  updatedAt: string;
}

function requireText(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0)
    throw new TypeError(`${name} must be a non-empty string.`);
  requireSqliteText([value]);
}

function requireRepository(repository: unknown): asserts repository is string {
  requireText(repository, "repository");
  if (!isAbsolute(repository))
    throw new TypeError("repository must be an absolute local path.");
}

function fromRow(row: Record<string, unknown>): StoredExternalFinding {
  return {
    id: String(row.id),
    repository: String(row.repository),
    provider: String(row.provider),
    sourceKey: String(row.source_key),
    sourceFindingId: String(row.source_finding_id),
    evidence: parseJson(String(row.evidence_json)) as Record<string, unknown>,
    assessment: { state: "not_assessed" },
    version: Number(row.version),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
  };
}

export function storeExternalFindings(
  database: DatabaseSync,
  input: ExternalFindingsImport,
  timestamp: string,
): {
  findings: StoredExternalFinding[];
  counts: { created: number; updated: number; unchanged: number };
} {
  requireRepository(input?.repository);
  requireText(input.provider, "provider");
  requireText(input.sourceKey, "sourceKey");
  requireSqliteText([timestamp]);
  if (!Array.isArray(input.findings))
    throw new TypeError("findings must be an array.");

  // Validate and serialize the complete batch before taking the write lock.
  const sourceIds = new Set<string>();
  const entries = input.findings.map((finding) => {
    requireText(finding?.source_finding_id, "source_finding_id");
    if (sourceIds.has(finding.source_finding_id))
      throw new TypeError(
        "findings must not contain duplicate source_finding_id values.",
      );
    sourceIds.add(finding.source_finding_id);
    if (!object(finding.evidence))
      throw new TypeError("evidence must be an object.");
    requireFiniteNumbers(finding.evidence);
    const evidenceJson = stringifyJson(finding.evidence, 0);
    const identity = [
      input.repository,
      input.provider,
      input.sourceKey,
      finding.source_finding_id,
    ];
    return {
      id: `ext_${createHash("sha256").update(JSON.stringify(identity)).digest("hex")}`,
      sourceFindingId: finding.source_finding_id,
      evidenceJson,
    };
  });

  return transaction(database, "BEGIN IMMEDIATE", () => {
    const stored = database.prepare(
      "SELECT * FROM external_source_reports WHERE id = ?",
    );
    const insert = database.prepare(
      `INSERT INTO external_source_reports
        (id, repository, provider, source_key, source_finding_id,
         evidence_json, version, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`,
    );
    const update = database.prepare(
      `UPDATE external_source_reports
       SET evidence_json = ?, version = version + 1, updated_at = ?
       WHERE id = ?`,
    );
    const counts = { created: 0, updated: 0, unchanged: 0 };
    const findings = entries.map((entry) => {
      const previous = stored.get(entry.id);
      if (!previous) {
        insert.run(
          entry.id,
          input.repository,
          input.provider,
          input.sourceKey,
          entry.sourceFindingId,
          entry.evidenceJson,
          timestamp,
          timestamp,
        );
        counts.created++;
      } else if (
        isDeepStrictEqual(
          parseJson(String(previous.evidence_json)),
          parseJson(entry.evidenceJson),
        )
      ) {
        counts.unchanged++;
      } else {
        update.run(entry.evidenceJson, timestamp, entry.id);
        counts.updated++;
      }
      return fromRow(stored.get(entry.id)!);
    });
    return { findings, counts };
  });
}

export function listExternalFindings(
  database: DatabaseSync,
  selection: { repository: string; id?: string },
): { findings: StoredExternalFinding[] } {
  requireRepository(selection?.repository);
  if (selection.id !== undefined) requireText(selection.id, "id");
  const rows =
    selection.id === undefined
      ? database
          .prepare(
            `SELECT * FROM external_source_reports
             WHERE repository = ? ORDER BY created_at, id`,
          )
          .all(selection.repository)
      : database
          .prepare(
            "SELECT * FROM external_source_reports WHERE repository = ? AND id = ?",
          )
          .all(selection.repository, selection.id);
  return { findings: rows.map(fromRow) };
}
