import type { DatabaseSync } from "node:sqlite";
import { parseJson, stringifyJson } from "../helpers/json";
import { requireSqliteText } from "./database";
import { transaction } from "./transaction";

export interface Finding {
  findingId: string;
  fingerprints: { primary: string };
  ruleId: string;
  identity: { anchor: string; instance?: string };
  [key: string]: unknown;
}

export interface EmbeddedFinding {
  finding: Finding;
  embedding: { model: string; vector: number[] };
}

class FindingConflict extends Error {}

function requireFiniteNumbers(value: unknown): void {
  if (typeof value === "number" && !Number.isFinite(value))
    throw new TypeError(
      "Stored finding JSON cannot contain non-finite numbers.",
    );
  if (value !== null && typeof value === "object")
    for (const item of Object.values(value)) requireFiniteNumbers(item);
}

export function storeFindings(
  database: DatabaseSync,
  entries: readonly EmbeddedFinding[],
  timestamp: string,
  repositoryId?: string,
): { findingIds: string[] } | { error: "finding_conflict" } {
  try {
    return transaction(database, "BEGIN IMMEDIATE", () => {
      requireSqliteText([timestamp, repositoryId]);
      const upsert = database.prepare(
        `INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, identity_instance,
          details_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET details_json = excluded.details_json,
          updated_at = excluded.updated_at
        WHERE findings.fingerprint = excluded.fingerprint
          AND findings.rule_id = excluded.rule_id
          AND findings.identity_anchor = excluded.identity_anchor
          AND findings.identity_instance IS excluded.identity_instance`,
      );
      const embedding = database.prepare(
        `INSERT INTO finding_embeddings (finding_id, model, vector_json) VALUES (?, ?, ?)
        ON CONFLICT(finding_id) DO UPDATE SET model = excluded.model, vector_json = excluded.vector_json`,
      );
      const repository = database.prepare(
        "INSERT OR IGNORE INTO finding_repositories (repository_id, finding_id) VALUES (?, ?)",
      );
      for (const entry of entries) {
        const finding = entry.finding;
        requireSqliteText([
          finding.findingId,
          finding.fingerprints.primary,
          finding.ruleId,
          finding.identity.anchor,
          finding.identity.instance,
          entry.embedding.model,
        ]);
        requireFiniteNumbers([finding, entry.embedding.vector]);
        const { changes } = upsert.run(
          finding.findingId,
          finding.fingerprints.primary,
          finding.ruleId,
          finding.identity.anchor,
          finding.identity.instance ?? null,
          stringifyJson(finding, 0),
          timestamp,
          timestamp,
        );
        if (changes === 0)
          throw new FindingConflict(
            "The stored finding identity cannot be replaced.",
          );
        if (repositoryId !== undefined)
          repository.run(repositoryId, finding.findingId);
        embedding.run(
          finding.findingId,
          entry.embedding.model,
          stringifyJson(entry.embedding.vector, 0),
        );
      }
      return { findingIds: entries.map(({ finding }) => finding.findingId) };
    });
  } catch (error) {
    if (
      error instanceof FindingConflict ||
      (error instanceof Error &&
        "errcode" in error &&
        (Number(error.errcode) & 0xff) === 19)
    ) {
      return { error: "finding_conflict" };
    }
    throw error;
  }
}

export function listStoredFindings(
  database: DatabaseSync,
  { limit, offset }: { limit: number; offset: number },
) {
  return transaction(database, "BEGIN", () => {
    const total = Number(
      database
        .prepare(
          "SELECT COUNT(*) AS total FROM findings WHERE details_json IS NOT NULL",
        )
        .get()!.total,
    );
    const rows = database
      .prepare(
        `SELECT details_json FROM findings WHERE details_json IS NOT NULL
        ORDER BY created_at, id LIMIT ? OFFSET ?`,
      )
      .all(limit, offset);
    const nextOffset = offset + rows.length;
    return {
      findings: rows.map(
        (row) => parseJson(String(row.details_json)) as Finding,
      ),
      limit,
      offset,
      total,
      nextOffset: nextOffset < total ? nextOffset : null,
    };
  });
}
