import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { equalFindingJson, parseJson } from "../helpers/json";
import { transaction } from "./transaction";
import { requireSqliteText } from "./database";

export interface DedupeGroup {
  groupId: string;
  findingIds: string[];
  createdAt: string;
}

function normalizedVector(vector: number[]): number[] {
  const maximum = vector.reduce(
    (maximum, value) => Math.max(maximum, Math.abs(value)),
    0,
  );
  // Binary scaling keeps ratios exact; 1023 is the largest finite Number exponent.
  const scale = 2 ** Math.min(Math.floor(Math.log2(maximum)), 1023);
  const norm =
    scale *
    Math.sqrt(vector.reduce((sum, value) => sum + (value / scale) ** 2, 0));
  if (!vector.every(Number.isFinite) || norm === 0 || !Number.isFinite(norm))
    throw new RangeError("A stored embedding cannot be compared.");
  return vector.map((value) => value / norm);
}

export function findPotentialDuplicates(
  database: DatabaseSync,
  findingId: string,
  repositoryId?: string,
  expectedCacheKeys?: Record<string, string>,
) {
  return transaction(database, "BEGIN", () => {
    requireSqliteText([findingId, repositoryId]);
    if (
      expectedCacheKeys !== undefined &&
      !embeddingsMatch(database, expectedCacheKeys)
    )
      return { error: "finding_changed" as const };
    const table =
      expectedCacheKeys === undefined
        ? "finding_embeddings"
        : "local_finding_embeddings";
    const source =
      repositoryId === undefined
        ? `${table} AS embeddings`
        : `finding_repositories AS repositories JOIN ${table} AS embeddings ON embeddings.finding_id = repositories.finding_id`;
    const predicate =
      repositoryId === undefined ? "" : "repositories.repository_id = ? AND ";
    const scope = repositoryId === undefined ? [] : [repositoryId];
    const anchor = database
      .prepare(
        `SELECT embeddings.vector_json FROM ${source}
       WHERE ${predicate}embeddings.finding_id = ?`,
      )
      .get(...scope, findingId);
    if (!anchor) return { error: "finding_not_indexed" as const };

    const rows = database.prepare(
      `SELECT json_quote(embeddings.finding_id) AS finding_id_json, embeddings.vector_json FROM ${source}
       JOIN findings ON findings.id = embeddings.finding_id
       WHERE ${predicate}embeddings.model = (SELECT model FROM ${table} WHERE finding_id = ?)
       AND embeddings.finding_id != ?
       ORDER BY findings.created_at, findings.id`,
    );
    const ranked: { id: string; similarity: number }[] = [];
    try {
      const vector = normalizedVector(JSON.parse(anchor.vector_json as string));
      for (const row of rows.iterate(...scope, findingId, findingId)) {
        const id: string = JSON.parse(row.finding_id_json as string);
        if (
          expectedCacheKeys !== undefined &&
          !Object.hasOwn(expectedCacheKeys, id)
        )
          continue;
        const candidate: number[] = JSON.parse(row.vector_json as string);
        if (candidate.length !== vector.length) continue;
        const other = normalizedVector(candidate);
        const similarity = vector.reduce(
          (total, value, index) => total + value * other[index],
          0,
        );
        if (similarity >= 0.55)
          ranked.push({
            id,
            similarity,
          });
      }
    } catch (error) {
      if (error instanceof SyntaxError || error instanceof RangeError)
        return { error: "embedding_failed" as const };
      throw error;
    }
    // Stable sorting keeps insertion-time / finding-ID order for ties.
    ranked.sort((a, b) => b.similarity - a.similarity);
    const selected = [findingId, ...ranked.slice(0, 50).map(({ id }) => id)];
    const serializedDocuments = database
      .prepare(
        `SELECT findings.details_json FROM json_each(?) AS selected
         JOIN findings ON findings.id = selected.value ORDER BY selected.key`,
      )
      .all(JSON.stringify(selected))
      .map((row) => row.details_json as string);
    const documents = serializedDocuments.map(parseJson);
    const [finding, ...potentialDuplicates] = documents;
    if (expectedCacheKeys === undefined)
      return { finding, potentialDuplicates };
    const repositoryIds: Record<string, string[]> = Object.fromEntries(
      selected.map((id) => [id, []]),
    );
    const sourceSnapshots = new Map<string, unknown>();
    const findingDocuments = new Map(
      selected.map((id, index) => [id, serializedDocuments[index]!]),
    );
    for (const row of database
      .prepare(
        `SELECT json_quote(repositories.finding_id) AS finding_id_json,
                json_quote(repositories.repository_id) AS repository_id_json,
                CASE WHEN scans.id IS NOT NULL THEN json_object(
                  'repositoryId', scans.target_id,
                  'revision', scans.target_revision,
                  'snapshotDigest', CASE WHEN scans.diff_target_kind = 'working_tree'
                    THEN scans.diff_content_digest ELSE scans.target_snapshot_digest END
                ) END AS source_json,
                occurrence.details_json AS occurrence_json
         FROM finding_repositories AS repositories
         JOIN findings ON findings.id = repositories.finding_id
         LEFT JOIN finding_occurrences AS occurrence
           ON occurrence.id = json_extract(findings.details_json, '$.occurrenceId')
           AND occurrence.finding_id = findings.id
         LEFT JOIN scans ON scans.id = occurrence.scan_id
         WHERE repositories.finding_id IN (SELECT value FROM json_each(?))
         ORDER BY repositories.finding_id, repositories.repository_id`,
      )
      .all(JSON.stringify(selected))) {
      const id: string = JSON.parse(row.finding_id_json as string);
      repositoryIds[id]!.push(JSON.parse(row.repository_id_json as string));
      if (
        typeof row.source_json === "string" &&
        typeof row.occurrence_json === "string" &&
        equalFindingJson(row.occurrence_json, findingDocuments.get(id)!)
      )
        sourceSnapshots.set(id, JSON.parse(row.source_json));
    }
    return {
      finding,
      potentialDuplicates,
      repositoryIds,
      sourceSnapshots: Object.fromEntries(sourceSnapshots),
    };
  });
}

export function storeDedupeGroups(
  database: DatabaseSync,
  groups: readonly (readonly string[])[],
  timestamp: string,
  expectedCacheKeys?: Record<string, string>,
):
  | { groups: DedupeGroup[] }
  | { error: "finding_changed" | "finding_conflict" } {
  try {
    return transaction(database, "BEGIN IMMEDIATE", () => {
      if (
        expectedCacheKeys !== undefined &&
        !embeddingsMatch(database, expectedCacheKeys)
      )
        return { error: "finding_changed" as const };
      const insertGroup = database.prepare(
        "INSERT INTO finding_dedupe_groups (id, created_at) VALUES (?, ?) ON CONFLICT(id) DO NOTHING",
      );
      const insertMember = database.prepare(
        "INSERT INTO finding_dedupe_group_members (group_id, finding_id) VALUES (?, ?) ON CONFLICT(group_id, finding_id) DO NOTHING",
      );
      const created = database.prepare(
        "SELECT created_at FROM finding_dedupe_groups WHERE id = ?",
      );
      const stored = new Map<string, DedupeGroup>();
      for (const group of groups) {
        requireSqliteText(group);
        // Durable group IDs use code-point sorting and ASCII-escaped JSON.
        const findingIds = [...new Set(group)].sort((left, right) =>
          Buffer.compare(Buffer.from(left), Buffer.from(right)),
        );
        const encoded = JSON.stringify(findingIds).replace(
          /[\u007f-\uffff]/g,
          (character) =>
            `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
        );
        const groupId =
          "fdg_" + createHash("sha256").update(encoded).digest("hex");
        insertGroup.run(groupId, timestamp);
        for (const findingId of findingIds)
          insertMember.run(groupId, findingId);
        stored.set(groupId, {
          groupId,
          findingIds,
          createdAt: created.get(groupId)!.created_at as string,
        });
      }
      return { groups: [...stored.values()] };
    });
  } catch (error) {
    if (
      error instanceof Error &&
      "errcode" in error &&
      (Number(error.errcode) & 0xff) === 19
    )
      return { error: "finding_conflict" as const };
    throw error;
  }
}

function embeddingsMatch(
  database: DatabaseSync,
  expected: Record<string, string>,
): boolean {
  return (
    database
      .prepare(
        `
    SELECT 1 FROM json_each(?) AS expected
    LEFT JOIN local_finding_embeddings AS embeddings ON embeddings.finding_id = expected.key
    WHERE embeddings.finding_id IS NULL OR embeddings.cache_key IS NOT expected.value
    LIMIT 1
  `,
      )
      .get(JSON.stringify(expected)) === undefined
  );
}

export function listDedupeGroups(database: DatabaseSync, findingId: string) {
  requireSqliteText([findingId]);
  const rows = database.prepare(`
    SELECT json_object('groupId', groups.id, 'createdAt', groups.created_at,
      'findingIds', json_group_array(members.finding_id ORDER BY members.finding_id)) AS document
    FROM finding_dedupe_group_members AS matched
    JOIN finding_dedupe_groups AS groups ON groups.id = matched.group_id
    JOIN finding_dedupe_group_members AS members ON members.group_id = groups.id
    WHERE matched.finding_id = ?
    GROUP BY groups.id ORDER BY groups.created_at, groups.id
  `);
  return {
    groups: rows
      .all(findingId)
      .map((row) => JSON.parse(row.document as string) as DedupeGroup),
  };
}
