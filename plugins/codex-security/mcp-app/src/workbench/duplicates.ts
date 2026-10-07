import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { parseJson } from "../helpers/json";
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
) {
  return transaction(database, "BEGIN", () => {
    requireSqliteText([findingId, repositoryId]);
    const source =
      repositoryId === undefined
        ? "finding_embeddings AS embeddings"
        : "finding_repositories AS repositories JOIN finding_embeddings AS embeddings ON embeddings.finding_id = repositories.finding_id";
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
       WHERE ${predicate}embeddings.model = (SELECT model FROM finding_embeddings WHERE finding_id = ?)
       AND embeddings.finding_id != ?
       ORDER BY findings.created_at, findings.id`,
    );
    const ranked: { id: string; similarity: number }[] = [];
    try {
      const vector = normalizedVector(JSON.parse(anchor.vector_json as string));
      for (const row of rows.iterate(...scope, findingId, findingId)) {
        const candidate: number[] = JSON.parse(row.vector_json as string);
        if (candidate.length !== vector.length) continue;
        const other = normalizedVector(candidate);
        const similarity = vector.reduce(
          (total, value, index) => total + value * other[index],
          0,
        );
        if (similarity >= 0.55)
          ranked.push({
            id: JSON.parse(row.finding_id_json as string),
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
    const [finding, ...potentialDuplicates] = database
      .prepare(
        `SELECT findings.details_json FROM json_each(?) AS selected
         JOIN findings ON findings.id = selected.value ORDER BY selected.key`,
      )
      .all(JSON.stringify(selected))
      .map((row) => parseJson(row.details_json as string));
    return { finding, potentialDuplicates };
  });
}

export function storeDedupeGroups(
  database: DatabaseSync,
  groups: readonly (readonly string[])[],
  timestamp: string,
) {
  try {
    return transaction(database, "BEGIN IMMEDIATE", () => {
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
