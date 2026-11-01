import type { DatabaseSync } from "node:sqlite";
import { isDeepStrictEqual } from "node:util";
import {
  escapeControls,
  parseJson,
  requireFiniteNumbers,
  stringifyJson,
} from "../helpers/json";
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

// The fresh document comes from stringifyJson after the command's finite-number
// check. Keep this comparison private: it is not equality for arbitrary JSON pairs.
function storedFindingJsonMatches(previous: string, fresh: string): boolean {
  const numberTag = Symbol("finding number");
  const outsideFreshRange = Symbol("outside fresh numeric range");
  // Finite Number output has |exponent| <= 324; BigInt output has exponent 0.
  // Normalizing either coefficient shifts its exponent by at most its document
  // length. A larger old exponent cannot match fresh, even after cancellation.
  const maxExponent = previous.length + fresh.length + 324;

  function numberToken(source: string): unknown {
    const [, sign, integer, fraction = "", exponentSign, exponentDigits = "0"] =
      /^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?)([0-9]+))?$/u.exec(source)!;
    const digits = integer + fraction;
    let first = 0;
    while (digits[first] === "0") first++;
    if (first === digits.length) return [numberTag, "0", 0];
    let last = digits.length;
    while (digits[last - 1] === "0") last--;

    const magnitude = Number(exponentDigits);
    if (magnitude > maxExponent) return outsideFreshRange;
    // Supported Node string lengths keep the bounded exponent and scale exact.
    const exponent = (exponentSign === "-" ? -1 : 1) * magnitude;
    const scale = exponent + digits.length - last - fraction.length;
    return [numberTag, sign + digits.slice(first, last), scale];
  }

  function comparisonView(source: string): unknown {
    try {
      return JSON.parse(
        source,
        (_key, value: unknown, context?: { source?: string }) => {
          if (typeof value !== "number") return value;
          const source = context!.source!;
          const token = numberToken(source);
          // parseJson preserves unsafe plain integer tokens as BigInt. Other
          // spellings must expose the same precision before we retain their text.
          const readback =
            !Number.isSafeInteger(value) && !/^-?[0-9]+$/u.test(source)
              ? Number.isFinite(value) && Number.isInteger(value)
                ? numberToken(String(BigInt(value)))
                : value
              : token;
          return [token, readback];
        },
      );
    } catch (error) {
      if (error instanceof SyntaxError)
        error.message = escapeControls(error.message);
      throw error;
    }
  }

  return isDeepStrictEqual(comparisonView(previous), comparisonView(fresh));
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
      const stored = database.prepare(
        "SELECT details_json FROM findings WHERE id = ?",
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
        let details = stringifyJson(finding, 0);
        const previous = stored.get(finding.findingId)?.details_json;
        if (
          typeof previous === "string" &&
          storedFindingJsonMatches(previous, details)
        )
          details = previous;
        const { changes } = upsert.run(
          finding.findingId,
          finding.fingerprints.primary,
          finding.ruleId,
          finding.identity.anchor,
          finding.identity.instance ?? null,
          details,
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
        ORDER BY julianday(upper(created_at)), id LIMIT ? OFFSET ?`,
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
