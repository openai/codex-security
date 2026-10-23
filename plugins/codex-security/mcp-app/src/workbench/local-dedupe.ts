import { createHash } from "node:crypto";
import type { DatabaseSync, SQLOutputValue } from "node:sqlite";
import { resolvedPathText } from "../helpers/helper-files";
import {
  parseJson,
  requireFiniteNumbers,
  stringifyJson,
} from "../helpers/json";
import { decodeUtf8 } from "../helpers/utf8";
import { requireSqliteText } from "./database";
import type { Finding } from "./findings";
import { stableTargetId } from "./migrations";
import { transaction } from "./transaction";

interface Preparation {
  action: "prepare";
  space: string;
  repositoryPath: string;
  anchorRepositoryId: string;
  repositoryId?: string;
  findings: readonly Finding[];
}

interface EmbeddingBatch {
  action: "embed";
  space: string;
  model: string;
  dimensions: number | bigint | boolean;
  entries: readonly {
    findingId: string;
    cacheKey: string;
    embedding: {
      model: string;
      vector: readonly (number | bigint | boolean)[];
    };
  }[];
}

export type LocalDedupeRequest = Preparation | EmbeddingBatch;

class LocalDedupeError extends Error {}

// Historical SQLite rows can contain BLOBs despite their TEXT affinity. Decode
// TEXT explicitly so SQLite's invalid UTF-8 is not silently replaced by Node.
function column(expression: string, name: string): string {
  return `CASE WHEN typeof(${expression}) = 'text' THEN CAST(${expression} AS BLOB)
    ELSE ${expression} END AS ${name}, typeof(${expression}) AS ${name}_type`;
}

function value(
  row: Record<string, SQLOutputValue>,
  name: string,
): SQLOutputValue {
  return row[`${name}_type`] === "text"
    ? decodeUtf8(Buffer.from(row[name] as Uint8Array))
    : row[name]!;
}

function cacheKey(space: string, document: SQLOutputValue): string {
  let text: string;
  if (document instanceof Uint8Array) {
    // Existing BLOB cache keys hash the bytes representation, not decoded JSON.
    const quote = document.includes(39) && !document.includes(34) ? 34 : 39;
    text = `b${String.fromCharCode(quote)}`;
    for (const byte of document) {
      if (byte === quote || byte === 92)
        text += `\\${String.fromCharCode(byte)}`;
      else if (byte === 9) text += "\\t";
      else if (byte === 10) text += "\\n";
      else if (byte === 13) text += "\\r";
      else if (byte < 32 || byte >= 127)
        text += `\\x${byte.toString(16).padStart(2, "0")}`;
      else text += String.fromCharCode(byte);
    }
    text += String.fromCharCode(quote);
  } else {
    text = document === null ? "None" : String(document);
  }
  requireSqliteText([space, text]);
  return createHash("sha256").update(`${space}\0${text}`).digest("hex");
}

function parseBody(document: SQLOutputValue): unknown {
  if (typeof document === "string") return parseJson(document);
  if (!(document instanceof Uint8Array))
    throw new TypeError("Stored finding JSON must be text or bytes.");
  const bytes = Buffer.from(document);
  let text: string;
  try {
    // json.loads historically accepted UTF-8, UTF-16 and UTF-32 BLOB bodies.
    if (
      bytes.subarray(0, 4).equals(Buffer.from([0, 0, 0xfe, 0xff])) ||
      bytes.subarray(0, 4).equals(Buffer.from([0xff, 0xfe, 0, 0])) ||
      (bytes.length >= 4 && bytes[0] === 0 && bytes[1] === 0) ||
      (bytes.length >= 4 && bytes[1] === 0 && bytes[2] === 0 && bytes[3] === 0)
    ) {
      const little = bytes[0] !== 0;
      if (bytes.length % 4) throw new Error("Truncated UTF-32 finding JSON.");
      text = "";
      for (let offset = 0; offset < bytes.length; offset += 4)
        text += String.fromCodePoint(
          little ? bytes.readUInt32LE(offset) : bytes.readUInt32BE(offset),
        );
    } else if (
      bytes.subarray(0, 2).equals(Buffer.from([0xfe, 0xff])) ||
      bytes.subarray(0, 2).equals(Buffer.from([0xff, 0xfe])) ||
      (bytes.length >= 2 && (bytes[0] === 0 || bytes[1] === 0))
    ) {
      if (bytes.length % 2) throw new Error("Truncated UTF-16 finding JSON.");
      const little = bytes[0] !== 0 && bytes[0] !== 0xfe;
      text = (little ? bytes : bytes.swap16()).toString("utf16le");
    } else {
      text = decodeUtf8(bytes);
    }
  } catch (error) {
    throw new LocalDedupeError((error as Error).message);
  }
  return parseJson(text.startsWith("\ufeff") ? text.slice(1) : text);
}

function orderedFinding(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(orderedFinding);
  if (value === null || typeof value !== "object") return value;
  // Python sorted response keys recursively; preserve the SDK embedding input.
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => {
        const a = Array.from(left, (point) => point.codePointAt(0)!);
        const b = Array.from(right, (point) => point.codePointAt(0)!);
        for (let index = 0; index < Math.min(a.length, b.length); index++) {
          const difference = a[index]! - b[index]!;
          if (difference !== 0) return difference;
        }
        return a.length - b.length;
      })
      .map(([key, item]) => [key, orderedFinding(item)]),
  );
}

function prepare(
  database: DatabaseSync,
  payload: Preparation,
  timestamp: string,
) {
  // A sealed scan selects finding IDs, not permission to select another corpus.
  const target = resolvedPathText(payload.repositoryPath, false);
  requireSqliteText([target]);
  const registered = database
    .prepare(
      `SELECT ${column("id", "id")} FROM security_targets WHERE current_path = ?`,
    )
    .get(target);
  const targetId =
    registered === undefined ? stableTargetId(target) : value(registered, "id");
  if (
    payload.anchorRepositoryId !== targetId ||
    (payload.repositoryId !== undefined && payload.repositoryId !== targetId)
  )
    throw new LocalDedupeError("target_mismatch");
  if (payload.findings.length === 0)
    return {
      cacheKeys: new Map<SQLOutputValue, string>(),
      findingsToEmbed: [],
    };

  const existing = database.prepare(
    `SELECT ${["fingerprint", "rule_id", "identity_anchor", "identity_instance", "details_json"].map((name) => column(name, name)).join(", ")}
      FROM findings WHERE id = ?`,
  );
  const insert = database.prepare(
    `INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, identity_instance,
      details_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET details_json = excluded.details_json,
      updated_at = excluded.updated_at`,
  );
  const link = database.prepare(
    "INSERT OR IGNORE INTO finding_repositories (repository_id, finding_id) VALUES (?, ?)",
  );
  for (const finding of payload.findings) {
    const identity = [
      finding.fingerprints.primary,
      finding.ruleId,
      finding.identity.anchor,
      finding.identity.instance ?? null,
    ] as const;
    requireSqliteText([finding.findingId]);
    const current = existing.get(finding.findingId);
    const values =
      current &&
      [
        "fingerprint",
        "rule_id",
        "identity_anchor",
        "identity_instance",
        "details_json",
      ].map((name) => value(current, name));
    if (
      values &&
      values.slice(0, 4).some((value, index) => value !== identity[index])
    )
      throw new LocalDedupeError("finding_conflict");
    // Historical input must never overwrite the current body or its cache key.
    if (values === undefined || values[4] === null) {
      requireSqliteText([...identity, timestamp]);
      try {
        requireFiniteNumbers(finding);
      } catch (error) {
        throw new LocalDedupeError((error as Error).message);
      }
      insert.run(
        finding.findingId,
        ...identity,
        stringifyJson(finding, 0),
        timestamp,
        timestamp,
      );
    }
    link.run(payload.anchorRepositoryId, finding.findingId);
  }

  const rows = database.prepare(
    `SELECT ${column("findings.id", "id")}, ${column("findings.details_json", "details")},
      ${column("embeddings.cache_key", "cache_key")} FROM findings
    LEFT JOIN local_finding_embeddings AS embeddings ON findings.id = embeddings.finding_id
    ${
      payload.repositoryId === undefined
        ? ""
        : "WHERE EXISTS (SELECT 1 FROM finding_repositories WHERE finding_id = findings.id AND repository_id = ?)"
    }
    ORDER BY findings.created_at, findings.id`,
  );
  const cacheKeys = new Map<SQLOutputValue, string>();
  const findingsToEmbed: unknown[] = [];
  for (const row of rows.iterate(
    ...(payload.repositoryId === undefined ? [] : [payload.repositoryId]),
  )) {
    const [id, document, savedKey] = ["id", "details", "cache_key"].map(
      (name) => value(row, name),
    );
    if (document === null) throw new LocalDedupeError("finding_not_indexed");
    const key = cacheKey(payload.space, document!);
    cacheKeys.set(id!, key);
    // A cache hit does not parse or rewrite the stored document.
    if (key !== savedKey)
      findingsToEmbed.push(orderedFinding(parseBody(document!)));
  }
  return { cacheKeys, findingsToEmbed };
}

function validVector(
  vector: EmbeddingBatch["entries"][number]["embedding"]["vector"],
): boolean {
  let maximum = 0;
  const numbers: number[] = [];
  for (const value of vector) {
    if (!["number", "bigint", "boolean"].includes(typeof value)) return false;
    const number = Number(value);
    if (typeof value === "bigint" && !Number.isFinite(number))
      throw new RangeError("int too large to convert to float");
    if (!Number.isFinite(number)) return false;
    maximum = Math.max(maximum, Math.abs(number));
    numbers.push(number);
  }
  if (maximum === 0) return false;
  let sum = 0;
  let correction = 0;
  for (const number of numbers) {
    const scaled = number / maximum;
    const term = scaled * scaled - correction;
    const next = sum + term;
    correction = next - sum - term;
    sum = next;
  }
  if (maximum * Math.sqrt(sum) < Number.MAX_VALUE / 2) return true;
  // Near overflow, a rounded sqrt/product can reject a norm that rounds to
  // MAX_VALUE. Compare exact squares in units of 2^-2148 with the overflow midpoint.
  const boundary = ((1n << 2098n) - (1n << 2044n)) ** 2n;
  const bytes = Buffer.allocUnsafe(8);
  let squares = 0n;
  for (const number of numbers) {
    bytes.writeDoubleBE(number);
    const bits = bytes.readBigUInt64BE();
    const exponent = Number((bits >> 52n) & 0x7ffn);
    const significand =
      (bits & ((1n << 52n) - 1n)) | (exponent === 0 ? 0n : 1n << 52n);
    squares +=
      (significand * significand) <<
      BigInt(exponent === 0 ? 0 : 2 * (exponent - 1));
    if (squares >= boundary) return false;
  }
  return true;
}

function embed(database: DatabaseSync, payload: EmbeddingBatch) {
  const current = database.prepare(
    `SELECT ${column("details_json", "details")} FROM findings WHERE id = ?`,
  );
  const save = database.prepare(
    `INSERT INTO local_finding_embeddings (finding_id, model, vector_json, cache_key)
      VALUES (?, ?, ?, ?) ON CONFLICT(finding_id) DO UPDATE SET
      model = excluded.model, vector_json = excluded.vector_json, cache_key = excluded.cache_key`,
  );
  for (const entry of payload.entries) {
    requireSqliteText([entry.findingId]);
    const row = current.get(entry.findingId);
    if (
      row === undefined ||
      cacheKey(payload.space, value(row, "details")) !== entry.cacheKey
    )
      throw new LocalDedupeError("finding_changed");
    const { model, vector } = entry.embedding;
    if (
      model !== payload.model ||
      !["number", "bigint", "boolean"].includes(typeof payload.dimensions) ||
      vector.length !== Number(payload.dimensions) ||
      !validVector(vector)
    )
      throw new LocalDedupeError("embedding_failed");
    requireSqliteText([model, entry.cacheKey]);
    save.run(entry.findingId, model, stringifyJson(vector, 0), entry.cacheKey);
  }
  return {};
}

export function localDedupe(
  database: DatabaseSync,
  payload: LocalDedupeRequest,
  timestamp: string,
) {
  try {
    const result = transaction(database, "BEGIN IMMEDIATE", () => {
      if (payload.action === "prepare")
        return prepare(database, payload, timestamp);
      if (payload.action === "embed") return embed(database, payload);
      throw new LocalDedupeError("invalid_request");
    });
    if ("cacheKeys" in result && result.cacheKeys instanceof Map) {
      // Unsupported JSON object keys fail at the response boundary after commit.
      for (const key of result.cacheKeys.keys())
        if (key instanceof Uint8Array)
          throw new TypeError("Finding cache keys cannot contain bytes.");
      return { ...result, cacheKeys: Object.fromEntries(result.cacheKeys) };
    }
    return result;
  } catch (error) {
    if (error instanceof LocalDedupeError || error instanceof SyntaxError)
      return { error: error.message };
    if (
      error instanceof Error &&
      "errcode" in error &&
      (Number(error.errcode) & 0xff) === 19
    )
      return { error: "finding_conflict" };
    throw error;
  }
}
