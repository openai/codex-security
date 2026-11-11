import { hash, randomUUID } from "node:crypto";
import { isAbsolute } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { isDeepStrictEqual } from "node:util";
import {
  compareCodePoints,
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
  provenance?: {
    sourceRepositories?: { url: string; platform?: "github" | "gitlab" }[];
    inspectorProjectMap?: [string, string][];
  };
  read?: number;
  excluded?: unknown[];
  report?: Record<string, unknown>;
}

export interface ExternalFindingSelection {
  repository: string;
  id?: string;
  importId?: string;
  findings?: Pick<StoredExternalFinding, "id" | "version">[];
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

export function requireText(
  value: unknown,
  name: string,
): asserts value is string {
  if (typeof value !== "string" || value.length === 0)
    throw new TypeError(`${name} must be a non-empty string.`);
  requireSqliteText([value]);
}

export function requireRepository(
  repository: unknown,
): asserts repository is string {
  requireText(repository, "repository");
  if (!isAbsolute(repository))
    throw new TypeError("repository must be an absolute local path.");
}

function parseEvidence(json: string): StoredExternalFinding["evidence"] {
  return parseJson(json) as StoredExternalFinding["evidence"];
}

function fromRow(row: Record<string, unknown>): StoredExternalFinding {
  return {
    id: String(row.id),
    repository: String(row.repository),
    provider: String(row.provider),
    sourceKey: String(row.source_key),
    sourceFindingId: String(row.source_finding_id),
    evidence: parseEvidence(String(row.evidence_json)),
    assessment: { state: "not_assessed" },
    version: Number(row.version),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
  };
}

// A change to the publication context advances the local revision. All imports
// of one finding revision therefore have equivalent provenance.
const findingWithProvenance = `SELECT f.*, (
  SELECT i.provenance_json FROM external_finding_import_members m
  JOIN external_finding_imports i ON i.id = m.import_id
  WHERE m.finding_id = f.id AND m.version = f.version LIMIT 1
) AS provenance_json FROM external_source_reports f`;

// A scanner can enumerate the same repository bindings in a different order.
function serializeProvenance(provenance: ExternalFindingsImport["provenance"]) {
  const repositories = provenance?.sourceRepositories;
  const projects = provenance?.inspectorProjectMap;
  if (!repositories?.length && !projects?.length) return null;
  return JSON.stringify({
    sourceRepositories: repositories?.length
      ? repositories
          .map(({ url, platform }) => ({ url, platform }))
          .sort(
            (a, b) =>
              compareCodePoints(a.url, b.url) ||
              compareCodePoints(a.platform ?? "", b.platform ?? ""),
          )
      : undefined,
    inspectorProjectMap: projects?.length
      ? projects.toSorted(([a], [b]) => compareCodePoints(a, b))
      : undefined,
  });
}

export function storeExternalFindings(
  database: DatabaseSync,
  input: ExternalFindingsImport,
  timestamp: string,
): {
  importId?: string;
  findings: StoredExternalFinding[];
  counts: { created: number; updated: number; unchanged: number };
} {
  requireRepository(input?.repository);
  requireText(input.provider, "provider");
  requireText(input.sourceKey, "sourceKey");
  requireSqliteText([timestamp]);
  if (!Array.isArray(input.findings))
    throw new TypeError("findings must be an array.");
  const counts = { created: 0, updated: 0, unchanged: 0 };
  if (input.findings.length === 0) return { findings: [], counts };
  const provenanceJson = serializeProvenance(input.provenance);
  const selection = {
    read: input.read ?? input.findings.length,
    excluded: input.excluded ?? [],
    report: input.report,
  };
  requireFiniteNumbers(selection);
  const selectionJson = stringifyJson(selection, 0);

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
      id: `ext_${hash("sha256", JSON.stringify(identity))}`,
      sourceFindingId: finding.source_finding_id,
      evidenceJson,
    };
  });

  return transaction(database, "BEGIN IMMEDIATE", () => {
    const importId = randomUUID();
    database
      .prepare(
        `INSERT INTO external_finding_imports
       (id, repository, created_at, provider, source_key, provenance_json, selection_json)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        importId,
        input.repository,
        timestamp,
        input.provider,
        input.sourceKey,
        provenanceJson,
        selectionJson,
      );
    const stored = database.prepare(`${findingWithProvenance} WHERE f.id = ?`);
    const write = database.prepare(
      `INSERT INTO external_source_reports
       (id, repository, provider, source_key, source_finding_id, evidence_json, version, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
       ON CONFLICT(id) DO UPDATE SET evidence_json = excluded.evidence_json,
         version = external_source_reports.version + 1, updated_at = excluded.updated_at
       RETURNING *`,
    );
    const findings = entries.map((entry) => {
      const previous = stored.get(entry.id);
      if (previous && previous.provenance_json === provenanceJson) {
        const finding = fromRow(previous);
        if (
          previous.evidence_json === entry.evidenceJson ||
          isDeepStrictEqual(finding.evidence, parseEvidence(entry.evidenceJson))
        ) {
          counts.unchanged++;
          return finding;
        }
      }
      const row = write.get(
        entry.id,
        input.repository,
        input.provider,
        input.sourceKey,
        entry.sourceFindingId,
        entry.evidenceJson,
        timestamp,
        timestamp,
      )!;
      counts[previous ? "updated" : "created"]++;
      return fromRow(row);
    });
    const member = database.prepare(
      "INSERT INTO external_finding_import_members (import_id, position, finding_id, version) VALUES (?, ?, ?, ?)",
    );
    findings.forEach(({ id, version }, position) =>
      member.run(importId, position, id, version),
    );
    return { importId, findings, counts };
  });
}

export function listExternalImports(
  database: DatabaseSync,
  selection: { repository: string },
) {
  requireRepository(selection?.repository);
  return {
    imports: database
      .prepare(
        `SELECT i.id AS importId, i.created_at AS createdAt, i.provider, i.source_key AS sourceKey,
       (SELECT count(*) FROM external_finding_import_members m WHERE m.import_id = i.id) AS count
     FROM external_finding_imports i WHERE i.repository = ?
     ORDER BY i.created_at DESC, i.rowid DESC`,
      )
      .all(selection.repository),
  };
}

export function listExternalFindings(
  database: DatabaseSync,
  selection: ExternalFindingSelection,
) {
  requireRepository(selection?.repository);
  const { repository, id, importId, findings: versions } = selection;
  if (importId === undefined && versions === undefined) {
    if (id !== undefined) requireText(id, "id");
    const lookup = "SELECT * FROM external_source_reports WHERE repository = ?";
    const rows =
      id === undefined
        ? database.prepare(`${lookup} ORDER BY created_at, id`).all(repository)
        : database.prepare(`${lookup} AND id = ?`).all(repository, id);
    return { findings: rows.map(fromRow) };
  }
  if (id !== undefined || (importId !== undefined && versions !== undefined))
    throw new TypeError(
      "Select either an import or a list of finding versions.",
    );
  return transaction(database, "BEGIN", () => {
    let summary: Record<string, unknown> = {};
    let pins: string, input: string;
    if (importId !== undefined) {
      requireText(importId, "importId");
      const batch = database
        .prepare(
          "SELECT selection_json FROM external_finding_imports WHERE repository = ? AND id = ?",
        )
        .get(repository, importId);
      if (!batch)
        throw new Error("Import does not exist in the selected repository.");
      summary = parseJson(String(batch.selection_json)) as Record<
        string,
        unknown
      >;
      pins =
        "SELECT finding_id AS id, version, position FROM external_finding_import_members WHERE import_id = ?";
      input = importId;
    } else {
      if (!Array.isArray(versions) || versions.length === 0)
        throw new TypeError("Select at least one finding version.");
      const seen = new Set<string>();
      input = JSON.stringify(
        versions.map(({ id, version }) => {
          requireText(id, "finding id");
          if (seen.has(id) || !Number.isSafeInteger(version) || version < 1)
            throw new TypeError(
              "Select each finding once with a positive integer version.",
            );
          seen.add(id);
          return [id, version];
        }),
      );
      pins =
        "SELECT value ->> 0 AS id, value ->> 1 AS version, key AS position FROM json_each(?)";
    }
    // A left join retains missing and foreign pins so a partial selection can never be approved.
    const rows = database
      .prepare(
        `SELECT p.id AS pinned_id, p.version AS pinned_version, f.* FROM (${pins}) p
       LEFT JOIN (${findingWithProvenance}) f ON f.id = p.id AND f.repository = ?
       ORDER BY p.position`,
      )
      .iterate(input, repository);
    const findings = Array.from(rows, (row) => {
      if (row.version !== row.pinned_version)
        throw new Error(
          `Finding ${row.pinned_id} version ${row.pinned_version} is missing or has changed. Review the current selection.`,
        );
      return {
        ...fromRow(row),
        ...(row.provenance_json != null && {
          provenance: parseJson(String(row.provenance_json)),
        }),
      };
    });
    return { read: findings.length, excluded: [], ...summary, findings };
  });
}
