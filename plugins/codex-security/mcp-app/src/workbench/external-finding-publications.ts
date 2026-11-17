import type { DatabaseSync } from "node:sqlite";
import { requireRepository, requireText } from "./external-findings";
import { transaction } from "./transaction";

export interface ExternalPublicationLinks {
  repository: string;
  cloudApiUrl: string;
  accountId: string;
  destinationId: string;
  entries: {
    id: string;
    version: number;
    receiptId: string;
    outcome: "created" | "updated" | "unchanged" | "private_job";
    cloudFindingId?: string;
  }[];
}

export function recordExternalFindingPublications(
  database: DatabaseSync,
  input: ExternalPublicationLinks,
  timestamp: string,
) {
  requireRepository(input?.repository);
  requireText(input.cloudApiUrl, "cloudApiUrl");
  requireText(input.accountId, "accountId");
  requireText(input.destinationId, "destinationId");
  if (!Array.isArray(input.entries))
    throw new TypeError("entries must be an array.");
  return transaction(database, "BEGIN IMMEDIATE", () => {
    // The reviewed version may have been superseded during upload. Every
    // positive revision through the current version existed in this repository.
    const lookup = database.prepare(
      "SELECT 1 FROM external_source_reports WHERE id = ? AND repository = ? AND version >= ?",
    );
    const insert = database.prepare(
      `INSERT INTO external_finding_publications
       (finding_id, version, cloud_api_url, account_id, destination_id, receipt_id, outcome, cloud_finding_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
    );
    let recorded = 0;
    for (const {
      id,
      version,
      receiptId,
      outcome,
      cloudFindingId,
    } of input.entries) {
      requireText(id, "id");
      requireText(receiptId, "receiptId");
      if (cloudFindingId !== undefined)
        requireText(cloudFindingId, "cloudFindingId");
      if (
        !Number.isSafeInteger(version) ||
        version < 1 ||
        !lookup.get(id, input.repository, version)
      )
        throw new Error(
          `No finding ${id} at version ${version} in the selected repository.`,
        );
      if (!["created", "updated", "unchanged", "private_job"].includes(outcome))
        throw new TypeError("Unknown external publication outcome.");
      recorded += Number(
        insert.run(
          id,
          version,
          input.cloudApiUrl,
          input.accountId,
          input.destinationId,
          receiptId,
          outcome,
          cloudFindingId ?? null,
          timestamp,
        ).changes,
      );
    }
    return { recorded };
  });
}

export function listExternalFindingPublications(
  database: DatabaseSync,
  input: { repository: string; id?: string },
) {
  requireRepository(input?.repository);
  if (input.id !== undefined) requireText(input.id, "id");
  const query = database.prepare(
    `SELECT p.finding_id AS id, p.version, p.cloud_api_url AS cloudApiUrl, p.account_id AS accountId,
       p.destination_id AS destinationId, p.receipt_id AS receiptId, p.outcome, p.cloud_finding_id AS cloudFindingId,
       p.created_at AS createdAt FROM external_finding_publications p
       JOIN external_source_reports f ON f.id = p.finding_id WHERE f.repository = ?
       ${input.id === undefined ? "" : "AND p.finding_id = ?"}
       ORDER BY p.created_at DESC, p.receipt_id, p.finding_id`,
  );
  const rows =
    input.id === undefined
      ? query.all(input.repository)
      : query.all(input.repository, input.id);
  return {
    publications: rows.map(({ cloudFindingId, ...row }) => ({
      ...row,
      ...(cloudFindingId == null ? {} : { cloudFindingId }),
    })),
  };
}
