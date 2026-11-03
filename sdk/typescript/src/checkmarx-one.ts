import { checkmarxEvidence } from "./checkmarx-evidence.js";
import type { ExternalFindings } from "./external-findings.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import {
  array,
  normalizeRecords,
  record,
  requiredText,
  stableId,
  text,
} from "./scanner-import.js";

export function checkmarxOneId(value: unknown): string {
  const row = record(value, "Checkmarx One result");
  const type = requiredText(row["type"], "Checkmarx One result type");
  if (type !== "sast")
    throw new Error(
      `Checkmarx One result type ${type} is outside the SAST import.`,
    );
  const data = record(row["data"], "Checkmarx One SAST data");
  return stableId("checkmarx-one", [
    requiredText(row["similarityId"], "Checkmarx One similarityId"),
    requiredText(data["resultHash"], "Checkmarx One resultHash"),
  ]);
}

export function normalizeCheckmarxOne(
  contents: string,
  repository: string,
  target: ExternalImportTarget,
): ExternalFindings {
  const document = record(
    JSON.parse(
      contents,
      (key: string, value: unknown, context?: { source: string }) => {
        // SAST query IDs can be 64-bit integers. Keep their exact digits in evidence.
        if (
          key === "queryId" &&
          typeof value === "number" &&
          Number.isInteger(value) &&
          !Number.isSafeInteger(value)
        )
          return context!.source;
        return value;
      },
    ),
    "Checkmarx One CLI JSON report",
  );
  const scanId = requiredText(document["scanID"], "Checkmarx One scanID");
  const rows =
    document["results"] === null && document["totalCount"] === 0
      ? []
      : array(document["results"], "Checkmarx One results");
  if (document["totalCount"] !== rows.length)
    throw new Error(
      "Checkmarx One totalCount must equal the number of exported results.",
    );
  return normalizeRecords(
    rows,
    (value) => {
      const row = record(value, "Checkmarx One result");
      const data = record(row["data"], "Checkmarx One SAST data");
      const queryId = data["queryId"];
      for (const node of array(data["nodes"] ?? [], "Checkmarx One SAST nodes"))
        record(node, "Checkmarx One SAST node");
      return checkmarxEvidence(
        {
          format: "checkmarx-one-json",
          repository,
          scanId,
          title: requiredText(data["queryName"], "Checkmarx One queryName"),
          ruleId: typeof queryId === "number" ? String(queryId) : text(queryId),
          severity: row["severity"],
          description: text(row["description"]),
          status: text(row["status"]),
          verdict: text(row["state"]),
          cwe: record(
            row["vulnerabilityDetails"] ?? {},
            "Checkmarx One vulnerability details",
          )["cweId"],
          sourceData: { row },
        },
        target,
      );
    },
    checkmarxOneId,
    target,
    {
      report: {
        format: "checkmarx-one-json",
        scanId,
        sourceRepositoryUrl: repository,
        totalCount: rows.length,
      },
    },
  );
}
