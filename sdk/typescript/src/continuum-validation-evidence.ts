import { isRecord } from "./record.js";
import { text } from "./scanner-import.js";
import type { ValidationItemRecord } from "./validation-provider.js";

export type ContinuumObservation = {
  siblingOnly?: boolean;
  siblingArtifacts?: string[];
  issueChanged?: boolean;
};

// CLI and workbench receive the original record. Keep retry metadata out of
// the public SDK result, including IDs of skipped evidence for other findings.
export const continuumObservations = new WeakMap<
  ValidationItemRecord,
  ContinuumObservation
>();

/** Distinct issue links in destination-first order. */
export function linkedIssueIds(finding: Record<string, unknown>) {
  const ids = [
    text(finding["mergedIntoIssueId"]),
    text(finding["duplicateOfIssueId"]),
    text(finding["createdIssueId"]),
  ];
  return [...new Set(ids.filter((id) => id !== null))];
}

export function linkedIssueId(finding: Record<string, unknown>) {
  return linkedIssueIds(finding)[0];
}

export function singleFindingValidationIssue(
  issue: unknown,
  issueId: unknown,
  finding: { scope: string; id: string },
) {
  if (!isRecord(issue) || typeof issueId !== "string") return null;
  const arn = `${finding.scope}/code-issues/${issueId}`;
  const ids = issue["findingIds"];
  if (
    issue["issueArn"] !== arn ||
    issue["issueId"] !== issueId ||
    !Array.isArray(ids) ||
    ids.length !== 1 ||
    ids[0] !== finding.id
  )
    return null;
  return { issueArn: arn, issueId, findingIds: [finding.id] };
}

function readVerdict(value: unknown) {
  if (
    value === "EXPLOITABLE" ||
    value === "NOT_EXPLOITABLE" ||
    value === "UNCERTAIN"
  )
    return value;
}

/** Project a bundle to the finding's result or the issue verdict alone. */
export function selectFindingValidationArtifact(
  artifact: Record<string, unknown>,
  findingId: unknown,
) {
  if (artifact["artifactType"] !== "VALIDATION_EVIDENCE") return;
  const body = artifact["body"];
  if (!isRecord(body)) return;
  const validation = body["validationEvidence"];
  if (!isRecord(validation))
    return typeof body["raw"] === "string"
      ? { scope: "issue", artifact }
      : undefined;
  const results = validation["perFindingResults"];
  if (results === undefined) return { scope: "issue", artifact };
  if (!Array.isArray(results))
    throw new Error("Continuum per-finding results must be an array.");
  const matches = results
    .map((value) => {
      if (!isRecord(value))
        throw new Error("Continuum per-finding result must be an object.");
      return value;
    })
    .filter((result) => result["findingId"] === findingId);
  if (matches.length === 0 || typeof findingId !== "string" || !findingId)
    return;
  const findingVerdict =
    matches.length === 1 ? readVerdict(matches[0]!["exploitable"]) : undefined;
  const verdict = findingVerdict ?? readVerdict(validation["exploitable"]);
  if (!verdict) return;
  const artifactId = artifact["artifactId"];
  if (typeof artifactId !== "string" || !artifactId.trim())
    throw new Error(
      "Continuum evidence artifact ID must be a non-empty string.",
    );
  return {
    scope: findingVerdict ? "finding" : "issue",
    artifact: {
      artifactId: artifactId.trim(),
      artifactType: artifact["artifactType"],
      ...(artifact["createdAt"] != null && {
        createdAt: artifact["createdAt"],
      }),
      ...(artifact["mediaType"] != null && {
        mediaType: artifact["mediaType"],
      }),
      ...(artifact["producer"] != null && { producer: artifact["producer"] }),
      body: {
        validationEvidence: {
          ...(typeof validation["terminalStatus"] === "string" && {
            terminalStatus: validation["terminalStatus"],
          }),
          exploitable: verdict,
          ...(findingVerdict && { perFindingResults: matches }),
        },
      },
    },
  };
}
