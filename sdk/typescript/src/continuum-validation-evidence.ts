import { isRecord } from "./record.js";

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

/** Project a bundled proof to the submitted finding, never another finding's proof. */
export function selectFindingValidationArtifact(
  artifact: Record<string, unknown>,
  findingId: unknown,
) {
  if (artifact["artifactType"] !== "VALIDATION_EVIDENCE") return;
  const body = artifact["body"];
  if (!isRecord(body)) return;
  const validation = body["validationEvidence"];
  if (!isRecord(validation) && typeof body["raw"] !== "string") return;
  const results = isRecord(validation)
    ? validation["perFindingResults"]
    : undefined;
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
  if (matches.length === 0) return;
  const artifactId = artifact["artifactId"];
  if (typeof artifactId !== "string" || !artifactId.trim())
    throw new Error(
      "Continuum evidence artifact ID must be a non-empty string.",
    );
  return {
    scope: "finding",
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
          ...(matches.length === 1 &&
            "exploitable" in matches[0]! && {
              exploitable: matches[0]!["exploitable"],
            }),
          perFindingResults: matches,
        },
      },
    },
  };
}
