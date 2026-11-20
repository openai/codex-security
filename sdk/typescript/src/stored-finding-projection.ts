import { isDeepStrictEqual } from "node:util";
import { normalizeBlackDuckFindings } from "./blackduck-findings.js";
import {
  continuumIssueFormat,
  normalizeContinuumFindings,
} from "./continuum-findings.js";
import { normalizeEndorFindings } from "./endor-findings.js";
import {
  validateExternalEvidence,
  type ExternalImportTarget,
} from "./external-import-contract.js";
import type { StoredExternalFinding } from "./external-findings-local.js";
import type {
  ExternalFinding,
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
import { normalizeInspectorFindings } from "./inspector-findings.js";
import { projectStoredOpenGrepFinding } from "./opengrep-findings.js";
import { isRecord } from "./record.js";
import { array, normalizeRecords, record } from "./scanner-import.js";
import { storedSemgrepCloudEvidence } from "./semgrep-platform-findings.js";
import { normalizeTrivyFindings } from "./trivy-findings.js";

type StoredRow = Pick<
  StoredExternalFinding,
  "provider" | "sourceFindingId" | "evidence"
>;
type Reader = (target: ExternalImportTarget) => ExternalFindings;

/** Reconstruct only report envelopes for which a native row retains its inputs. */
function* nativeReaders(
  row: StoredRow,
  inspectorMap?: ReadonlyMap<string, string>,
): Generator<Reader> {
  const data = row.evidence.source_data;
  if (!data) return;
  if (row.provider === "endor" && data["uuid"] === row.sourceFindingId)
    yield (target) => normalizeEndorFindings(data, target);
  if (
    row.provider === "trivy" &&
    isRecord(data["report"]) &&
    isRecord(data["result"]) &&
    typeof data["scanRoot"] === "string"
  ) {
    const root = data["scanRoot"];
    const input = {
      ...data["report"],
      Results: [
        {
          ...data["result"],
          Vulnerabilities: [data["vulnerability"]],
          Packages: data["package"] ? [data["package"]] : [],
        },
      ],
    };
    yield (target) => normalizeTrivyFindings(input, target, root);
  }
  const url = data["sourceRepositoryUrl"];
  if (typeof url !== "string") return;
  if (row.provider === "inspector" && isRecord(data["finding"]))
    yield (target) =>
      normalizeInspectorFindings(
        { findings: [data["finding"]] },
        url,
        target,
        inspectorMap,
      );
  if (row.provider === "continuum" && isRecord(data["finding"])) {
    // The list and detail APIs can return the same raw record with different SAST projections.
    const detail = {
      finding: data["finding"],
      patches: data["patches"] ?? [],
      evidenceArtifacts: data["evidence_artifacts"] ?? [],
      validationIssue: data["validation_issue"],
    };
    yield (target) => normalizeContinuumFindings(detail, url, target);
    yield (target) =>
      normalizeContinuumFindings({ items: [data["finding"]] }, url, target);
  }
  const issue = data["issue"];
  if (
    row.provider === "continuum" &&
    data["format"] === continuumIssueFormat &&
    isRecord(issue)
  )
    yield (target) => {
      const artifacts = array(
        data["evidence_artifacts"] ?? [],
        "Continuum issue evidence artifacts",
      );
      const patches = array(data["patches"] ?? [], "Continuum patches").map(
        (patch) => ({
          artifactId: record(patch, "Continuum patch")["artifactId"],
          artifactType: "PATCH",
          body: { patch },
        }),
      );
      return normalizeContinuumFindings(
        {
          format: continuumIssueFormat,
          environmentId: data["environmentId"],
          issues: [
            {
              issue: { ...issue, artifacts: [...artifacts, ...patches] },
              findings: data["findings"],
            },
          ],
        },
        url,
        target,
      );
    };
  if (
    row.provider === "blackduck" &&
    typeof data["projectVersionUrl"] === "string"
  ) {
    const input = {
      totalCount: 1,
      items: [data["row"]],
      _meta: {
        href: data["projectVersionUrl"] + "/vulnerable-bom-components",
        links: [],
      },
    };
    yield (target) => normalizeBlackDuckFindings(input, url, target);
  }
}

function cloudEvidence(
  row: StoredRow,
  finding: ExternalFinding,
  sourceRepositories: readonly ExternalSourceRepository[],
  inspectorMap?: ReadonlyMap<string, string>,
) {
  try {
    return validateExternalEvidence(row.evidence, "cloud");
  } catch (error) {
    if (row.provider === "semgrep") {
      const projected = storedSemgrepCloudEvidence(finding, sourceRepositories);
      if (projected) return validateExternalEvidence(projected, "cloud");
    }
    // Enriched typed fields can exceed Cloud limits while the complete native
    // record fits. Verify the local reader reproduced this reviewed row before
    // allowing its Cloud reader to choose different optional fields.
    for (const read of nativeReaders(row, inspectorMap)) {
      let local: ExternalFindings;
      try {
        local = read("local");
      } catch {
        continue;
      }
      if (!isDeepStrictEqual(local.findings[0], finding)) continue;
      const cloud = read("cloud");
      if (cloud.findings.length) return cloud.findings[0]!.evidence;
    }
    throw error;
  }
}

export function projectStoredFinding(
  row: StoredRow,
  sourceRepositories: readonly ExternalSourceRepository[],
  inspectorMap?: ReadonlyMap<string, string>,
): ExternalFindings {
  const finding = {
    source_finding_id: row.sourceFindingId,
    evidence: row.evidence,
  };
  if (row.provider === "semgrep") {
    const traces = projectStoredOpenGrepFinding(finding);
    if (traces) return traces;
  }
  return normalizeRecords(
    [row],
    () => cloudEvidence(row, finding, sourceRepositories, inspectorMap),
    () => row.sourceFindingId,
    "cloud",
  );
}
