import {
  type ExternalImportTarget,
  validateExternalEvidence,
} from "./external-import-contract.js";
import { CodexSecurityError } from "./errors.js";
import type {
  ExternalFinding,
  ExternalSourceRepository,
} from "./external-findings.js";
import { isRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  record,
  requiredText,
  scannerSeverity,
  stableId,
  text,
} from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";
import {
  platformLocationPath,
  requireSemgrepFullRef,
  selectionRepository,
} from "./semgrep-platform-findings.js";

export const guardianSelectionFormat = "semgrep-guardian-selection/v1";

export const guardianFindingId = /^semgrep-guardian:[0-9a-f]{64}$/u;

function guardianScope(data: Record<string, unknown>) {
  const tool = data["tool"];
  if (
    tool !== "get_semgrep_sast_findings" &&
    tool !== "get_semgrep_supply_chain_findings"
  )
    throw new Error("Select a Guardian SAST or Supply Chain findings tool.");
  const deployment = requiredText(data["deployment"], "Guardian deployment");
  const repository = requiredText(data["repository"], "Guardian repository");
  const ref = requiredText(data["ref"], "Guardian Git ref");
  requireSemgrepFullRef(ref);
  return { tool, deployment, repository, ref };
}

function guardianId(scope: ReturnType<typeof guardianScope>, id: unknown) {
  return stableId("semgrep-guardian", [
    scope.deployment,
    scope.repository,
    scope.tool,
    scope.ref,
    requiredText(id, "Guardian finding ID"),
  ]);
}

export function guardianFindingRepository(
  { source_finding_id, evidence }: ExternalFinding,
  target: ExternalImportTarget,
) {
  const data = evidence.source_data ?? {};
  const generated = guardianFindingId.test(source_finding_id);
  if (data["format"] !== guardianSelectionFormat && !generated) return;
  const row = record(data["finding"], "Original Guardian finding");
  const scope = guardianScope(data);
  requireGuardianRowScope(scope, row);
  if (evidence.branch != null && evidence.branch !== scope.ref)
    throw new CodexSecurityError(
      "The Guardian finding branch does not match the selected ref.",
    );
  if (source_finding_id !== guardianId(scope, row["id"]))
    throw new CodexSecurityError(
      "The normalized finding ID does not match the original Guardian finding.",
    );
  return declaredScannerRepositoryUrl(
    data["sourceRepositoryUrl"],
    "Guardian",
    target,
  );
}

type GuardianTool =
  "get_semgrep_sast_findings" | "get_semgrep_supply_chain_findings";

/** The request passed to the signed-in Guardian MCP client. */
interface GuardianRequest {
  name: GuardianTool;
  arguments: {
    deployment_name: string;
    repository_name: string;
    ref: string;
    states?: string[] | null;
    severities?: string[] | null;
    max_num_findings?: number;
  };
}

function selectionScope(request: unknown, findingIds: unknown) {
  const tool = record(request, "Guardian tool request");
  const args = record(tool["arguments"], "Guardian tool arguments");
  const scope = guardianScope({
    tool: tool["name"],
    deployment: args["deployment_name"],
    repository: args["repository_name"],
    ref: args["ref"],
  });
  const ids = new Set(
    array(findingIds, "Guardian finding IDs").map((id) =>
      requiredText(id, "Guardian finding ID"),
    ),
  );
  if (!ids.size) throw new Error("Select at least one Guardian finding ID.");
  return { ...scope, ids };
}

function requireGuardianRowScope(
  scope: ReturnType<typeof guardianScope>,
  row: Record<string, unknown>,
): void {
  const id = row["id"];
  const repository = record(row["repository"], "Guardian finding repository");
  if (
    repository["name"] !== scope.repository ||
    (row["ref"] != null && row["ref"] !== scope.ref)
  )
    throw new Error(
      `Guardian finding ${id} does not match the selected repository and ref.`,
    );
  const expected = scope.tool === "get_semgrep_sast_findings" ? "sast" : "sca";
  if (
    row["issueType"] != null &&
    text(row["issueType"])
      ?.toLowerCase()
      .replace(/^issue_type_/u, "") !== expected
  )
    throw new Error(
      `Guardian finding ${id} does not match the selected product.`,
    );
}

function selectedRows(
  scope: ReturnType<typeof selectionScope>,
  structuredContent: unknown,
) {
  const { findings } = record(structuredContent, "Guardian structuredContent");
  const rows = new Map<string, Record<string, unknown>>();
  for (const row of array(findings ?? [], "Guardian findings")) {
    if (
      !isRecord(row) ||
      typeof row["id"] !== "string" ||
      !scope.ids.has(row["id"])
    )
      continue;
    const id = row["id"];
    if (rows.has(id))
      throw new Error(`Guardian returned duplicate finding ID ${id}.`);
    requireGuardianRowScope(scope, row);
    rows.set(id, row);
  }
  return Array.from(scope.ids, (id) => {
    const row = rows.get(id);
    if (!row)
      throw new Error(`Guardian did not return selected finding ${id}.`);
    return row;
  });
}

/** Use the caller's connected Guardian MCP client. Only selected rows enter the saved capture. */
export async function collectSelectedSemgrepGuardianFindings(
  selection: {
    request: GuardianRequest;
    findingIds: readonly string[];
    sourceRepositoryUrl: string;
  },
  dependencies: {
    callTool: (request: GuardianRequest) => Promise<unknown>;
    environment?: NodeJS.ProcessEnv;
  },
) {
  const query = structuredClone(selection.request);
  const scope = selectionScope(query, selection.findingIds);
  const sourceRepositoryUrl = declaredScannerRepositoryUrl(
    selection.sourceRepositoryUrl,
    "Guardian",
    "local",
  );
  const result = record(
    await dependencies.callTool(query),
    "Guardian MCP result",
  );
  if (result["isError"]) {
    const content = result["content"];
    const messages = Array.isArray(content)
      ? content
          .map((part: unknown) =>
            isRecord(part) && part["type"] === "text"
              ? text(part["text"])
              : null,
          )
          .filter(Boolean)
      : [];
    throw new Error(messages.join("\n") || "Guardian MCP request failed.");
  }
  return {
    format: guardianSelectionFormat,
    sourceRepositoryUrl,
    request: query,
    findingIds: [...scope.ids],
    structuredContent: {
      findings: selectedRows(scope, result["structuredContent"]),
    },
  };
}

export function normalizeGuardianSelection(
  document: Record<string, unknown>,
  target: ExternalImportTarget,
  declaredUrl?: string,
  references: readonly ExternalSourceRepository[] = [],
) {
  // Guardian returns a repository name. The caller supplies its verified SCM mapping.
  const url = declaredScannerRepositoryUrl(
    document["sourceRepositoryUrl"],
    "Guardian",
    target,
  );
  const repositoryBinding = selectionRepository(url, references, target);
  if (
    declaredUrl !== undefined &&
    repositoryBinding.key(
      declaredScannerRepositoryUrl(declaredUrl, "Guardian", target),
    ) !== repositoryBinding.key(url)
  )
    throw new Error(
      "Guardian selection does not match the declared source repository URL.",
    );
  const scope = selectionScope(document["request"], document["findingIds"]);
  const { tool, deployment, repository, ref } = scope;
  return normalizeRecords(
    selectedRows(scope, document["structuredContent"]),
    (finding) => {
      const rule = text(finding["rulePath"]);
      const message = text(finding["message"]);
      const path = platformLocationPath(finding["filePath"]);
      const line = finding["line"];
      return validateExternalEvidence(
        {
          title: rule ?? message ?? `Semgrep finding ${finding["id"]}`,
          description: message,
          severity: scannerSeverity(
            text(finding["severity"])
              ?.toLowerCase()
              .replace(/^severity_/u, ""),
          ),
          branch: ref,
          locations: path
            ? [{ path, line: line === 0 ? null : (line ?? null) }]
            : [],
          ...(tool === "get_semgrep_sast_findings" && {
            details: {
              kind: "sast",
              scanner_origin: "Semgrep",
              repository: { name: repository, url },
              rule: rule ? { id: rule } : null,
              source_status: text(finding["status"]),
            },
          }),
          source_data: {
            format: guardianSelectionFormat,
            tool,
            deployment,
            repository,
            ref,
            sourceRepositoryUrl: url,
            finding,
          },
        },
        target,
      );
    },
    // Guardian's string ID has not been verified against Web API occurrence IDs.
    (finding) => guardianId(scope, finding["id"]),
    target,
    { report: { format: guardianSelectionFormat, repositoryUrl: url } },
  );
}
