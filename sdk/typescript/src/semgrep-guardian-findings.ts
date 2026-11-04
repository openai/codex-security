import {
  repositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import { requireExternalImports } from "./external-imports-feature.js";
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
} from "./semgrep-platform-findings.js";

export const guardianSelectionFormat = "semgrep-guardian-selection/v1";

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
  const name = tool["name"];
  if (
    name !== "get_semgrep_sast_findings" &&
    name !== "get_semgrep_supply_chain_findings"
  )
    throw new Error("Select a Guardian SAST or Supply Chain findings tool.");
  const args = record(tool["arguments"], "Guardian tool arguments");
  const deployment = requiredText(
    args["deployment_name"],
    "Guardian deployment",
  );
  const repository = requiredText(
    args["repository_name"],
    "Guardian repository",
  );
  const ref = requiredText(args["ref"], "Guardian Git ref");
  requireSemgrepFullRef(ref);
  const ids = new Set(
    array(findingIds, "Guardian finding IDs").map((id) =>
      requiredText(id, "Guardian finding ID"),
    ),
  );
  if (!ids.size) throw new Error("Select at least one Guardian finding ID.");
  return { tool: name, deployment, repository, ref, ids };
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
    const repository = record(row["repository"], "Guardian finding repository");
    if (
      repository["name"] !== scope.repository ||
      (row["ref"] != null && row["ref"] !== scope.ref)
    )
      throw new Error(
        `Guardian finding ${id} does not match the selected repository and ref.`,
      );
    const expected =
      scope.tool === "get_semgrep_sast_findings" ? "sast" : "sca";
    if (
      row["issueType"] != null &&
      text(row["issueType"])
        ?.toLowerCase()
        .replace(/^issue_type_/u, "") !== expected
    )
      throw new Error(
        `Guardian finding ${id} does not match the selected product.`,
      );
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
  requireExternalImports(dependencies.environment);
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
  declaredUrl?: string,
) {
  // Guardian returns a repository name. The caller supplies its verified SCM mapping.
  const url = declaredScannerRepositoryUrl(
    document["sourceRepositoryUrl"],
    "Guardian",
    "local",
  );
  if (
    declaredUrl !== undefined &&
    repositoryUrlKey(
      declaredScannerRepositoryUrl(declaredUrl, "Guardian", "local"),
    ) !== repositoryUrlKey(url)
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
        "local",
      );
    },
    // Guardian's string ID has not been verified against Web API occurrence IDs.
    (finding) =>
      stableId("semgrep-guardian", [
        deployment,
        repository,
        tool,
        ref,
        finding["id"],
      ]),
    "local",
    { report: { format: guardianSelectionFormat, repositoryUrl: url } },
  );
}
