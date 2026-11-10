import { readFile } from "node:fs/promises";
import { posix } from "node:path";
import { prepareNormalizedLocalImport } from "@openai/codex-security";

const [capture, repository, mode, ...extra] = process.argv.slice(2);
if (
  !capture ||
  !repository ||
  (mode !== undefined && mode !== "--save") ||
  extra.length
) {
  throw new Error(
    "Usage: node semgrep-hosted-mcp.mjs CAPTURE.json CHECKOUT [--save]",
  );
}

const { deploymentId, project, ref, findingIds, issues } = JSON.parse(
  await readFile(capture, "utf8"),
);
if (
  typeof deploymentId !== "string" ||
  !deploymentId.trim() ||
  typeof project?.id !== "string" ||
  !project.id.trim() ||
  typeof ref !== "string" ||
  !ref.startsWith("refs/")
) {
  throw new Error(
    "Supply the deployment ID and project ID as strings and the full Git ref.",
  );
}
const scm = new URL(project.url);
if (
  !["https:", "http:"].includes(scm.protocol) ||
  scm.username ||
  scm.password
) {
  throw new Error(
    "Use the project's credential-free HTTP(S) source-control URL.",
  );
}
if (
  !Array.isArray(findingIds) ||
  !findingIds.length ||
  findingIds.some((id) => typeof id !== "string" || !id.trim())
) {
  throw new Error("Set findingIds to the requested nonempty string issue IDs.");
}
const missing = new Set(findingIds);
if (missing.size !== findingIds.length) {
  throw new Error("The requested findingIds contain duplicate IDs.");
}
if (!Array.isArray(issues)) {
  throw new Error(
    "Supply the selected issues[] rows from the hosted MCP response.",
  );
}

// Only project repository-relative files. Other paths stay in the original row.
function locations({ filePath, line }) {
  if (typeof filePath !== "string" || !filePath) return [];
  const path = filePath.replaceAll("\\", "/");
  const normalized = posix.normalize(path);
  if (
    path.includes("\0") ||
    path.split("/").includes("..") ||
    normalized.startsWith("/") ||
    /^(?:[a-z][a-z\d+.-]*:|~[^/]*(?:\/|$)|[^/@]+@[^/]+:)/iu.test(normalized) ||
    normalized === "." ||
    normalized.endsWith("/") ||
    path.endsWith("/.")
  )
    return [];
  return [
    { path: filePath, ...(Number.isSafeInteger(line) && line > 0 && { line }) },
  ];
}

const severities = {
  SEVERITY_CRITICAL: "critical",
  SEVERITY_HIGH: "high",
  SEVERITY_MEDIUM: "medium",
  SEVERITY_LOW: "low",
};

const findings = issues.map((row) => {
  const { issue } = row;
  if (!missing.delete(issue?.id)) {
    throw new Error(
      `Unexpected or duplicate issue ID in the response: ${JSON.stringify(issue?.id)}.`,
    );
  }
  if (
    issue.repository?.id !== project.id ||
    issue.ref !== ref ||
    issue.issueType !== "ISSUE_TYPE_SAST"
  ) {
    throw new Error(
      `Issue ${issue.id} does not match the selected project ID, ref and Code product.`,
    );
  }
  return {
    source_finding_id: issue.id,
    evidence: {
      title: issue.rulePath || issue.message || `Semgrep issue ${issue.id}`,
      severity: severities[issue.severity] ?? "unknown",
      description: issue.message,
      branch: ref,
      locations: locations(issue),
      details: {
        kind: "sast",
        repository: { id: project.id, name: project.name, url: project.url },
        rule: issue.rulePath ? { id: issue.rulePath } : null,
      },
      source_data: { deploymentId, project, row },
    },
  };
});
if (missing.size) {
  throw new Error(
    `Missing requested issue IDs: ${JSON.stringify([...missing])}.`,
  );
}

const prepared = await prepareNormalizedLocalImport(
  { read: issues.length, findings, excluded: [] },
  {
    repository,
    provider: "semgrep",
    sourceKey: JSON.stringify([
      "semgrep-hosted-mcp",
      deploymentId,
      project.id,
      ref,
      "sast",
    ]),
  },
);
if (!prepared.matchesRepositoryRemote) {
  throw new Error(
    "Select a checkout with a configured Git remote matching the project's source-control URL.",
  );
}
console.log(
  JSON.stringify(
    mode === "--save" ? await prepared.import() : prepared.preview,
    null,
    2,
  ),
);
