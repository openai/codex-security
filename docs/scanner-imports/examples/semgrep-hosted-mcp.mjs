import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join, posix } from "node:path";
import { createInterface } from "node:readline/promises";
import {
  ExternalPublicationError,
  prepareNormalizedExternalPublication,
  prepareNormalizedLocalImport,
} from "@openai/codex-security";

const args = process.argv.slice(2);
const save = args.at(-1) === "--save";
if (save) args.pop();
const [capture, target, cloudRepository] = args;
const toCloud = target === "cloud";
assert(
  capture &&
    target &&
    args.length === (toCloud ? 3 : 2) &&
    (!toCloud || cloudRepository.trim()),
  "Usage: node semgrep-hosted-mcp.mjs CAPTURE.json {CHECKOUT | cloud REPOSITORY_URL_OR_ID} [--save]",
);

function requireScmUrl(value) {
  const url = URL.parse(value);
  assert(
    ["https:", "http:"].includes(url?.protocol) &&
      !url.username &&
      !url.password &&
      !/[?#]/u.test(value),
    "Use an HTTP(S) source-control URL without credentials, query, or fragment.",
  );
}

if (
  toCloud &&
  (URL.parse(cloudRepository)?.host ||
    /^(?:[a-z][a-z\d+.-]*:\/|\/\/|[^@/\s]+@[^/:\s]+:)/iu.test(
      cloudRepository.trim(),
    ))
) {
  requireScmUrl(cloudRepository);
}
const { deploymentId, project, ref, findingIds, issues } = JSON.parse(
  await readFile(capture, "utf8"),
);
requireScmUrl(project.url);
assert(
  Array.isArray(findingIds) && findingIds.length && Array.isArray(issues),
  "Supply the requested findingIds and the original issues[] rows.",
);
assert(
  [deploymentId, project.id, ...findingIds].every(
    (id) => typeof id === "string" && id.trim(),
  ) && ref?.startsWith("refs/"),
  "Use string deployment, project and finding IDs, and a full Git ref.",
);
const missing = new Set(findingIds);
assert.equal(
  missing.size,
  findingIds.length,
  "The requested findingIds contain duplicate IDs.",
);

// Keep the original path in the row even when it cannot be used as a repository location.
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

function text(value) {
  return typeof value === "string" && value.trim() ? value : null;
}

const sourceProject = { id: project.id, name: project.name, url: project.url };
const findings = issues.map((row) => {
  const { issue } = row;
  assert(
    missing.delete(issue?.id),
    `Unexpected or duplicate issue ID: ${JSON.stringify(issue?.id)}`,
  );
  assert(
    issue.repository?.id === project.id &&
      issue.ref === ref &&
      issue.issueType === "ISSUE_TYPE_SAST",
    `Issue ${JSON.stringify(issue.id)} does not match the selected project ID, ref and Code product.`,
  );
  const severity = issue.severity?.replace(/^SEVERITY_/u, "").toLowerCase();
  const rule = text(issue.rulePath);
  const message = text(issue.message);
  const projectedLocations = locations(issue);
  const start = projectedLocations[0]?.line;
  return {
    source_finding_id: issue.id,
    evidence: {
      title: rule ?? `Semgrep issue ${issue.id}`,
      severity: ["critical", "high", "medium", "low"].includes(severity)
        ? severity
        : "unknown",
      description: message,
      branch: ref,
      locations: projectedLocations,
      details: {
        kind: "sast",
        repository: sourceProject,
        ...(start &&
          Number.isSafeInteger(issue.endLine) &&
          issue.endLine >= start && { code: { end_line: issue.endLine } }),
        rule: rule ? { id: rule } : null,
      },
      source_data: { deploymentId, project: sourceProject, row },
    },
  };
});
assert(
  !missing.size,
  `Missing requested issue IDs: ${JSON.stringify([...missing])}`,
);

const selection = { read: findings.length, findings, excluded: [] };
const scope = JSON.stringify([
  "semgrep-hosted-mcp",
  deploymentId,
  project.id,
  ref,
  "sast",
]);
const options = {
  repository: toCloud ? cloudRepository : target,
  provider: "semgrep",
  sourceKey:
    Buffer.byteLength(scope) <= 512
      ? scope
      : "semgrep-hosted-mcp:" +
        createHash("sha256").update(scope).digest("hex"),
};

async function run() {
  if (!toCloud) {
    const local = await prepareNormalizedLocalImport(selection, options, {
      sourceRepositories:
        project.scmType === "SCM_TYPE_GITHUB_ENTERPRISE"
          ? [{ url: project.url, platform: "github" }]
          : [],
    });
    assert(
      existsSync(join(local.preview.repository, ".git")) &&
        local.matchesRepositoryRemote,
      "Pass the Git worktree root with a configured remote for the selected project.",
    );
    return save
      ? local.import()
      : { sourceRepositoryUrl: project.url, ...local.preview };
  }

  const cloud = await prepareNormalizedExternalPublication(selection, options);
  if (!save) return cloud.preview;
  console.error(JSON.stringify(cloud.preview, null, 2));
  const prompt = createInterface({
    input: process.stdin,
    output: process.stderr,
  });
  try {
    const answer = await prompt.question(
      "Publish this selection to the Cloud destination above? [y/N] ",
    );
    if (!/^y(es)?$/iu.test(answer.trim())) return { published: false };
  } finally {
    prompt.close();
  }

  try {
    const result = await cloud.publish();
    if (result.status !== "complete") process.exitCode = 1;
    return result;
  } catch (error) {
    if (!(error instanceof ExternalPublicationError)) throw error;
    process.exitCode = 1;
    return error.result;
  }
}

console.log(JSON.stringify(await run(), null, 2));
