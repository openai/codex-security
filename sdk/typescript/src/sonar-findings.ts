import { z } from "zod";
import {
  cloudRepositoryUrlKey,
  type ExternalImportTarget,
  repositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import type { Severity } from "./external-import-models.js";
import { isRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  readScannerJson,
  record,
  relativePath,
  requiredText,
  text,
} from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";

const captureText = z.string().refine((value) => Boolean(value.trim()));
const captureSchema = z.object({
  format: z.literal("sonar-issues/v1"),
  server: captureText,
  organization: captureText,
  project: captureText,
  branch: captureText.optional(),
  pullRequest: captureText.optional(),
  repositoryUrl: captureText.optional(),
  projectBase: z
    .string()
    .refine((path) => path === "" || relativePath(path) === path)
    .optional(),
  pages: z.array(z.unknown()).min(1),
});
export type SonarCapture = z.infer<typeof captureSchema>;

export function parseSonarCapture(value: unknown): SonarCapture {
  const capture = captureSchema.parse(value);
  if (capture.branch && capture.pullRequest)
    throw new Error(
      "A Sonar capture must select a branch or a pull request, not both.",
    );
  const url = URL.parse(capture.server);
  if (
    !url ||
    !["https:", "http:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  )
    throw new Error(
      "Expected an HTTP(S) Sonar server URL without credentials, query or fragment.",
    );
  capture.server = url.href.replace(/\/$/u, "");
  if (capture.repositoryUrl)
    declaredScannerRepositoryUrl(capture.repositoryUrl, "Sonar", "local");
  return capture;
}

type NativeRecord = Record<string, unknown>;

const pagingSchema = z.object({
  pageIndex: z.int().positive(),
  pageSize: z.int().positive(),
  total: z.int().nonnegative(),
});

function indexByKey(value: unknown, label: string) {
  const index = new Map<string, NativeRecord>();
  for (const item of array(value ?? [], label)) {
    const row = record(item, label);
    const key = requiredText(row["key"], `${label} key`);
    index.set(key, row);
  }
  return index;
}

function readPage(value: unknown) {
  const page = record(value, "Sonar issue search page");
  return {
    paging: pagingSchema.parse(page["paging"]),
    issues: array(page["issues"], "Sonar issues").map((issue) =>
      record(issue, "Sonar issue"),
    ),
    components: indexByKey(page["components"], "Sonar component"),
    rules: indexByKey(page["rules"], "Sonar rule"),
  };
}

export function completeSonarPages(values: unknown[]) {
  const pages = values
    .map(readPage)
    .sort((a, b) => a.paging.pageIndex - b.paging.pageIndex);
  const first = pages[0]?.paging;
  if (
    !first ||
    pages.length !== Math.max(1, Math.ceil(first.total / first.pageSize)) ||
    pages.some(
      ({ paging, issues }, i) =>
        paging.pageIndex !== i + 1 ||
        paging.total !== first.total ||
        paging.pageSize !== first.pageSize ||
        issues.length !==
          Math.min(first.pageSize, first.total - i * first.pageSize),
    )
  )
    throw new Error(
      "Supply every Sonar issue search page exactly once, with consistent paging and issue counts.",
    );
  const ids = new Set<string>();
  for (const { issues } of pages) {
    for (const issue of issues) {
      const id = text(issue["key"]);
      if (id && ids.has(id))
        throw new Error(
          "Sonar issue search pages overlap. Collect the selection again.",
        );
      if (id) ids.add(id);
    }
  }
  return pages;
}

const severityLevels: Readonly<Record<string, Severity>> = {
  BLOCKER: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "informational",
  CRITICAL: "high",
  MAJOR: "medium",
  MINOR: "low",
};

function securitySeverity(issue: NativeRecord): Severity {
  const impacts = array(issue["impacts"] ?? [], "Sonar issue impacts");
  const security = impacts.find(
    (impact) => isRecord(impact) && impact["softwareQuality"] === "SECURITY",
  );
  if (
    !isRecord(security) &&
    (impacts.length || issue["type"] !== "VULNERABILITY")
  )
    throw new Error(
      "Sonar issue has no security impact or legacy vulnerability type.",
    );
  const value = isRecord(security) ? security["severity"] : issue["severity"];
  return typeof value === "string" && Object.hasOwn(severityLevels, value)
    ? severityLevels[value]!
    : "unknown";
}

function relatedComponents(
  issue: NativeRecord,
  primary: string,
  components: Map<string, NativeRecord>,
) {
  const keys = new Set([primary]);
  for (const value of array(issue["flows"] ?? [], "Sonar issue flows")) {
    const flow = record(value, "Sonar flow");
    for (const entry of array(flow["locations"], "Sonar flow locations")) {
      const location = record(entry, "Sonar flow location");
      const key = text(location["component"]);
      if (key) keys.add(key);
    }
  }
  return Array.from(keys).flatMap((key) => components.get(key) ?? []);
}

function issueLink(
  server: string,
  project: string,
  id: string,
  branch?: string,
  pullRequest?: string,
) {
  const link = new URL("project/issues", server + "/");
  link.searchParams.set("id", project);
  if (branch) link.searchParams.set("branch", branch);
  if (pullRequest) link.searchParams.set("pullRequest", pullRequest);
  link.searchParams.set("open", id);
  link.searchParams.set("issues", id);
  return link.href;
}

export function normalizeSonarFindings(
  input: unknown,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const capture =
    isRecord(input) && "format" in input ? parseSonarCapture(input) : undefined;
  const repository = declaredScannerRepositoryUrl(
    capture?.repositoryUrl ?? sourceRepositoryUrl,
    "Sonar",
    target,
  );
  if (capture?.repositoryUrl && sourceRepositoryUrl) {
    const key = target === "cloud" ? cloudRepositoryUrlKey : repositoryUrlKey;
    if (
      key(repository) !==
      key(declaredScannerRepositoryUrl(sourceRepositoryUrl, "Sonar", target))
    )
      throw new Error(
        "The Sonar capture repository does not match the declared source repository.",
      );
  }
  const pages = completeSonarPages(
    capture?.pages ?? (Array.isArray(input) ? input : [input]),
  );
  const rows = pages.flatMap((page) =>
    page.issues.map((issue) => ({ issue, page })),
  );
  const scope = {
    project: capture?.project,
    organization: capture?.organization,
    branch: capture?.branch,
    pullRequest: capture?.pullRequest,
  };
  for (const { issue } of rows) {
    requiredText(issue["project"], "Sonar issue project");
    for (const field of [
      "project",
      "organization",
      "branch",
      "pullRequest",
    ] as const) {
      const value = text(issue[field]);
      if (value === null) continue;
      if (scope[field] !== undefined && scope[field] !== value)
        throw new Error(
          `The Sonar export contains conflicting ${field} values.`,
        );
      scope[field] = value;
    }
    if (scope.branch && scope.pullRequest)
      throw new Error(
        "The Sonar export mixes branch and pull request results.",
      );
  }
  const context = {
    format: "sonar-issues/v1",
    ...(capture && { server: capture.server }),
    ...(capture?.projectBase !== undefined && {
      projectBase: capture.projectBase,
    }),
    ...scope,
    repositoryUrl: repository,
  };
  const result = normalizeRecords(
    rows,
    ({ issue, page }, id) => {
      const component = requiredText(
        issue["component"],
        "Sonar issue component",
      );
      const componentPath = relativePath(
        page.components.get(component)?.["path"],
      );
      const base = capture?.projectBase;
      const path =
        componentPath && base !== undefined
          ? base
            ? `${base}/${componentPath}`
            : componentPath
          : null;
      const range =
        issue["textRange"] == null
          ? null
          : record(issue["textRange"], "Sonar issue textRange");
      const line = range?.["startLine"] ?? issue["line"] ?? null;
      const rule = requiredText(issue["rule"], "Sonar issue rule");
      const descriptor = page.rules.get(rule);
      const name = text(descriptor?.["name"]);
      const updated = text(issue["updateDate"]);
      const severity = securitySeverity(issue);
      if (target === "cloud" && severity === "unknown")
        throw new Error(
          "Codex Security Cloud requires a recognized Sonar security severity. The issue can be imported locally.",
        );
      return validateExternalEvidence(
        {
          title: name ?? rule,
          severity,
          description: text(issue["message"]),
          url: capture
            ? issueLink(
                capture.server,
                capture.project,
                id,
                scope.branch,
                scope.pullRequest,
              )
            : null,
          locations: path ? [{ path, line }] : [],
          branch: scope.branch ?? null,
          source_updated_at: updated
            ? Math.floor(Date.parse(updated) / 1000)
            : null,
          details: {
            kind: "sast",
            scanner_origin: "SonarQube",
            repository: { url: repository },
            source_status: text(issue["issueStatus"]) ?? text(issue["status"]),
            rule: { id: rule, name },
            code: { end_line: path ? (range?.["endLine"] ?? null) : null },
          },
          source_data: structuredClone({
            ...context,
            issue,
            components: relatedComponents(issue, component, page.components),
            ...(descriptor && { rule: descriptor }),
          }),
        },
        target,
      );
    },
    ({ issue }) => requiredText(issue["key"], "Sonar issue key"),
    target,
  );
  return { ...result, report: context };
}

export async function readSonarFindings(
  path: string,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): Promise<ExternalFindings> {
  return normalizeSonarFindings(
    await readScannerJson(path),
    sourceRepositoryUrl,
    target,
  );
}
