import { z } from "zod";
import { CodexSecurityError } from "./errors.js";
import type { Provider } from "./external-import-models.js";
import {
  type ExternalImportTarget,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import { isRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  readScannerJson,
  record,
  requiredText,
  stableId,
  text,
} from "./scanner-import.js";
import {
  declaredScannerRepositoryUrl,
  repositoryScopeValidator,
} from "./scanner-repository-url.js";

const count = z.int().nonnegative();
const positive = z.int().positive();
const cvssScore = z
  .union([z.string().trim().min(1), z.number()])
  .pipe(z.coerce.number<string | number>().min(0).max(10));
const scores = ["severity", "cvss"] as const;
const pageMetadata = z.object({
  total_elements: count,
  number: count,
  size: positive,
  total_pages: count,
});
const severityByScore = [
  "informational",
  "low",
  "low",
  "medium",
  "high",
  "critical",
] as const;
const applicationGuid = z.guid().toLowerCase();
const applicationPath = /^\/appsec\/v1\/applications\/([^/]+)$/u;

function integer(value: unknown, label: string, minimum = 0): number {
  const result = (minimum === 0 ? count : positive).safeParse(value);
  if (!result.success)
    throw new Error(
      `Veracode ${label} must be an integer of at least ${minimum}.`,
    );
  return result.data;
}

function guid(value: unknown): string {
  const result = applicationGuid.safeParse(value);
  if (!result.success)
    throw new Error("Expected a Veracode application context GUID.");
  return result.data;
}

function halUrl(value: unknown, label: string): URL {
  const link = record(value, `Veracode ${label} link`);
  const href = requiredText(link["href"], `Veracode ${label} href`);
  const template =
    link["templated"] === true && /\{([?&])[\w]+(?:,[\w]+)*\}$/u.exec(href);
  const concrete = template ? href.slice(0, template.index) : href;
  const parts = /^https?:\/\/([^/?#\\]+)(\/[^?#]*)(?:\?[^#]*)?$/iu.exec(
    concrete,
  );
  const url = URL.parse(concrete);
  if (
    !url ||
    !parts ||
    (template && (template[1] === "&") !== concrete.includes("?")) ||
    parts[1]!.includes("@") ||
    /[{}\\\s\p{Cc}]/u.test(concrete) ||
    parts[2] !== url.pathname
  )
    throw new Error(`Invalid Veracode ${label} HAL URL.`);
  return url;
}

function applicationScope(url: URL) {
  const match = applicationPath.exec(url.pathname);
  if (!match || url.href.includes("?"))
    throw new Error(
      "Expected a Veracode application HAL URL without query parameters.",
    );
  const application = guid(match[1]);
  return {
    origin: url.origin,
    application,
    applicationUrl: `${url.origin}/appsec/v1/applications/${application}`,
  };
}

type Scope = ReturnType<typeof applicationScope>;

function requireApplication(row: Record<string, unknown>, scope: Scope) {
  if (
    row["context_type"] !== "APPLICATION" ||
    guid(row["context_guid"]) !== scope.application
  )
    throw new Error(
      "Veracode findings must belong to the same APPLICATION policy context; sandbox and mixed applications are unsupported.",
    );
}

function occurrenceId(row: Record<string, unknown>, scope: Scope): string {
  if (row["scan_type"] !== "STATIC")
    throw new Error("Only Veracode STATIC findings are supported.");
  return stableId("veracode-static-policy", [
    scope.origin,
    scope.application,
    row["context_type"],
    scope.application,
    integer(row["issue_id"], "issue_id", 1),
  ]);
}

const nativeId = /^veracode-static-policy:[a-f0-9]{64}$/u;

function hasVeracodeRow(row: unknown): boolean {
  return (
    isRecord(row) &&
    "context_guid" in row &&
    "context_type" in row &&
    "scan_type" in row &&
    "issue_id" in row
  );
}

function hasVeracodeEvidence(data: unknown, id: string): boolean {
  if (!isRecord(data)) return false;
  const application =
    typeof data["applicationUrl"] === "string" &&
    applicationPath.test(URL.parse(data["applicationUrl"])?.pathname ?? "");
  const repository = "sourceRepositoryUrl" in data;
  const row = hasVeracodeRow(data["row"]);
  // Other providers can retain a raw vendor row or choose any occurrence ID.
  // Corroborate the native row or ID with its repository and application envelope.
  return (
    (row && (application || repository)) ||
    (nativeId.test(id) && application && repository)
  );
}

function retainedRepository(
  provider: Provider,
  finding: ExternalFinding,
  target: ExternalImportTarget,
): { url: string; scope?: string } | undefined {
  const {
    source_finding_id: id,
    evidence: { source_data: sourceData },
  } = finding;
  if (provider !== "veracode") {
    if (hasVeracodeEvidence(sourceData, id))
      throw new CodexSecurityError(
        "Retained Veracode evidence requires the veracode provider.",
      );
    return;
  }
  const data = isRecord(sourceData) ? sourceData : {};
  const native =
    nativeId.test(id) ||
    hasVeracodeRow(isRecord(data["row"]) ? data["row"] : data);
  if (!native && !("sourceRepositoryUrl" in data)) return;
  const url = declaredScannerRepositoryUrl(
    data["sourceRepositoryUrl"],
    "Veracode",
    target,
  );
  if (!native) return { url };
  const scope = applicationScope(
    halUrl({ href: data["applicationUrl"] }, "retained application"),
  );
  const row = record(data["row"], "Veracode retained finding");
  requireApplication(row, scope);
  if (id !== occurrenceId(row, scope))
    throw new Error(
      "Veracode source finding ID contradicts the retained native occurrence.",
    );
  return { url, scope: scope.applicationUrl };
}

export const veracodeReportRepositories = repositoryScopeValidator(
  { provider: "veracode", label: "Veracode", scope: "application" },
  retainedRepository,
);

function selection(
  url: URL,
  scope: Scope,
  number: number,
  size: number,
  rel: string,
) {
  const match = /^\/appsec\/v2\/applications\/([^/]+)\/findings$/u.exec(
    url.pathname,
  );
  if (
    url.origin !== scope.origin ||
    !match ||
    guid(match[1]) !== scope.application
  )
    throw new Error(
      "Veracode HAL links must identify the same origin and findings application.",
    );
  const query = url.searchParams;
  const scans = query.getAll("scan_type");
  if (
    query.has("context") ||
    query.has("sca_dep_mode") ||
    query.has("sca_scan_mode") ||
    scans.length > 1 ||
    scans.some((type) => type !== "STATIC")
  )
    throw new Error(
      "Only the Veracode STATIC APPLICATION policy selection is supported, not sandbox, DAST or SCA.",
    );
  for (const key of [
    "violates_policy",
    "new",
    "include_annot",
    "include_exp_date",
  ]) {
    const flags = query.getAll(key);
    if (!flags.length) continue;
    if (flags.length !== 1 || !/^(true|false)$/iu.test(flags[0]!))
      throw new Error(`Invalid Veracode ${key} selection.`);
    query.set(key, flags[0]!.toLowerCase());
  }
  for (const key of ["cwe", "finding_category"]) {
    const ids = query
      .getAll(key)
      .flatMap((value) =>
        value.split(",").map((id) => id.replace(/^0+(?=\d)/u, "")),
      );
    if (ids.length) query.set(key, [...new Set(ids)].sort().join(","));
  }
  for (const field of scores) {
    for (const key of [field, `${field}_gte`]) {
      const values = query.getAll(key);
      if (!values.length) continue;
      const value = values[0]!;
      const score =
        field === "severity"
          ? /^[0-5]$/u.test(value) && Number(value)
          : cvssScore.safeParse(value).data;
      if (values.length !== 1 || typeof score !== "number")
        throw new Error(`Invalid Veracode ${key} selection.`);
      query.set(key, String(score));
    }
  }
  // Collection self links may omit pagination. Navigation uses the API defaults.
  for (const [key, expected, defaultValue] of [
    ["page", number, 0],
    ["size", size, 50],
  ] as const) {
    const values = query.getAll(key);
    if (
      values.length
        ? values.length !== 1 || values[0] !== String(expected)
        : rel !== "self" && expected !== defaultValue
    )
      throw new Error(`Veracode HAL ${key} does not match the declared page.`);
    query.delete(key);
  }
  query.sort();
  return query;
}

function readPage(input: unknown) {
  const document = record(input, "Veracode HAL findings page");
  const metadata = pageMetadata.safeParse(
    record(document["page"], "Veracode page metadata"),
  );
  if (!metadata.success) {
    const field = metadata.error.issues[0]!.path[0];
    throw new Error(
      `Veracode page.${String(field)} must be an integer of at least ${field === "size" ? 1 : 0}.`,
    );
  }
  const {
    number,
    size,
    total_pages: pages,
    total_elements: total,
  } = metadata.data;
  const embedded =
    document["_embedded"] === undefined && total === 0
      ? { findings: [] }
      : record(document["_embedded"], "Veracode HAL _embedded");
  if (
    document["error"] != null ||
    (document["status"] != null && document["status"] !== 200) ||
    [document["errors"], embedded["errors"]].some(
      (errors) =>
        errors != null && !(Array.isArray(errors) && errors.length === 0),
    )
  )
    throw new Error(
      "Veracode returned an error, not a complete findings page.",
    );
  const rows = array(embedded["findings"], "Veracode _embedded.findings");
  if (
    !(pages === Math.ceil(total / size) || (total === 0 && pages === 1)) ||
    number >= Math.max(1, pages) ||
    rows.length !== Math.min(size, total - number * size)
  )
    throw new Error("Incomplete or inconsistent Veracode HAL page counts.");
  const links = record(document["_links"], "Veracode HAL _links");
  const scope = applicationScope(halUrl(links["application"], "application"));
  const query = selection(
    halUrl(links["self"], "self"),
    scope,
    number,
    size,
    "self",
  );
  const filter = query.toString();
  const positions: Record<string, number> = {
    first: 0,
    last: Math.max(0, pages - 1),
    next: number + 1,
    prev: number - 1,
    previous: number - 1,
  };
  for (const [rel, link] of Object.entries(links)) {
    if (rel === "application" || rel === "self") continue;
    if (Object.hasOwn(positions, rel)) {
      const position = positions[rel]!;
      if (
        position < 0 ||
        position >= Math.max(1, pages) ||
        selection(halUrl(link, rel), scope, position, size, rel).toString() !==
          filter
      )
        throw new Error(
          `Contradictory Veracode ${rel} page link or selection.`,
        );
    } else {
      for (const reference of Array.isArray(link) ? link : [link]) {
        const url = halUrl(reference, rel);
        const app = /^\/appsec\/v[12]\/applications\/([^/]+)/u.exec(
          url.pathname,
        );
        if (
          url.origin !== scope.origin ||
          (app && guid(app[1]) !== scope.application)
        )
          throw new Error(
            `Veracode ${rel} link contradicts the origin or application.`,
          );
      }
    }
  }
  return { rows, scope, query, filter, number, size, total, pages };
}

function readReport(input: unknown) {
  const pages = (Array.isArray(input) ? input : [input])
    .map(readPage)
    .sort((left, right) => left.number - right.number);
  const first = pages[0];
  if (
    !first ||
    pages.length !== Math.max(1, first.pages) ||
    pages.some(
      (page, index) =>
        page.number !== index ||
        page.total !== first.total ||
        page.size !== first.size ||
        page.scope.applicationUrl !== first.scope.applicationUrl ||
        page.filter !== first.filter,
    )
  )
    throw new Error(
      "Supply every Veracode page exactly once with stable totals, selection, origin and application context.",
    );
  const { scope, query } = first;
  const selectedScores = scores.filter(
    (field) => query.has(field) || query.has(`${field}_gte`),
  );
  const staticOnly = query.has("scan_type");
  const violates = query.get("violates_policy");
  const newOnly = query.get("new") === "true";
  const cwes = query.get("cwe")?.split(",");
  const categories = query.get("finding_category")?.split(",");
  const seen = new Set<string>();
  const rows: Record<string, unknown>[] = [];
  for (const page of pages) {
    for (const value of page.rows) {
      const row = record(value, "Veracode finding");
      requireApplication(row, scope);
      if (
        newOnly &&
        record(row["finding_status"], "Veracode finding_status")["new"] !== true
      )
        throw new Error("Veracode finding contradicts the new selection.");
      if (
        query.get("include_annot") === "false" &&
        Array.isArray(row["annotations"]) &&
        row["annotations"].length
      )
        throw new Error(
          "Veracode finding contradicts the include_annot selection.",
        );
      if (cwes || categories || selectedScores.length) {
        const details = record(
          row["finding_details"],
          "Veracode finding_details",
        );
        for (const [field, ids] of [
          ["cwe", cwes],
          ["finding_category", categories],
        ] as const) {
          if (!ids || row["scan_type"] !== "STATIC") continue;
          const entry = record(details[field], `Veracode ${field}`);
          const id = integer(entry["id"], `${field} ID`);
          if (!ids.includes(String(id)))
            throw new Error(
              `Veracode finding contradicts the ${field} selection.`,
            );
        }
        for (const field of selectedScores) {
          const score =
            field === "severity"
              ? integer(details[field], field)
              : cvssScore.safeParse(details[field]).data;
          const exact = query.get(field);
          const minimum = query.get(`${field}_gte`);
          if (
            score === undefined ||
            (exact !== null && score !== Number(exact)) ||
            (minimum !== null && score < Number(minimum))
          )
            throw new Error(
              `Veracode finding contradicts the ${field} selection.`,
            );
        }
      }
      if (staticOnly && row["scan_type"] !== "STATIC")
        throw new Error(
          "Veracode finding contradicts the requested STATIC scan type.",
        );
      if (violates !== null && row["violates_policy"] !== (violates === "true"))
        throw new Error(
          "Veracode finding contradicts the violates_policy selection.",
        );

      const issue = row["issue_id"];
      if (
        typeof row["scan_type"] === "string" &&
        positive.safeParse(issue).success
      ) {
        const key = `${row["scan_type"]}:${issue}`;
        if (seen.has(key))
          throw new Error(
            "Overlapping Veracode findings repeat a native issue; recollect the complete selection.",
          );
        seen.add(key);
      }
      rows.push(row);
    }
  }
  return { scope, rows };
}

export function normalizeVeracodeFindings(
  input: unknown,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const repository = declaredScannerRepositoryUrl(
    sourceRepositoryUrl,
    "Veracode",
    target,
  );
  const { scope, rows } = readReport(input);
  return normalizeRecords(
    rows,
    (row) => {
      const details = record(
        row["finding_details"],
        "Veracode finding_details",
      );
      const status = record(row["finding_status"], "Veracode finding_status");
      const cwe = record(details["cwe"], "Veracode CWE");
      const weakness = `CWE-${integer(cwe["id"], "CWE ID", 1)}`;
      const category =
        details["finding_category"] == null
          ? null
          : record(details["finding_category"], "Veracode finding category");
      const severity =
        severityByScore[integer(details["severity"], "severity")];
      if (!severity)
        throw new Error("Veracode severity must be on the native 0–5 scale.");
      return validateExternalEvidence(
        {
          title: text(category?.["name"]) ?? text(cwe["name"]) ?? weakness,
          severity,
          description: text(row["description"]),
          details: {
            kind: "sast",
            repository: { url: repository },
            source_status: requiredText(
              status["status"],
              "Veracode finding status",
            ),
            weakness_ids: [weakness],
          },
          source_data: structuredClone({
            sourceRepositoryUrl: repository,
            applicationUrl: scope.applicationUrl,
            row,
          }),
        },
        target,
      );
    },
    (row) => occurrenceId(row, scope),
    target,
  );
}

export async function readVeracodeFindings(
  path: string,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): Promise<ExternalFindings> {
  return normalizeVeracodeFindings(
    await readScannerJson(path),
    sourceRepositoryUrl,
    target,
  );
}
