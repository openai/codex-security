import Ajv2020 from "ajv/dist/2020.js";
import schema from "../schemas/external-findings.schema.json" with { type: "json" };
import type {
  ExternalFindingEvidence,
  FindingImportRequest,
  FindingImportReceipt,
  ImportRepositoryPage,
  SourceReportPage,
  SourceReport,
} from "./external-import-models.js";

const ajv = new Ajv2020({
  strict: false,
  validateFormats: false,
  useDefaults: true,
});
const STRING_BYTE_LIMITS: Readonly<Record<string, number>> = {
  description: 65536,
  path: 2048,
  url: 2048,
  manifest_path: 2048,
  client_id: 128,
  next: 4096,
};

// These model constraints are not represented by JSON Schema character limits.
function validateModelStrings(input: unknown): void {
  if (input === null || typeof input !== "object") return;
  if (Array.isArray(input)) {
    for (const item of input) validateModelStrings(item);
    return;
  }
  for (const [field, value] of Object.entries(input)) {
    if (field === "source_data") continue;
    if (typeof value === "string") {
      if (!value.trim() || value.includes("\0"))
        throw new Error(
          `${field} must be nonempty and contain no NUL characters.`,
        );
      const limit = STRING_BYTE_LIMITS[field] ?? 512;
      if (Buffer.byteLength(value) > limit)
        throw new Error(
          `${field} exceeds its Cloud limit of ${limit} UTF-8 bytes.`,
        );
    } else if (
      Array.isArray(value) &&
      value.every((item) => typeof item === "string")
    ) {
      if (value.some((item) => Buffer.byteLength(item) > 512))
        throw new Error(
          `${field} entries exceed the Cloud limit of 512 UTF-8 bytes.`,
        );
    } else validateModelStrings(value);
  }
}

function validator<T>(name: keyof typeof schema.$defs) {
  const check = ajv.compile<T>({
    $defs: schema.$defs,
    $ref: `#/$defs/${name}`,
  });
  return (input: unknown): T => {
    if (!check(input))
      throw new Error(`${name}: ${ajv.errorsText(check.errors)}`);
    validateModelStrings(input);
    return input;
  };
}

const evidence = validator<ExternalFindingEvidence>("ImportedFindingEvidence");
const request = validator<FindingImportRequest>("FindingImportRequest");
export const validateImportReceipt = validator<FindingImportReceipt>(
  "FindingImportReceipt",
);
export const validateRepositories = validator<ImportRepositoryPage>(
  "ImportRepositoryPage",
);
export const validateSourceReports =
  validator<SourceReportPage>("SourceReportPage");
export const validateSourceReport = validator<SourceReport>("SourceReport");

export function validateExternalEvidence(
  input: unknown,
): ExternalFindingEvidence {
  const result = evidence(input);
  for (const location of result.locations ?? []) {
    const path = location.path.replaceAll("\\", "/");
    if (
      path.startsWith("/") ||
      path.split("/")[0]!.includes(":") ||
      path.split("/").includes("..")
    )
      throw new Error("Locations must use repository-relative paths.");
  }
  if (result.url !== null && result.url !== undefined) {
    const url = result.url
      .replace(/[\t\r\n]/gu, "")
      .replace(/^[\u0000-\u0020]+/u, "");
    const authority = /^https?:\/\/([^/?#]+)/iu.exec(url)?.[1];
    if (
      !authority ||
      authority.includes("@") ||
      authority.includes("[") !== authority.includes("]")
    )
      throw new Error(
        "Evidence URLs must be HTTP(S) links without credentials.",
      );
  }
  const pending: [unknown, number][] = [[result, 0]];
  while (pending.length > 0) {
    const [value, depth] = pending.pop()!;
    if (depth > 20)
      throw new Error("Evidence exceeds the Cloud JSON depth limit of 20.");
    if (value !== null && typeof value === "object") {
      for (const child of Object.values(value))
        pending.push([child, depth + 1]);
    } else if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error("Evidence must contain finite JSON numbers.");
    }
  }
  if (Buffer.byteLength(JSON.stringify(result)) > 256 * 1024)
    throw new Error("Evidence exceeds the Cloud limit of 256 KiB.");
  return result;
}

export function validateImportRequest(input: unknown): FindingImportRequest {
  const result = request(input);
  if (
    new Set(result.items.map((item) => item.client_id)).size !==
    result.items.length
  )
    throw new Error("Import contains duplicate client IDs.");
  if (
    new Set(result.items.map((item) => item.source_finding_id)).size !==
    result.items.length
  )
    throw new Error("Import contains duplicate source finding identities.");
  for (const item of result.items) validateExternalEvidence(item.evidence);
  if (Buffer.byteLength(JSON.stringify(result)) > 5 * 1024 * 1024)
    throw new Error("Import exceeds the Cloud limit of 5 MiB.");
  return result;
}
