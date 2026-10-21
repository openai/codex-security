import type { JsonObject } from "./types.js";

// Match finalize_scan_contract.py's existing retained-JSON and path contract.
// Repository paths are not subject to portable artifact filename restrictions.
const windowsUnsafeComponent =
  /[<>:"|?*\x00-\x1f]|[ .]$|^(?:con|prn|aux|nul|con[iİı]n\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$/iu;

function requirePublicationJson(value: unknown, label: string): void {
  if (typeof value === "string") {
    if (!value.isWellFormed())
      throw new Error(`${label}: expected well-formed Unicode JSON strings`);
  } else if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new Error(`${label}: non-finite JSON numbers are not supported`);
    if (Number.isInteger(value) && !Number.isSafeInteger(value))
      throw new Error(
        `${label}: unsafe integer-valued JSON numbers are not supported`,
      );
  } else if (Array.isArray(value)) {
    value.forEach((item, index) =>
      requirePublicationJson(item, `${label}[${index}]`),
    );
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      requirePublicationJson(key, label);
      requirePublicationJson(item, `${label}.<property>`);
    }
  }
}

function relativeComponents(
  value: string,
  label: string,
  allowDot: boolean,
): string[] {
  requirePublicationJson(value, label);
  const parts = value.split("/");
  const normalized = parts.filter((part) => part !== "" && part !== ".");
  if (
    /^[\p{White_Space}\x1c-\x1f]*$/u.test(value) ||
    (!allowDot && normalized.length === 0) ||
    /^\p{L}:/u.test(value) ||
    /[\\\x00-\x1f]/u.test(value) ||
    value.startsWith("/") ||
    parts.includes("..")
  )
    throw new Error(`${label}: expected a safe repository-relative POSIX path`);
  return normalized;
}

export function coverageReceiptComponents(value: string): string[] {
  const label = "coverage receipt";
  try {
    const parts = relativeComponents(value, label, false);
    if (parts.some((part) => windowsUnsafeComponent.test(part)))
      throw new Error(`${label}: expected a safe scan-relative POSIX path`);
    return parts;
  } catch (error) {
    if (error instanceof Error)
      Object.assign(error, { code: "invalid_coverage_receipt_path" });
    throw error;
  }
}

export function validateRetainedCoverage(coverage: JsonObject): void {
  for (const field of [
    "surfaces",
    "explicitExclusions",
    "deferred",
    "openQuestions",
  ] as const)
    requirePublicationJson(coverage[field], `coverage.${field}`);
  for (const [index, row] of (coverage.deferred as JsonObject[]).entries()) {
    if (Array.isArray(row.paths))
      for (const value of row.paths as string[])
        relativeComponents(value, `coverage.deferred[${index}].paths`, true);
  }
}
