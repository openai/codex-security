import { hash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { gunzip } from "node:zlib";
import { CodexSecurityError, errorMessage } from "./errors.js";
import type { ExternalFinding, ExternalFindings } from "./external-findings.js";

export function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label} must be an object.`);
  return value as Record<string, unknown>;
}

export function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array.`);
  return value;
}

export function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

export function requiredText(value: unknown, label: string): string {
  const result = text(value);
  if (!result) throw new Error(`${label} must be nonempty text.`);
  return result;
}

export function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((v): v is string => text(v) !== null)
    : [];
}

/** Paths that cannot be attributed to a repository stay in original evidence. */
export function relativePath(value: unknown): string | null {
  const path = text(value)?.replaceAll("\\", "/");
  return path &&
    !path.startsWith("/") &&
    !path.includes("\0") &&
    !path.split("/")[0]!.includes(":") &&
    !path.split("/").includes("..")
    ? path
    : null;
}

export function stableId(prefix: string, fields: unknown[]): string {
  return `${prefix}:${hash("sha256", JSON.stringify(fields))}`;
}

export async function readScannerJson(path: string): Promise<unknown> {
  let bytes = await readFile(path);
  if (bytes[0] === 0x1f && bytes[1] === 0x8b)
    bytes = await promisify(gunzip)(bytes);
  try {
    return JSON.parse(bytes.toString("utf8").replace(/^\uFEFF/u, ""));
  } catch (error) {
    throw new CodexSecurityError(
      `Scanner JSON could not be parsed. ${errorMessage(error)}`,
      { cause: error },
    );
  }
}

/** Exclude every colliding record: choosing the first could overwrite another occurrence. */
export function normalizeRecords<T>(
  records: T[],
  normalize: (record: T) => ExternalFinding,
): ExternalFindings {
  const result: ExternalFindings = {
    read: records.length,
    findings: [],
    excluded: [],
  };
  const mapped: { position: number; finding: ExternalFinding }[] = [];
  const counts = new Map<string, number>();
  for (const [index, value] of records.entries()) {
    try {
      const finding = normalize(value);
      const id = finding.source_finding_id;
      if (!id.trim() || id.includes("\0") || Buffer.byteLength(id) > 512)
        throw new Error(
          "Source finding ID must contain 1–512 UTF-8 bytes and no NUL characters.",
        );
      mapped.push({ position: index + 1, finding });
      counts.set(id, (counts.get(id) ?? 0) + 1);
    } catch (error) {
      result.excluded.push({
        position: index + 1,
        source_finding_id: null,
        reason: errorMessage(error),
      });
    }
  }
  for (const { position, finding } of mapped) {
    if (counts.get(finding.source_finding_id)! > 1)
      result.excluded.push({
        position,
        source_finding_id: finding.source_finding_id,
        reason:
          "Ambiguous duplicate source identity; select one complete finding or separate source projects.",
      });
    else result.findings.push(finding);
  }
  result.excluded.sort((a, b) => a.position - b.position);
  return result;
}
