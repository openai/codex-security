import { hash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { posix } from "node:path";
import { promisify } from "node:util";
import { gunzip } from "node:zlib";
import { CodexSecurityError, errorMessage } from "./errors.js";
import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import { isRecord } from "./record.js";

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
    !/^[A-Za-z]:/.test(path) &&
    !path.split("/").includes("..")
    ? path
    : null;
}

export function repositoryFilePath(value: unknown): string | null {
  const relative = relativePath(value);
  if (!relative) return null;
  const path = posix.normalize(relative);
  return path === "." ||
    path.endsWith("/") ||
    /^(?:[a-z][a-z\d+.-]*:|~[^/]*(?:\/|$)|[^/]+@[^/]+:)/iu.test(path)
    ? null
    : path;
}

export function stableId(prefix: string, fields: unknown[]): string {
  return `${prefix}:${hash("sha256", JSON.stringify(fields))}`;
}

const strictUtf8 = new TextDecoder("utf-8", { fatal: true });
const gunzipAsync = promisify(gunzip);

async function readScannerBytes(path: string): Promise<Buffer> {
  const bytes = await readFile(path);
  return bytes[0] === 0x1f && bytes[1] === 0x8b ? gunzipAsync(bytes) : bytes;
}

export async function readScannerText(path: string): Promise<string> {
  return strictUtf8.decode(await readScannerBytes(path));
}

export function parseJsonOrJsonl(contents: string): unknown {
  try {
    return JSON.parse(contents);
  } catch {
    return contents
      .split(/\r?\n/u)
      .filter((line) => line.trim())
      .map((line) => JSON.parse(line));
  }
}

export async function readScannerJson(path: string): Promise<unknown> {
  const bytes = await readScannerBytes(path);
  let decoded: string;
  try {
    decoded = strictUtf8.decode(bytes);
  } catch (error) {
    throw new CodexSecurityError(
      `Scanner report is not valid UTF-8. ${errorMessage(error)}`,
      { cause: error },
    );
  }
  try {
    return JSON.parse(decoded.replace(/^\uFEFF/u, ""));
  } catch (error) {
    throw new CodexSecurityError(
      `Scanner JSON could not be parsed. ${errorMessage(error)}`,
      { cause: error },
    );
  }
}

/** Empty reference containers and property-bag metadata do not externalize data. */
export function hasSarifExternalPropertyReferences(value: unknown): boolean {
  if (value == null) return false;
  return Object.entries(
    record(value, "SARIF external property references"),
  ).some(
    ([key, references]) =>
      key !== "properties" &&
      (!Array.isArray(references) || references.length > 0),
  );
}

const sarifArtifactLocationFields = new Set([
  "artifactLocation",
  "analysisTarget",
  "executableLocation",
  "workingDirectory",
  "stdin",
  "stdout",
  "stderr",
  "stdoutStderr",
  "mappedTo",
  "displayBase",
]);

/** Keep original artifact indexes; omit only inventory unrelated to this finding. */
export function sarifRunContextForResult(
  runContext: Record<string, unknown>,
  ...selectedEvidence: unknown[]
): Record<string, unknown> {
  const { artifacts, ...context } = runContext;
  if (!Array.isArray(artifacts) || artifacts.length === 0) return runContext;
  const locations: Record<string, unknown>[] = [];
  let hasArtifactLink = false;
  function visit(value: unknown): void {
    if (typeof value === "string") {
      // SARIF message links can refer to an artifact without an artifactLocation.
      if (/sarif:/iu.test(value)) hasArtifactLink = true;
    } else if (Array.isArray(value)) value.forEach(visit);
    else if (isRecord(value))
      for (const [key, child] of Object.entries(value)) {
        if (key === "properties") continue;
        if (sarifArtifactLocationFields.has(key) && isRecord(child))
          locations.push(child);
        if (
          ["locations", "responseFiles", "analysisToolLogFiles"].includes(
            key,
          ) &&
          Array.isArray(child)
        )
          locations.push(...child.filter(isRecord));
        if (key === "originalUriBaseIds" && isRecord(child))
          locations.push(...Object.values(child).filter(isRecord));
        visit(child);
      }
  }
  visit([context, ...selectedEvidence]);
  if (hasArtifactLink) return runContext;
  const unresolvedUri = /[%:\\]|(?:^|\/)\.\.?(?:\/|$)/u;
  for (const location of locations) {
    if (typeof location["index"] === "number" && location["index"] >= 0)
      return runContext;
    if (typeof location["uri"] !== "string") continue;
    for (const artifact of artifacts) {
      if (!isRecord(artifact) || !isRecord(artifact["location"])) continue;
      const candidate = artifact["location"];
      // Keep URI spellings that need resolution; evidence is never rewritten.
      if (
        location["uriBaseId"] !== candidate["uriBaseId"] ||
        unresolvedUri.test(location["uri"]) ||
        (typeof candidate["uri"] === "string" &&
          unresolvedUri.test(candidate["uri"])) ||
        location["uri"] === candidate["uri"]
      )
        return runContext;
    }
  }
  return context;
}

/** Duplicate IDs cannot identify a single rule in this run. */
export function indexSarifRules(rules: Record<string, unknown>[]) {
  const byId = new Map<
    unknown,
    { rule: Record<string, unknown>; index: number } | null
  >();
  for (const [index, rule] of rules.entries()) {
    const id = rule["id"];
    byId.set(id, byId.has(id) ? null : { rule, index });
  }
  return byId;
}

/** Exclude every colliding record: choosing the first could overwrite another occurrence. */
export function normalizeRecords<T>(
  records: T[],
  projectEvidence: (record: T, id: string) => ExternalFinding["evidence"],
  identify: (record: T) => string,
  target: "local" | "cloud" = "cloud",
): ExternalFindings {
  const result: ExternalFindings = {
    read: records.length,
    findings: [],
    excluded: [],
  };
  const identified: { position: number; value: T; id: string }[] = [];
  const counts = new Map<string, number>();
  for (const [index, value] of records.entries()) {
    try {
      const id = identify(value);
      if (
        !id.trim() ||
        id.includes("\0") ||
        (target === "cloud" && Buffer.byteLength(id) > 512)
      )
        throw new Error(
          target === "cloud"
            ? "Source finding ID must contain 1–512 UTF-8 bytes and no NUL characters."
            : "Source finding ID must be nonempty and contain no NUL characters.",
        );
      identified.push({ position: index + 1, value, id });
      counts.set(id, (counts.get(id) ?? 0) + 1);
    } catch (error) {
      result.excluded.push({
        position: index + 1,
        source_finding_id: null,
        reason: errorMessage(error),
      });
    }
  }
  for (const { position, value, id } of identified) {
    if (counts.get(id)! > 1) {
      result.excluded.push({
        position,
        source_finding_id: id,
        reason:
          "Ambiguous duplicate source identity; select one complete finding or separate source projects.",
      });
      continue;
    }
    try {
      result.findings.push({
        source_finding_id: id,
        evidence: projectEvidence(value, id),
      });
    } catch (error) {
      result.excluded.push({
        position,
        source_finding_id: id,
        reason: errorMessage(error),
      });
    }
  }
  result.excluded.sort((a, b) => a.position - b.position);
  return result;
}
