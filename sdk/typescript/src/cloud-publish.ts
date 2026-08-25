import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { basename, isAbsolute, join, posix } from "node:path";
import { z } from "incur";
import Papa from "papaparse";
import { parse as parseToml } from "smol-toml";
import { loadContract } from "./contract.js";
import { AuthenticationRequiredError, CodexSecurityError } from "./errors.js";
import type { Finding, ScanManifest } from "./models.js";
import {
  bundledPluginRoot,
  codexSecurityCredentialAllowsAmbientImport,
  codexSecurityCredentialHome,
  codexSecurityHasStoredFileCredentials,
  expandHome,
} from "./runtime.js";
import { VERSION } from "./version.js";

const CLOUD_PUBLISH_URL =
  "https://chatgpt.com/backend-api/aardvark/cli/findings";
const CSV_TARGET_ID = "codex-security-csv-import";
const CHATGPT_LOGIN_REQUIRED =
  "Cloud publication requires a ChatGPT login already available to Codex Security. Run a scan or sign in with ChatGPT using Codex file credential storage, then retry.";

const credentialsSchema = z.object({
  auth_mode: z.literal("chatgpt").optional(),
  OPENAI_API_KEY: z.null().optional(),
  tokens: z.object({
    access_token: z.string().trim().min(1),
    account_id: z.string().trim().min(1),
  }),
});

const receiptSchema = z.object({
  status: z.literal("accepted"),
  finding_ids: z.array(z.string().min(1)),
  finding_count: z.number().int().positive(),
});

export interface CloudPublicationResult {
  scanId: string;
  findingIds: string[];
  findingCount: number;
  dryRun?: true;
  findings?: Finding[];
}

interface CloudPublicationDependencies {
  environment?: NodeJS.ProcessEnv;
  fetch?: (url: string, options: RequestInit) => Promise<Response>;
  signal?: AbortSignal;
  dryRun?: boolean;
}

interface CsvFindingRow {
  occurrenceId: string;
  findingId: string;
  candidateId?: string;
  title: string;
  summary: string;
  severity: Finding["severity"]["level"];
  confidence: Finding["confidence"]["level"];
  status: "open" | "closed";
  closeReason?: "already_fixed" | "wont_fix" | "false_positive";
  note?: string;
  remediation: string;
  path: string;
  startLine: number;
  endLine?: number;
}

const REQUIRED_CSV_COLUMNS = [
  "occurrence_id",
  "finding_id",
  "title",
  "summary",
  "severity",
  "confidence",
  "status",
  "close_reason",
  "note",
  "remediation",
  "path",
  "start_line",
  "end_line",
] as const;
const OPTIONAL_CSV_COLUMNS = ["candidate_id"] as const;
const FINDING_ID = /^csf_[a-f0-9]{24}$/u;
const OCCURRENCE_ID = /^occ_[a-f0-9]{24}$/u;
const SEVERITIES = new Set<Finding["severity"]["level"]>([
  "critical",
  "high",
  "medium",
  "low",
  "informational",
]);
const CONFIDENCES = new Set<Finding["confidence"]["level"]>([
  "high",
  "medium",
  "low",
]);
const CLOSE_REASONS = new Set<NonNullable<CsvFindingRow["closeReason"]>>([
  "already_fixed",
  "wont_fix",
  "false_positive",
]);

export async function publishScanToCloud(
  scanDirectory: string,
  dependencies: CloudPublicationDependencies & {
    expectedScanId?: string;
  } = {},
): Promise<CloudPublicationResult> {
  const { manifest, findings } = await loadContract(scanDirectory, {
    pluginRoot: await bundledPluginRoot(),
    signal: dependencies.signal,
    expectedScanId: dependencies.expectedScanId,
  });
  if (findings.findings.length === 0) {
    throw new CodexSecurityError(
      "The completed scan has no findings to publish.",
    );
  }
  return publishCloudPayload(manifest.scan, findings.findings, dependencies);
}

export async function publishFindingsCsvToCloud(
  csvPath: string,
  dependencies: CloudPublicationDependencies & {
    now?: () => number;
  } = {},
): Promise<CloudPublicationResult> {
  dependencies.signal?.throwIfAborted();
  let source: string;
  try {
    source = await readFile(csvPath, "utf8");
  } catch (error) {
    throw new CodexSecurityError("Could not read findings CSV.", {
      cause: error,
    });
  }
  dependencies.signal?.throwIfAborted();
  const rows = parseFindingsCsv(source);
  const digest = sha256(source);
  const scanId = `scan_csv_${digest.slice(0, 24)}`;
  const findings = rows.map((row) => csvRowFinding(row, scanId));
  const timestamp = new Date((dependencies.now ?? Date.now)()).toISOString();
  const findingsDocument = JSON.stringify({
    documentType: "codex-security.findings",
    schemaVersion: "1.0",
    scanId,
    findings,
  });
  const coverageDocument = JSON.stringify({
    documentType: "codex-security.coverage",
    schemaVersion: "1.0",
    scanId,
    mode: "repository",
    completeness: "unknown",
    inventoryStrategy: "custom",
    includePaths: ["."],
    excludePaths: [],
    surfaces: findings.map((finding) => ({
      id: finding.occurrenceId,
      label: finding.title,
      disposition: "reported",
      receiptRefs: [],
    })),
    explicitExclusions: [],
    deferred: [],
  });
  const scan: ScanManifest["scan"] = {
    id: scanId,
    producer: { name: "codex-security-cli", version: VERSION },
    status: "completed",
    startedAt: timestamp,
    completedAt: timestamp,
    sealedAt: timestamp,
    target: {
      kind: "directory_snapshot",
      targetId: CSV_TARGET_ID,
      displayName: basename(csvPath),
      snapshotDigest: `codex-security-snapshot/v1:sha256:${digest}`,
    },
    scope: {
      includePaths: ["."],
      excludePaths: [],
      summary: "Findings imported from a Codex Security CSV export.",
    },
    coverageRef: "coverage.json",
    findingsRef: "findings.json",
    artifacts: [
      {
        path: "findings.json",
        sha256: sha256(findingsDocument),
        mediaType: "application/json",
      },
      {
        path: "coverage.json",
        sha256: sha256(coverageDocument),
        mediaType: "application/json",
      },
      {
        path: "findings.csv",
        sha256: digest,
        mediaType: "text/csv",
      },
    ],
  };
  return publishCloudPayload(scan, findings, dependencies);
}

function parseFindingsCsv(source: string): CsvFindingRow[] {
  const { data: rows, errors } = Papa.parse<string[]>(source, {
    delimiter: ",",
    skipEmptyLines: "greedy",
  });
  if (errors.length > 0) {
    throw new CodexSecurityError(
      `Findings CSV could not be parsed: ${errors[0]!.message}`,
    );
  }
  const headers = rows.shift();
  const allowed = new Set<string>([
    ...REQUIRED_CSV_COLUMNS,
    ...OPTIONAL_CSV_COLUMNS,
  ]);
  if (
    headers === undefined ||
    !REQUIRED_CSV_COLUMNS.every((name) => headers.includes(name)) ||
    headers.some((name) => !allowed.has(name)) ||
    new Set(headers).size !== headers.length
  ) {
    throw new CodexSecurityError(
      `Findings CSV must use the Codex Security export columns: ${REQUIRED_CSV_COLUMNS.join(", ")} (candidate_id is optional).`,
    );
  }
  if (rows.length === 0) {
    throw new CodexSecurityError(
      "Findings CSV must contain at least one finding.",
    );
  }

  const findingIds = new Set<string>();
  const occurrenceIds = new Set<string>();
  return rows.map((fields, index) => {
    const rowNumber = index + 2;
    if (fields.length !== headers.length) {
      throw csvRowError(rowNumber, "must match the header columns");
    }
    const get = (name: string): string => fields[headers.indexOf(name)] ?? "";
    const findingId = get("finding_id");
    const occurrenceId = get("occurrence_id");
    if (!FINDING_ID.test(findingId)) {
      throw csvRowError(rowNumber, "has an invalid finding_id");
    }
    if (!OCCURRENCE_ID.test(occurrenceId)) {
      throw csvRowError(rowNumber, "has an invalid occurrence_id");
    }
    if (findingIds.has(findingId)) {
      throw csvRowError(rowNumber, "has a duplicate finding_id");
    }
    if (occurrenceIds.has(occurrenceId)) {
      throw csvRowError(rowNumber, "has a duplicate occurrence_id");
    }
    findingIds.add(findingId);
    occurrenceIds.add(occurrenceId);

    const title = requiredCsvText(get("title"), rowNumber, "title");
    const summary = requiredCsvText(get("summary"), rowNumber, "summary");
    const remediation = requiredCsvText(
      get("remediation"),
      rowNumber,
      "remediation",
    );
    const severity = get("severity") as Finding["severity"]["level"];
    if (!SEVERITIES.has(severity)) {
      throw csvRowError(rowNumber, "has an invalid severity");
    }
    const confidence = get("confidence") as Finding["confidence"]["level"];
    if (!CONFIDENCES.has(confidence)) {
      throw csvRowError(rowNumber, "has an invalid confidence");
    }
    const status = get("status");
    if (status !== "open" && status !== "closed") {
      throw csvRowError(rowNumber, "has an invalid status");
    }
    const closeReason = get("close_reason");
    if (
      (status === "open" && closeReason !== "") ||
      (status === "closed" &&
        !CLOSE_REASONS.has(
          closeReason as NonNullable<CsvFindingRow["closeReason"]>,
        ))
    ) {
      throw csvRowError(rowNumber, "has an invalid close_reason");
    }
    const note = get("note");
    if (
      status === "closed" &&
      (closeReason === "false_positive" || closeReason === "wont_fix") &&
      note.trim().length === 0
    ) {
      throw csvRowError(rowNumber, "requires a note for its close_reason");
    }
    const path = get("path");
    if (!safeFindingPath(path)) {
      throw csvRowError(rowNumber, "has an invalid path");
    }
    const startLine = csvLine(get("start_line"), rowNumber, "start_line");
    const endLineText = get("end_line");
    const endLine =
      endLineText === ""
        ? undefined
        : csvLine(endLineText, rowNumber, "end_line");
    if (endLine !== undefined && endLine < startLine) {
      throw csvRowError(rowNumber, "has end_line before start_line");
    }
    const candidateId = get("candidate_id");
    return {
      occurrenceId,
      findingId,
      ...(candidateId.trim() === "" ? {} : { candidateId }),
      title,
      summary,
      severity,
      confidence,
      status,
      ...(closeReason === ""
        ? {}
        : {
            closeReason: closeReason as NonNullable<
              CsvFindingRow["closeReason"]
            >,
          }),
      ...(note.trim() === "" ? {} : { note }),
      remediation,
      path,
      startLine,
      ...(endLine === undefined ? {} : { endLine }),
    };
  });
}

function csvRowFinding(row: CsvFindingRow, scanId: string): Finding {
  const ruleId = "import.csv";
  const anchor = row.findingId;
  const fingerprint = `codex-security/v1:sha256:${sha256(
    ["codex-security/v1", CSV_TARGET_ID, ruleId, anchor, ""].join("\0"),
  )}`;
  const findingId = `csf_${sha256(fingerprint).slice(0, 24)}`;
  const occurrenceId = `occ_${sha256([scanId, fingerprint].join("\0")).slice(
    0,
    24,
  )}`;
  return {
    findingId,
    occurrenceId,
    ruleId,
    identity: { anchor },
    fingerprints: {
      algorithm: "codex-security/v1",
      primary: fingerprint,
    },
    title: row.title,
    summary: row.summary,
    severity: { level: row.severity },
    confidence: {
      level: row.confidence,
      rationale: "Imported from a Codex Security findings CSV.",
    },
    taxonomy: { category: "imported", cwe: [] },
    locations: [
      {
        path: row.path,
        startLine: row.startLine,
        ...(row.endLine === undefined ? {} : { endLine: row.endLine }),
      },
    ],
    remediation: row.remediation,
    provenance: {
      source: "csv_import",
      sourceFindingId: row.findingId,
      sourceOccurrenceId: row.occurrenceId,
      csvStatus: row.status,
      ...(row.closeReason === undefined
        ? {}
        : { csvCloseReason: row.closeReason }),
      ...(row.note === undefined ? {} : { csvNote: row.note }),
    },
    extensions: {
      ...(row.candidateId === undefined
        ? {}
        : { candidateId: row.candidateId }),
    },
  };
}

function requiredCsvText(
  value: string,
  rowNumber: number,
  column: string,
): string {
  if (value.trim().length === 0) {
    throw csvRowError(rowNumber, `requires ${column}`);
  }
  return value;
}

function csvLine(value: string, rowNumber: number, column: string): number {
  if (!/^[1-9]\d*$/u.test(value)) {
    throw csvRowError(rowNumber, `has an invalid ${column}`);
  }
  const line = Number(value);
  if (!Number.isSafeInteger(line)) {
    throw csvRowError(rowNumber, `has an invalid ${column}`);
  }
  return line;
}

function safeFindingPath(value: string): boolean {
  if (
    value.trim().length === 0 ||
    value === "." ||
    isAbsolute(value) ||
    /^[A-Za-z]:/u.test(value) ||
    value.includes("\\") ||
    /[\u0000-\u001F]/u.test(value) ||
    value.split("/").includes("..")
  ) {
    return false;
  }
  const normalized = posix.normalize(value).replace(/\/+$/u, "");
  return normalized !== "." && !normalized.startsWith("../");
}

function csvRowError(rowNumber: number, detail: string): CodexSecurityError {
  return new CodexSecurityError(`Findings CSV row ${rowNumber} ${detail}.`);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

async function publishCloudPayload(
  scan: ScanManifest["scan"],
  findings: Finding[],
  dependencies: CloudPublicationDependencies,
): Promise<CloudPublicationResult> {
  if (findings.length === 0) {
    throw new CodexSecurityError("There are no findings to publish.");
  }
  dependencies.signal?.throwIfAborted();
  if (dependencies.dryRun) {
    return {
      scanId: scan.id,
      findingIds: [],
      findingCount: findings.length,
      dryRun: true,
      findings,
    };
  }
  const credentials = await readCloudCredentials(
    dependencies.environment ?? process.env,
  );
  const publishUrl =
    dependencies.environment?.["CODEX_SECURITY_CLOUD_PUBLISH_URL"]?.trim() ||
    CLOUD_PUBLISH_URL;
  const timeout = AbortSignal.timeout(30_000);
  const signal = dependencies.signal
    ? AbortSignal.any([dependencies.signal, timeout])
    : timeout;
  let response: Response;
  try {
    response = await (dependencies.fetch ?? globalThis.fetch)(publishUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credentials.access_token}`,
        "ChatGPT-Account-ID": credentials.account_id,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        schemaVersion: "1.0",
        scan,
        findings,
      }),
      redirect: "error",
      signal,
    });
  } catch {
    // A lost response does not establish whether the server accepted the POST.
    throw new CodexSecurityError(
      "Cloud publication was not confirmed. The request was not retried; check whether it was accepted before submitting again.",
    );
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    const detail =
      response.status === 401
        ? "Sign in with ChatGPT again before retrying."
        : response.status === 403
          ? "The signed-in account is not authorized to publish to Cloud."
          : response.status === 404
            ? "Cloud publication is not available for this account or deployment."
            : "The request was not retried.";
    throw new CodexSecurityError(
      `Cloud publication failed (HTTP ${response.status}). ${detail}`,
    );
  }
  const receipt = receiptSchema.safeParse(
    await response.json().catch(() => undefined),
  );
  // Cloud assigns opaque IDs in request order, so they cannot be compared to
  // local finding IDs. The authenticated response must still preserve the
  // submitted count and return one distinct observation for each finding.
  if (
    (response.status !== 200 && response.status !== 201) ||
    !receipt.success ||
    receipt.data.finding_count !== findings.length ||
    receipt.data.finding_ids.length !== findings.length ||
    new Set(receipt.data.finding_ids).size !== receipt.data.finding_ids.length
  ) {
    throw new CodexSecurityError(
      "Cloud publication returned an invalid acceptance receipt. Check whether the request was accepted before submitting again.",
    );
  }
  return {
    scanId: scan.id,
    findingIds: receipt.data.finding_ids,
    findingCount: receipt.data.finding_count,
  };
}

async function readCloudCredentials(environment: NodeJS.ProcessEnv) {
  let home = expandHome(
    environment["CODEX_HOME"]?.trim() || "~/.codex",
    environment,
  );
  let requireFileStorage = true;
  const dedicatedHome = codexSecurityCredentialHome(environment);
  if (existsSync(dedicatedHome)) {
    if (!(await codexSecurityCredentialAllowsAmbientImport(dedicatedHome))) {
      throw new AuthenticationRequiredError(CHATGPT_LOGIN_REQUIRED);
    }
    if (await codexSecurityHasStoredFileCredentials(dedicatedHome)) {
      home = dedicatedHome;
      requireFileStorage = false;
    } else if (existsSync(join(dedicatedHome, "config.toml"))) {
      // Do not silently switch accounts when the dedicated login may be in a keyring.
      throw new AuthenticationRequiredError(CHATGPT_LOGIN_REQUIRED);
    }
  }
  if (requireFileStorage) {
    let credentialStorage: unknown;
    try {
      credentialStorage = parseToml(
        await readFile(join(home, "config.toml"), "utf8"),
      )["cli_auth_credentials_store"];
    } catch {
      throw new AuthenticationRequiredError(CHATGPT_LOGIN_REQUIRED);
    }
    // File presence is not proof that it is the active ambient login:
    // automatic or keyring storage can leave auth.json for another account.
    if (credentialStorage !== "file") {
      throw new AuthenticationRequiredError(CHATGPT_LOGIN_REQUIRED);
    }
  }
  try {
    const credentials = credentialsSchema.safeParse(
      JSON.parse(await readFile(join(home, "auth.json"), "utf8")),
    );
    if (credentials.success) return credentials.data.tokens;
  } catch {
    // Parsing and filesystem diagnostics must not reflect credential contents.
  }
  throw new AuthenticationRequiredError(CHATGPT_LOGIN_REQUIRED);
}
