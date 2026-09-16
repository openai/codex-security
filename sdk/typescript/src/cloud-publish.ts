import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "incur";
import { parse as parseToml } from "smol-toml";
import { loadContract } from "./contract.js";
import { AuthenticationRequiredError, CodexSecurityError } from "./errors.js";
import type { Finding, ScanManifest } from "./models.js";
import {
  CSV_TARGET_ID,
  csvRowFinding,
  parseFindingsCsv,
} from "./findings-import.js";
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
  dependencies: CloudPublicationDependencies = {},
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
  const scanId = `scan_csv_${sha256(
    ["codex-security-csv-import/v1", VERSION, source].join("\0"),
  ).slice(0, 24)}`;
  const findings = rows.map((row) => csvRowFinding(row, scanId));
  const timestamp = "1970-01-01T00:00:00.000Z";
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
      displayName: "findings.csv",
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
    dependencies.signal?.throwIfAborted();
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
    await response.json().catch(() => {
      dependencies.signal?.throwIfAborted();
      return undefined;
    }),
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
