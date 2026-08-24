import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "incur";
import { parse as parseToml } from "smol-toml";
import { loadContract } from "./contract.js";
import { AuthenticationRequiredError, CodexSecurityError } from "./errors.js";
import type { Finding } from "./models.js";
import {
  bundledPluginRoot,
  codexSecurityCredentialAllowsAmbientImport,
  codexSecurityCredentialHome,
  codexSecurityHasStoredFileCredentials,
  expandHome,
} from "./runtime.js";

const CLOUD_PUBLISH_URL =
  "https://chatgpt.com/backend-api/aardvark/cli/findings";
const CHATGPT_LOGIN_REQUIRED =
  'Cloud publication requires ChatGPT credentials stored with cli_auth_credentials_store = "file". Automatic and keyring storage are not read because a stale auth.json may belong to another account. Configure file storage, sign in with ChatGPT again, then retry.';

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

export async function publishScanToCloud(
  scanDirectory: string,
  dependencies: {
    environment?: NodeJS.ProcessEnv;
    fetch?: (url: string, options: RequestInit) => Promise<Response>;
    signal?: AbortSignal;
    dryRun?: boolean;
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
  dependencies.signal?.throwIfAborted();
  if (dependencies.dryRun) {
    return {
      scanId: manifest.scan.id,
      findingIds: [],
      findingCount: findings.findings.length,
      dryRun: true,
      findings: findings.findings,
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
        scan: manifest.scan,
        findings: findings.findings,
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
    receipt.data.finding_count !== findings.findings.length ||
    receipt.data.finding_ids.length !== findings.findings.length ||
    new Set(receipt.data.finding_ids).size !== receipt.data.finding_ids.length
  ) {
    throw new CodexSecurityError(
      "Cloud publication returned an invalid acceptance receipt. Check whether the request was accepted before submitting again.",
    );
  }
  return {
    scanId: manifest.scan.id,
    findingIds: receipt.data.finding_ids,
    findingCount: receipt.data.finding_count,
  };
}

async function readCloudCredentials(environment: NodeJS.ProcessEnv) {
  let home = expandHome(
    environment["CODEX_HOME"]?.trim() || "~/.codex",
    environment,
  );
  const dedicatedHome = codexSecurityCredentialHome(environment);
  if (existsSync(dedicatedHome)) {
    if (!(await codexSecurityCredentialAllowsAmbientImport(dedicatedHome))) {
      throw new AuthenticationRequiredError(CHATGPT_LOGIN_REQUIRED);
    }
    if (await codexSecurityHasStoredFileCredentials(dedicatedHome)) {
      home = dedicatedHome;
    } else if (existsSync(join(dedicatedHome, "config.toml"))) {
      // Do not silently switch accounts when the dedicated login may be in a keyring.
      throw new AuthenticationRequiredError(CHATGPT_LOGIN_REQUIRED);
    }
  }
  let credentialStorage: unknown;
  try {
    credentialStorage = parseToml(
      await readFile(join(home, "config.toml"), "utf8"),
    )["cli_auth_credentials_store"];
  } catch {
    throw new AuthenticationRequiredError(CHATGPT_LOGIN_REQUIRED);
  }
  // File presence is not proof that it is the active login: automatic or
  // keyring storage can leave an auth.json from a different account.
  if (credentialStorage !== "file") {
    throw new AuthenticationRequiredError(CHATGPT_LOGIN_REQUIRED);
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
