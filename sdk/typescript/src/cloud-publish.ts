import { hash } from "node:crypto";
import { existsSync } from "node:fs";
import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import { z } from "incur";
import { parse as parseToml } from "smol-toml";
import cloudSchema from "../schemas/cloud-import-v1.schema.json" with { type: "json" };
import { loadContract, readScanFile } from "./contract.js";
import {
  requireCloudScanEligibility,
  cloudRepositoryIdentity,
} from "./cloud-scan-eligibility.js";
import type {
  CreateImportedScan,
  ImportDestination,
  ImportDestinations,
  ImportedScanReceipt,
  ImportArtifactDeclaration,
} from "./cloud-import-models.js";
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
  "https://chatgpt.com/backend-api/aardvark/imported-scans/v1";
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
const ajv = new Ajv2020({ strict: false, validateFormats: false });
const validateDestinations = ajv.compile<ImportDestinations>({
  ...cloudSchema,
  $ref: "#/$defs/ImportDestinations",
});
const validateReceipt = ajv.compile<ImportedScanReceipt>({
  ...cloudSchema,
  $ref: "#/$defs/ImportedScanReceipt",
});
type ImportContent = Omit<
  CreateImportedScan,
  "environment_id" | "repository_id" | "connector_id"
>;
const validateImportContent = ajv.compile<ImportContent>({
  $defs: cloudSchema.$defs,
  ...cloudSchema.$defs.CreateImportedScan,
  required: cloudSchema.$defs.CreateImportedScan.required.filter(
    (field) =>
      !["environment_id", "repository_id", "connector_id"].includes(field),
  ),
});
const validateCreate = ajv.compile<CreateImportedScan>({
  ...cloudSchema,
  $ref: "#/$defs/CreateImportedScan",
});

export interface CloudPublicationResult {
  scanId: string;
  /** Native publication does not return canonical finding IDs in this response. */
  findingIds: string[];
  /** Number of findings in the submitted local artifact, before Cloud processing. */
  findingCount: number;
  /** Finalization/acceptance receipt; inspect stage statuses for processing completion. */
  publication?: ImportedScanReceipt;
  dryRun?: true;
  findings?: Finding[];
}
export type CloudDestination = ImportDestination;
export interface CloudPublicationDependencies {
  environment?: NodeJS.ProcessEnv;
  fetch?: (url: string, options: RequestInit) => Promise<Response>;
  signal?: AbortSignal;
  dryRun?: boolean;
  cloudEnvironment?: string;
  selectEnvironment?: (destinations: ImportDestination[]) => Promise<string>;
}

async function cloudRequest(
  path: string,
  dependencies: CloudPublicationDependencies,
  method = "GET",
  body?: BodyInit,
  contentType = "application/json",
  timeoutMs = 30_000,
): Promise<unknown> {
  dependencies.signal?.throwIfAborted();
  const credentials = await readCloudCredentials(
    dependencies.environment ?? process.env,
  );
  const base =
    dependencies.environment?.["CODEX_SECURITY_CLOUD_PUBLISH_URL"]?.trim() ||
    CLOUD_PUBLISH_URL;
  const timeout = AbortSignal.timeout(timeoutMs);
  const signal = dependencies.signal
    ? AbortSignal.any([dependencies.signal, timeout])
    : timeout;
  let response: Response;
  try {
    response = await (dependencies.fetch ?? globalThis.fetch)(
      `${base.replace(/\/$/u, "")}${path}`,
      {
        method,
        headers: {
          Authorization: `Bearer ${credentials.access_token}`,
          "ChatGPT-Account-ID": credentials.account_id,
          "Content-Type": contentType,
          Accept: "application/json",
        },
        ...(body === undefined ? {} : { body }),
        redirect: "error",
        signal,
      },
    );
  } catch (cause) {
    dependencies.signal?.throwIfAborted();
    throw new CodexSecurityError(
      "Cloud publication was not confirmed. Repeat the same publication to resume its immutable upload session.",
      { cause },
    );
  }
  if (!response.ok) {
    const detail = await response.text();
    dependencies.signal?.throwIfAborted();
    const recovery =
      response.status === 401
        ? "Sign in with ChatGPT again."
        : response.status === 403
          ? "Current access to the selected environment and repository is required."
          : response.status === 404 || response.status === 410
            ? "This deployment does not support native scan imports; no legacy publication was attempted."
            : method === "POST" && path === "" && response.status < 500
              ? "Resolve this rejection before retrying publication."
              : "Repeat the same publication to resume after resolving the error.";
    throw new CodexSecurityError(
      `Cloud publication failed (HTTP ${response.status}). ${detail}${detail ? " " : ""}${recovery}`,
    );
  }
  return response.json();
}

export async function listCloudDestinations(
  dependencies: CloudPublicationDependencies = {},
  repositoryRemote?: string,
): Promise<ImportDestination[]> {
  const payload = await cloudRequest(
    `/destinations${repositoryRemote === undefined ? "" : `?repository_remote=${encodeURIComponent(repositoryRemote)}`}`,
    dependencies,
  );
  if (!validateDestinations(payload) || payload.protocol_version !== 1)
    throw new CodexSecurityError(
      "Cloud returned an incompatible destination discovery response.",
    );
  return payload.destinations;
}

export async function selectCloudDestination(
  destinations: ImportDestination[],
  dependencies: CloudPublicationDependencies,
): Promise<ImportDestination> {
  if (dependencies.cloudEnvironment !== undefined) {
    const destination = destinations.find(
      (item) => item.environment_id === dependencies.cloudEnvironment,
    );
    if (!destination)
      throw new CodexSecurityError(
        "The selected Cloud environment is not an authorized match for this repository.",
      );
    return destination;
  }
  if (destinations.length === 0)
    throw new CodexSecurityError(
      "No existing authorized Cloud environment matches this repository. No artifacts were uploaded.",
    );
  const environments = [
    ...new Map(
      destinations.map((item) => [item.environment_id, item]),
    ).values(),
  ];
  if (environments.length === 1) return environments[0]!;
  if (!dependencies.selectEnvironment)
    throw new CodexSecurityError(
      "Multiple Cloud environments match. Specify --cloud-environment ENV_ID or use an interactive terminal.",
    );
  const selected = await dependencies.selectEnvironment(environments);
  const destination = destinations.find(
    (item) => item.environment_id === selected,
  );
  if (!destination)
    throw new CodexSecurityError(
      "The selected Cloud environment is not an authorized destination.",
    );
  return destination;
}

export async function publishScanToCloud(
  scanDirectory: string,
  dependencies: CloudPublicationDependencies & { expectedScanId?: string } = {},
): Promise<CloudPublicationResult> {
  const contract = await loadContract(scanDirectory, {
    pluginRoot: await bundledPluginRoot(),
    signal: dependencies.signal,
    expectedScanId: dependencies.expectedScanId,
  });
  const repository = requireCloudScanEligibility(contract);
  const { scan } = contract.manifest;
  const names: ImportArtifactDeclaration["name"][] = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
  ];
  const report = await lstat(join(scanDirectory, "report.md")).catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return undefined;
      throw error;
    },
  );
  if (report !== undefined) names.push("report.md");
  const bytes = new Map<string, Buffer>();
  const artifacts: ImportArtifactDeclaration[] = [];
  for (const name of names) {
    const contents = await readScanFile(
      scanDirectory,
      name,
      "Cloud publication artifact",
      dependencies.signal,
    );
    const digest = hash("sha256", contents);
    const declared = scan.artifacts.find((item) => item.path === name);
    if (declared && declared.sha256 !== digest)
      throw new CodexSecurityError(
        `Scan artifact changed after validation: ${name}.`,
      );
    if (
      name === "scan-manifest.json" &&
      JSON.stringify(
        JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(contents)),
      ) !== JSON.stringify(contract.manifest)
    )
      throw new CodexSecurityError("Scan manifest changed after validation.");
    bytes.set(name, contents);
    artifacts.push({ name, sha256: digest, size_bytes: contents.byteLength });
  }
  const content: ImportContent = {
    protocol_version: 1,
    source_scan_id: scan.id,
    repository_remote: scan.target.remote!,
    repository_path: ".",
    target_kind: scan.target.kind as "git_revision" | "git_worktree",
    coverage_mode: "full_repository",
    base_commit: scan.target.revision!,
    snapshot_digest:
      scan.target.snapshotDigest?.replace(
        /^codex-security-snapshot\/v1:sha256:/u,
        "",
      ) ?? null,
    scan_started_at: scan.startedAt,
    scan_completed_at: scan.completedAt,
    artifacts,
  };
  if (!validateImportContent(content))
    throw new CodexSecurityError(
      `The scan does not satisfy the Cloud import contract: ${ajv.errorsText(validateImportContent.errors)}.`,
    );
  const totalBytes = artifacts.reduce(
    (total, artifact) => total + artifact.size_bytes,
    0,
  );
  const maxTotalBytes = 128 * 1024 * 1024;
  if (totalBytes > maxTotalBytes)
    throw new CodexSecurityError(
      `Cloud publication artifacts total ${totalBytes} bytes; the import limit is ${maxTotalBytes} bytes (128 MiB).`,
    );
  if (dependencies.dryRun)
    return {
      scanId: scan.id,
      findingIds: [],
      findingCount: contract.findings.findings.length,
      dryRun: true,
      findings: contract.findings.findings,
    };
  const destinations = await listCloudDestinations(
    dependencies,
    scan.target.remote!,
  );
  const destination = await selectCloudDestination(
    destinations.filter(
      (item) => cloudRepositoryIdentity(item.repository_remote) === repository,
    ),
    dependencies,
  );
  const request: CreateImportedScan = {
    ...content,
    environment_id: destination.environment_id,
    repository_id: destination.repository_id,
    connector_id: destination.connector_id,
  };
  if (!validateCreate(request))
    throw new CodexSecurityError(
      `The scan does not satisfy the Cloud import contract: ${ajv.errorsText(validateCreate.errors)}.`,
    );
  let importedScanId: string | undefined;
  const receipt = (payload: unknown): ImportedScanReceipt => {
    if (
      !validateReceipt(payload) ||
      payload.protocol_version !== 1 ||
      payload.source !== "cli" ||
      payload.source_scan_id !== scan.id ||
      payload.environment_id !== destination.environment_id ||
      payload.repository_id !== destination.repository_id ||
      (importedScanId !== undefined &&
        payload.imported_scan_id !== importedScanId) ||
      payload.artifacts.length !== artifacts.length ||
      !artifacts.every((expected) =>
        payload.artifacts.some(
          (actual) =>
            actual.name === expected.name &&
            actual.sha256 === expected.sha256 &&
            actual.size_bytes === expected.size_bytes,
        ),
      )
    )
      throw new CodexSecurityError(
        "Cloud returned an incompatible scan import receipt. Repeat the same publication to check its status.",
      );
    importedScanId = payload.imported_scan_id;
    return payload;
  };
  let publication = receipt(
    await cloudRequest("", dependencies, "POST", JSON.stringify(request)),
  );
  if (publication.upload_status === "expired")
    throw new CodexSecurityError(
      "The abandoned Cloud upload session has expired.",
    );
  const repairRetention =
    publication.upload_status === "finalizing" &&
    publication.materialization_status === "failed" &&
    publication.failure_code === "artifact_retention_failed";
  if (publication.upload_status === "uploading" || repairRetention) {
    for (const artifact of artifacts) {
      if (
        !repairRetention &&
        publication.artifacts.some(
          (item) =>
            item.name === artifact.name &&
            item.sha256 === artifact.sha256 &&
            item.size_bytes === artifact.size_bytes &&
            item.uploaded,
        )
      )
        continue;
      publication = receipt(
        await cloudRequest(
          `/${encodeURIComponent(publication.imported_scan_id)}/artifacts/${artifact.name}`,
          dependencies,
          "PUT",
          new Uint8Array(bytes.get(artifact.name)!),
          "application/octet-stream",
          // Allow the server's 120-second ingress window plus response processing.
          150_000,
        ),
      );
    }
    publication = receipt(
      await cloudRequest(
        `/${encodeURIComponent(publication.imported_scan_id)}/finalize`,
        dependencies,
        "POST",
      ),
    );
  } else if (
    publication.materialization_status === "failed" ||
    publication.dedupe_status === "failed"
  ) {
    publication = receipt(
      await cloudRequest(
        `/${encodeURIComponent(publication.imported_scan_id)}/retry`,
        dependencies,
        "POST",
      ),
    );
  }
  if (!["accepted", "finalizing"].includes(publication.upload_status))
    throw new CodexSecurityError(
      "Cloud did not confirm finalization or acceptance. Repeat the same publication to resume.",
    );
  return {
    scanId: scan.id,
    findingIds: [],
    findingCount: contract.findings.findings.length,
    publication,
  };
}

/** CSV lacks immutable repository provenance and is ineligible for native imports. */
export async function publishFindingsCsvToCloud(
  _csvPath: string,
  _dependencies: CloudPublicationDependencies = {},
): Promise<CloudPublicationResult> {
  throw new CodexSecurityError(
    "Cloud publication accepts full-repository SCM scans only; CSV imports are unsupported.",
  );
}

async function readCloudCredentials(environment: NodeJS.ProcessEnv) {
  const configuredHome = environment["CODEX_HOME"];
  let home = expandHome(
    configuredHome?.trim() ? configuredHome : "~/.codex",
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
