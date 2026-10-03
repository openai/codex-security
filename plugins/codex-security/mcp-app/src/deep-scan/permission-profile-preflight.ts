import { asRecord as record } from "../record.js";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface, type Interface } from "node:readline";
import { isDeepStrictEqual } from "node:util";
import { MCP_APP_VERSION } from "../version.js";
import { DeepScanNonRetryableError } from "./errors.js";
import { executablePathForSpawn } from "./executable-path.js";

/** The stable profile id selected by the worker's raw config overrides. */
export const DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID =
  "codex_security_deep_scan_worker";

export interface DeepScanPermissionProfilePreflightOptions {
  /** The exact Codex executable that will run the worker turn. */
  readonly codexPath: string;
  /** The worker cwd used for app-server startup and cwd-scoped config RPCs. */
  readonly cwd: string;
  /** Raw `-c` values passed to both this preflight and the SDK worker. */
  readonly configOverrides: readonly string[];
  /**
   * Exact environment snapshot shared with the SDK worker. The caller resolves
   * relative CODEX_HOME values before changing the preflight subprocess cwd.
   * Omit it to retain Node's default child-process environment inheritance.
   */
  readonly env?: Readonly<Record<string, string>>;
  /** Check native authentication before using an otherwise ignored OPENAI_API_KEY. */
  readonly allowOpenAiApiKeyFallback?: boolean;
  /** The injected profile before app-server expands omitted options to null. */
  readonly expectedProfile: Readonly<Record<string, unknown>>;
  readonly signal: AbortSignal;
}

type JsonRecord = Record<string, unknown>;

type PendingRequest = {
  readonly id: number;
  readonly method: string;
  readonly resolve: (message: JsonRecord) => void;
  readonly reject: (error: Error) => void;
};

/**
 * Verify the worker profile with the same executable, effective worker cwd,
 * Codex home, and raw overrides that the real worker will use. App-server must
 * start in the worker cwd because startup config also selects authentication
 * and cloud-managed requirements; cwd-scoped RPCs alone do not replace that
 * startup context. This must finish before starting a turn: startup warnings
 * arrive too late to keep a fallback profile safe.
 *
 * This is intentionally a pragmatic preflight, not an atomic reservation:
 * managed config can change between this check and `codex exec`. Callers must
 * also reject the exact runtime fallback warning via
 * `deepScanPermissionProfileFallbackError` before accepting worker output.
 */
export async function preflightDeepScanWorkerPermissionProfile(
  options: DeepScanPermissionProfilePreflightOptions,
): Promise<{ useOpenAiApiKey: boolean }> {
  validateOptions(options);
  if (options.signal.aborted) throw abortError(options.signal.reason);

  const client = new AppServerPreflightClient(options);
  try {
    await client.initialize();
    const configResponse = await client.request("config/read", {
      cwd: options.cwd,
      includeLayers: false,
    });
    const catalog = await client.readPermissionProfileCatalog(options.cwd);
    const matchingEntries = catalog.filter(
      (entry) => entry.id === DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
    );
    if (matchingEntries.length !== 1) throw malformedPreflightError();
    const catalogEntry = matchingEntries[0];
    const requirementsResponse =
      catalogEntry.allowed === true
        ? undefined
        : await client.readConfigRequirementsForClassification();
    verifyPreflightResult(
      options,
      configResponse,
      catalogEntry,
      requirementsResponse,
    );
    if (
      !options.allowOpenAiApiKeyFallback ||
      record(configResponse.config)?.forced_login_method === "chatgpt"
    ) {
      return { useOpenAiApiKey: false };
    }
    // Reuse Codex's selected credential store and provider, including keyring
    // and command-backed providers, instead of interpreting auth.json here.
    const account = await client.request("account/read", {
      refreshToken: false,
    });
    return {
      useOpenAiApiKey:
        account.requiresOpenaiAuth === true && account.account === null,
    };
  } finally {
    await client.close();
  }
}

class AppServerPreflightClient {
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly childClose: Promise<void>;
  private readonly stdoutLines: Interface;
  private pending: PendingRequest | undefined;
  private nextId = 1;
  private terminalError: Error | undefined;
  private closed = false;
  private childClosed = false;
  private readonly removeAbortListener: () => void;

  constructor(
    private readonly options: DeepScanPermissionProfilePreflightOptions,
  ) {
    const args: string[] = [];
    for (const override of options.configOverrides) {
      args.push("--config", override);
    }
    args.push("app-server", "--stdio");

    this.child = spawn(executablePathForSpawn(options.codexPath), args, {
      cwd: options.cwd,
      ...(options.env === undefined ? {} : { env: options.env }),
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.childClose = new Promise((resolve) => {
      this.child.once("close", () => {
        this.childClosed = true;
        resolve();
      });
    });
    // stderr can contain paths or repository contents. Drain it so the child
    // cannot block, but never retain or surface it in Deep Scan errors.
    this.child.stderr.resume();
    this.stdoutLines = createInterface({
      input: this.child.stdout,
      crlfDelay: Infinity,
    });
    this.stdoutLines.on("line", (line) => this.consumeStdoutLine(line));
    this.stdoutLines.on("error", () => {
      this.fail(codexExecutableStdioError(options.codexPath));
    });
    this.child.stdin.on("error", () => {
      this.fail(codexExecutableStdioError(options.codexPath));
    });
    this.child.on("error", (error) => {
      this.fail(codexExecutableStartError(options.codexPath, error));
    });
    this.child.on("exit", (code, signal) => {
      if (!this.closed) {
        this.fail(codexExecutableExitError(options.codexPath, code, signal));
      }
    });

    const onAbort = () => {
      this.fail(abortError(options.signal.reason));
      this.stopChild();
    };
    options.signal.addEventListener("abort", onAbort, { once: true });
    this.removeAbortListener = () =>
      options.signal.removeEventListener("abort", onAbort);
  }

  async initialize(): Promise<void> {
    await this.request("initialize", {
      clientInfo: {
        name: "codex_security_deep_scan",
        title: "Codex Security Deep Scan",
        version: MCP_APP_VERSION,
      },
      capabilities: { experimentalApi: true },
    });
    if (this.terminalError) throw this.terminalError;
    this.write({ jsonrpc: "2.0", method: "initialized", params: {} });
  }

  async readPermissionProfileCatalog(cwd: string): Promise<JsonRecord[]> {
    const entries: JsonRecord[] = [];
    const seenCursors = new Set<string>();
    let cursor: string | undefined;

    while (true) {
      const result = await this.request("permissionProfile/list", {
        cwd,
        ...(cursor === undefined ? {} : { cursor }),
      });
      const data = result.data;
      if (!Array.isArray(data)) throw malformedPreflightError();
      for (const value of data) {
        const entry = record(value);
        // Catalog ids are opaque. Only our requested profile id is fixed and
        // non-empty; unrelated valid ids may be empty or otherwise unusual.
        if (!entry || typeof entry.id !== "string") {
          throw malformedPreflightError();
        }
        if (typeof entry.allowed !== "boolean") throw malformedPreflightError();
        if (
          entry.description !== null &&
          entry.description !== undefined &&
          typeof entry.description !== "string"
        ) {
          throw malformedPreflightError();
        }
        entries.push(entry);
      }

      const nextCursor = result.nextCursor;
      if (nextCursor === null) return entries;
      if (
        typeof nextCursor !== "string" ||
        nextCursor.length === 0 ||
        seenCursors.has(nextCursor)
      ) {
        throw malformedPreflightError();
      }
      seenCursors.add(nextCursor);
      cursor = nextCursor;
    }
  }

  /**
   * Classification is best effort after the catalog already rejected the
   * profile. An older runtime may not expose this API; that is still a safe
   * generic managed-policy rejection, not a reason to guess at remediation.
   */
  async readConfigRequirementsForClassification(): Promise<
    JsonRecord | undefined
  > {
    try {
      return await this.request("configRequirements/read");
    } catch (error) {
      if (this.options.signal.aborted || isAbortError(error)) throw error;
      return undefined;
    }
  }

  request(method: string, params?: JsonRecord): Promise<JsonRecord> {
    if (this.terminalError) return Promise.reject(this.terminalError);
    const id = this.nextId++;
    return new Promise<JsonRecord>((resolve, reject) => {
      // This no-turn preflight awaits each request before sending the next.
      this.pending = { id, method, resolve, reject };
      this.write({
        jsonrpc: "2.0",
        id,
        method,
        ...(params === undefined ? {} : { params }),
      });
    });
  }

  async close(): Promise<void> {
    this.closed = true;
    this.removeAbortListener();
    this.pending?.reject(
      this.terminalError ?? codexExecutableStdioError(this.options.codexPath),
    );
    this.pending = undefined;
    this.stopChild();
    if (this.childClosed) return;
    await this.childClose;
  }

  private write(message: JsonRecord): void {
    if (!this.child.stdin.writable) {
      this.fail(codexExecutableStdioError(this.options.codexPath));
      return;
    }
    this.child.stdin.write(`${JSON.stringify(message)}\n`, (error) => {
      if (error) this.fail(codexExecutableStdioError(this.options.codexPath));
    });
  }

  private consumeStdoutLine(line: string): void {
    if (this.terminalError || line.trim().length === 0) return;
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      this.fail(malformedPreflightError());
      return;
    }
    const message = record(value);
    if (!message) {
      this.fail(malformedPreflightError());
      return;
    }
    const id = message.id;
    if (typeof id !== "number") {
      // Notifications and server-initiated requests are irrelevant to this
      // read-only preflight. We never answer them or start a turn.
      return;
    }
    const pending = this.pending;
    if (!pending || pending.id !== id) {
      this.fail(malformedPreflightError());
      return;
    }
    this.pending = undefined;
    if (message.error !== undefined) {
      pending.reject(
        jsonRpcPreflightError(
          this.options.codexPath,
          pending.method,
          message.error,
        ),
      );
      return;
    }
    const result = record(message.result);
    if (!result) {
      pending.reject(malformedPreflightError());
      return;
    }
    pending.resolve(result);
  }

  private fail(error: Error): void {
    if (this.terminalError) return;
    this.terminalError = error;
    this.pending?.reject(error);
    this.pending = undefined;
  }

  private stopChild(): void {
    this.stdoutLines.close();
    if (!this.child.stdin.destroyed) this.child.stdin.end();
    if (this.child.exitCode === null && this.child.signalCode === null) {
      this.child.kill("SIGTERM");
    }
  }
}

function verifyPreflightResult(
  options: DeepScanPermissionProfilePreflightOptions,
  configResponse: JsonRecord,
  catalogEntry: JsonRecord,
  requirementsResponse: JsonRecord | undefined,
): void {
  if (catalogEntry.allowed !== true) {
    throw existingAllowlistExcludesProfile(requirementsResponse)
      ? disallowedProfileAllowlistError()
      : managedPolicyRejectedError();
  }

  const config = record(configResponse.config);
  const permissions = record(config?.permissions);
  const actualProfile = permissions
    ? record(permissions[DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID])
    : undefined;
  if (
    !config ||
    !permissions ||
    !actualProfile ||
    typeof config.default_permissions !== "string"
  )
    throw malformedPreflightError();

  if (config.default_permissions !== DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID) {
    throw profileNotSelectedError();
  }

  const expectedProfile = comparableProfile(options.expectedProfile);
  const actualWithoutDescription = comparableProfile(actualProfile);
  if (!isDeepStrictEqual(actualWithoutDescription, expectedProfile)) {
    throw profileCollisionError();
  }
}

function existingAllowlistExcludesProfile(
  response: JsonRecord | undefined,
): boolean {
  if (!response || !Object.hasOwn(response, "requirements")) return false;
  if (response.requirements === null) return false;
  const requirements = record(response.requirements);
  if (
    !requirements ||
    !Object.hasOwn(requirements, "allowedPermissionProfiles")
  )
    return false;
  if (requirements.allowedPermissionProfiles === null) return false;
  const allowlist = record(requirements.allowedPermissionProfiles);
  if (!allowlist) return false;
  if (Object.values(allowlist).some((value) => typeof value !== "boolean"))
    return false;
  return allowlist[DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID] !== true;
}

/**
 * `config/read` serializes omitted TOML options as null. Drop only those null
 * placeholders; every unexpected non-null field still participates in the
 * strict comparison. A display description is intentionally not security
 * relevant, but it must remain a string when present.
 */
function comparableProfile(
  value: Readonly<Record<string, unknown>>,
): JsonRecord {
  const normalized = stripNullObjectFields(value) as JsonRecord;
  const description = normalized.description;
  if (description !== undefined && typeof description !== "string") {
    throw malformedPreflightError();
  }
  const { description: _description, ...rest } = normalized;
  return rest;
}

function stripNullObjectFields(value: unknown): unknown {
  if (Array.isArray(value))
    return value.map((entry) => stripNullObjectFields(entry));
  const object = record(value);
  if (!object) return value;

  // Object.fromEntries defines literal data properties, including
  // `__proto__`; assigning untrusted config keys onto `{}` would invoke its
  // legacy prototype setter and could hide an unexpected profile field.
  return Object.fromEntries(
    Object.entries(object)
      .filter(([, entry]) => entry !== null)
      .map(([key, entry]) => [key, stripNullObjectFields(entry)]),
  );
}

function validateOptions(
  options: DeepScanPermissionProfilePreflightOptions,
): void {
  if (
    !nonEmptyString(options.codexPath) ||
    !nonEmptyString(options.cwd) ||
    !Array.isArray(options.configOverrides) ||
    options.configOverrides.some((value) => !nonEmptyString(value)) ||
    !record(options.expectedProfile) ||
    !options.signal ||
    typeof options.signal.addEventListener !== "function"
  ) {
    throw malformedPreflightError();
  }
  comparableProfile(options.expectedProfile);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

// Verified permission incompatibilities explicitly stop the scan. A failed
// transport attempt alone does not establish that the scan cannot proceed.
function disallowedProfileAllowlistError(): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(
    `Deep Scan cannot safely start a read-only worker because organization policy does not allow the required \`${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}\` permission profile. Ask your Codex administrator to define this read-only stub in a normal config layer:\n\n[permissions.${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}]\nextends = ":read-only"\n\nand add this entry to your existing allowlist in requirements.toml:\n\n[allowed_permission_profiles]\n${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID} = true\n\nDeep Scan did not run.`,
  );
}

function managedPolicyRejectedError(): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(
    `Deep Scan cannot safely start a read-only worker because managed Codex policy rejected the required \`${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}\` permission profile. Ask your Codex administrator to review the managed permission, sandbox, and filesystem requirements. Deep Scan did not run.`,
  );
}

function profileNotSelectedError(): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(
    `Deep Scan cannot safely start a read-only worker because Codex did not select the required \`${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}\` permission profile. Ask your Codex administrator to allow that profile for Deep Scan. Deep Scan did not run.`,
  );
}

function profileCollisionError(): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(
    `Deep Scan cannot safely start a read-only worker because existing Codex configuration changes the reserved \`${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}\` permission profile. Ask your Codex administrator to keep the normal-config \`[permissions.${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}]\` stub limited to \`extends = ":read-only"\`; Deep Scan supplies its deny rules at runtime. Deep Scan did not run.`,
  );
}

function malformedPreflightError(): Error {
  return new Error(
    "Deep Scan cannot safely verify its read-only worker permission profile with this Codex configuration. Deep Scan did not run.",
  );
}

function unsupportedCodexApiError(
  codexPath: string,
  api: string,
): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(
    "Deep Scan cannot safely verify its read-only worker permission profile because " +
      "the selected Codex executable " +
      JSON.stringify(codexPath) +
      " does not support the required " +
      JSON.stringify(api) +
      " API. " +
      "Update the Codex installation at that path " +
      "(the desktop app if it is bundled, otherwise the selected CLI) and retry." +
      " Deep Scan did not run.",
  );
}

function jsonRpcPreflightError(
  codexPath: string,
  method: string,
  value: unknown,
): Error {
  const error = record(value);
  const code =
    typeof error?.code === "number" && Number.isFinite(error.code)
      ? error.code
      : undefined;
  if (code === -32601) return unsupportedCodexApiError(codexPath, method);
  const codeDetail = code === undefined ? "" : " (JSON-RPC code " + code + ")";
  return new Error(
    "Deep Scan cannot safely verify its read-only worker permission profile because " +
      "the selected Codex executable " +
      JSON.stringify(codexPath) +
      " returned an error for " +
      JSON.stringify(method) +
      codeDetail +
      ". Check the Codex configuration and retry. Deep Scan did not run.",
  );
}

function codexExecutableStartError(codexPath: string, error: Error): Error {
  const value = "code" in error ? error.code : undefined;
  const code =
    typeof value === "string" && /^[A-Z0-9_]+$/u.test(value)
      ? value
      : undefined;
  const codeDetail = code === undefined ? "" : " (" + code + ")";
  const message = codexExecutableFailureMessage(
    codexPath,
    "could not start" + codeDetail,
  );
  return new Error(message, { cause: error });
}

function codexExecutableExitError(
  codexPath: string,
  code: number | null,
  signal: NodeJS.Signals | null,
): Error {
  const detail =
    code !== null
      ? "exited before permission-profile verification completed with code " +
        code
      : signal !== null
        ? "was terminated before permission-profile verification completed by signal " +
          signal
        : "exited before permission-profile verification completed";
  return new Error(codexExecutableFailureMessage(codexPath, detail));
}

function codexExecutableStdioError(codexPath: string): Error {
  return new Error(
    codexExecutableFailureMessage(
      codexPath,
      "could not exchange app-server JSON-RPC over stdio",
    ),
  );
}

function codexExecutableFailureMessage(
  codexPath: string,
  detail: string,
): string {
  return (
    "Deep Scan cannot safely verify its read-only worker permission profile because " +
    "the selected Codex executable " +
    JSON.stringify(codexPath) +
    " " +
    detail +
    ". " +
    "Check that the named executable runs with --version, and check CODEX_CLI_PATH/PATH, then retry." +
    " Deep Scan did not run."
  );
}

/**
 * Recognize the precise late startup warning emitted when requirements reject
 * the selected Deep Scan profile. This is defense in depth for the accepted
 * preflight-to-exec race: stopping and discarding output cannot undo work that
 * the runtime may already have started under the fallback profile.
 */
export function deepScanPermissionProfileFallbackError(
  message: unknown,
): DeepScanNonRetryableError | undefined {
  if (typeof message !== "string") return undefined;
  const prefix =
    "Configured value for `permission_profile` is disallowed by requirements; " +
    `falling back from \`${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}\` to required value \``;
  const warning = message.trim();
  // The destination is an opaque quoted profile id. It can be empty and can
  // itself contain backticks or newlines, so only anchor the known source
  // prefix and the warning's terminal backtick-period.
  if (!warning.startsWith(prefix) || !warning.endsWith("`.")) return undefined;
  return new DeepScanNonRetryableError(
    `Deep Scan stopped a worker because organization policy rejected the required \`${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}\` permission profile after the turn started. The worker was stopped and its results were discarded. Ask your Codex administrator to define this read-only stub in a normal config layer:\n\n[permissions.${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}]\nextends = ":read-only"\n\nand add this entry to your existing allowlist in requirements.toml:\n\n[allowed_permission_profiles]\n${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID} = true`,
  );
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

function abortError(reason: unknown): Error {
  if (reason instanceof Error) return reason;
  return new DOMException(
    "Deep Scan worker permission profile preflight aborted.",
    "AbortError",
  );
}
