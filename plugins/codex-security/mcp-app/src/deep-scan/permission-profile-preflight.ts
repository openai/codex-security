import type { JsonObject as JsonRecord } from "../types.js";
import { asRecord as record } from "../record.js";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface, type Interface } from "node:readline";
import { createReadStream } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { version as MCP_APP_VERSION } from "../../package.json";
import { DeepScanNonRetryableError } from "./errors.js";
import { executablePathForSpawn } from "./executable-path.js";
import { isPermissionProfileFallbackWarning } from "../../../scripts/codex_profile.mjs";

/** The stable profile id selected by the worker's raw config overrides. */
export const DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID =
  "codex_security_deep_scan_worker";

export interface DeepScanPermissionProfilePreflightOptions {
  /** The exact Codex executable that will run the worker turn. */
  readonly codexPath: string;
  /** The worker cwd used for app-server startup and cwd-scoped config RPCs. */
  readonly cwd: string;
  /** Worker overrides, including the effective provider selection. */
  readonly configOverrides: readonly string[];
  /** Provider metadata needed for managed selection; credentials stay in private profiles. */
  readonly providerConfigOverrides?: readonly string[];
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
  /** Internal SDK helper context changes the wrapper-owned subject label. */
  readonly context?: "helper";
}

type PendingRequest = {
  readonly id: number;
  readonly method: string;
  readonly resolve: (message: JsonRecord) => void;
  readonly reject: (error: Error) => void;
};

type RuntimeConfigReadOptions = Pick<
  DeepScanPermissionProfilePreflightOptions,
  "codexPath" | "cwd" | "configOverrides" | "env" | "signal" | "context"
> & {
  readonly commandArgs?: readonly string[];
  readonly providerConfigOverrides?: readonly string[];
};

/** Read native effective settings, including managed provider requirements, without a turn. */
export async function readDeepScanRuntimeConfig(
  options: RuntimeConfigReadOptions,
): Promise<JsonRecord> {
  return withPreflightClient(options, async (client) => {
    const response = await client.request("config/read", {
      cwd: options.cwd,
      includeLayers: false,
    });
    const config = record(response.config);
    if (!config) throw malformedPreflightError(options.context);
    return config;
  });
}

/** Persist the owning session and obtain native permissions without a model turn. */
export async function prepareCliDeepScanSession(
  options: RuntimeConfigReadOptions & {
    prompt: string;
  },
): Promise<{
  threadId: string;
  model: string;
  reasoningEffort?: string;
  permissionProfile: unknown;
}> {
  return withPreflightClient(options, async (client) => {
    const response = await client.request("thread/start", {
      cwd: options.cwd,
      threadSource: "security_scan",
      ephemeral: false,
    });
    const thread = record(response.thread);
    if (
      typeof thread?.id !== "string" ||
      typeof thread.path !== "string" ||
      typeof response.model !== "string"
    ) {
      throw new Error("Codex did not return the owning Deep Scan session.");
    }
    // Native history persistence records the effective turn context, including
    // managed filesystem denials. No turn/start or model request is needed.
    await client.request("thread/inject_items", {
      threadId: thread.id,
      items: [
        {
          type: "message",
          role: "user",
          content: [{ type: "input_text", text: options.prompt }],
        },
      ],
    });
    let permissionProfile: unknown;
    const input = createReadStream(thread.path, { encoding: "utf8" });
    const lines = createInterface({ input, crlfDelay: Infinity });
    try {
      for await (const line of lines) {
        if (!line.trim()) continue;
        const entry = record(JSON.parse(line));
        if (entry?.type === "turn_context") {
          permissionProfile = record(entry.payload)?.permission_profile;
        }
      }
    } finally {
      lines.close();
      input.destroy();
    }
    if (permissionProfile === undefined) {
      throw new Error(
        "Codex did not persist the Deep Scan session's effective permissions.",
      );
    }
    return {
      threadId: thread.id,
      model: response.model,
      ...(typeof response.reasoningEffort === "string"
        ? { reasoningEffort: response.reasoningEffort }
        : {}),
      permissionProfile,
    };
  });
}

/**
 * Verify the worker profile with the same executable, effective worker cwd,
 * Codex home, and permission overrides that the real worker will use. App-server must
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
  return withPreflightClient(options, async (client) => {
    const configResponse = await client.request("config/read", {
      cwd: options.cwd,
      includeLayers: false,
    });
    const catalog = await client.readPermissionProfileCatalog(options.cwd);
    const matchingEntries = catalog.filter(
      (entry) => entry.id === DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
    );
    if (matchingEntries.length !== 1)
      throw malformedPreflightError(options.context);
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
    // Reuse Codex's selected credential store, including keyring, instead of
    // interpreting auth.json here. Custom provider auth is loaded privately by exec.
    const account = await client.request("account/read", {
      refreshToken: false,
    });
    return {
      useOpenAiApiKey:
        account.requiresOpenaiAuth === true && account.account === null,
    };
  });
}

async function withPreflightClient<T>(
  options: RuntimeConfigReadOptions,
  operation: (client: AppServerPreflightClient) => Promise<T>,
): Promise<T> {
  if (options.signal.aborted) throw abortError(options.signal.reason);
  const client = new AppServerPreflightClient(options);
  try {
    await client.initialize();
    return await operation(client);
  } catch (error) {
    await client.close();
    const stderr = client.stderrText;
    if (error instanceof Error && stderr)
      Object.defineProperty(error, "message", {
        value: error.message + "\n" + stderr,
        writable: true,
        configurable: true,
        enumerable: false,
      });
    throw error;
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
  private readonly stderr: Buffer[] = [];
  private terminalError: Error | undefined;
  private closed = false;
  private childClosed = false;
  private readonly removeAbortListener: () => void;

  constructor(private readonly options: RuntimeConfigReadOptions) {
    const args: string[] = [...(options.commandArgs ?? [])];
    for (const override of options.configOverrides) {
      args.push("--config", override);
    }
    // App-server loads credential-free metadata; exec reads private provider profiles.
    for (const override of options.providerConfigOverrides ?? []) {
      args.push("--config", override);
    }
    args.push("app-server", "--stdio");

    this.child = spawn(executablePathForSpawn(options.codexPath), args, {
      cwd: options.cwd,
      ...(options.env === undefined ? {} : { env: options.env }),
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    this.childClose = new Promise((resolve) => {
      this.child.once("close", () => {
        this.childClosed = true;
        resolve();
      });
    });
    this.child.stderr.on("data", (chunk) => this.stderr.push(chunk));
    this.stdoutLines = createInterface({
      input: this.child.stdout,
      crlfDelay: Infinity,
    });
    this.stdoutLines.on("line", (line) => this.consumeStdoutLine(line));
    const onStdioError = (error: Error) => {
      const failure = codexExecutableStdioError(
        options.codexPath,
        options.context,
      );
      failure.message += "\n" + error.message;
      this.fail(failure);
    };
    this.stdoutLines.on("error", onStdioError);
    this.child.stdin.on("error", onStdioError);
    this.child.on("error", (error) => {
      this.fail(
        codexExecutableStartError(options.codexPath, error, options.context),
      );
    });
    this.child.on("close", (code, signal) => {
      if (!this.closed) {
        this.fail(
          codexExecutableExitError(
            options.codexPath,
            code,
            signal,
            options.context,
          ),
        );
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

  get stderrText(): string {
    return Buffer.concat(this.stderr).toString("utf8");
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
      if (!Array.isArray(data))
        throw malformedPreflightError(this.options.context);
      for (const value of data) {
        const entry = record(value);
        // Catalog ids are opaque. Only our requested profile id is fixed and
        // non-empty; unrelated valid ids may be empty or otherwise unusual.
        if (!entry || typeof entry.id !== "string") {
          throw malformedPreflightError(this.options.context);
        }
        if (typeof entry.allowed !== "boolean")
          throw malformedPreflightError(this.options.context);
        entries.push(entry);
      }

      const nextCursor = result.nextCursor;
      if (nextCursor === null) return entries;
      if (
        typeof nextCursor !== "string" ||
        nextCursor.length === 0 ||
        seenCursors.has(nextCursor)
      ) {
        throw malformedPreflightError(this.options.context);
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
    this.stopChild();
    if (this.childClosed) return;
    const forcedTermination = setTimeout(() => {
      if (this.child.exitCode === null && this.child.signalCode === null) {
        this.child.kill("SIGKILL");
      }
      // Descendants can keep inherited pipes open after the child exits.
      this.child.stdin.destroy();
      this.child.stdout.destroy();
      this.child.stderr.destroy();
    }, 1_000);
    try {
      await this.childClose;
    } finally {
      clearTimeout(forcedTermination);
    }
  }

  private write(message: JsonRecord): void {
    if (!this.child.stdin.writable) {
      this.fail(
        codexExecutableStdioError(this.options.codexPath, this.options.context),
      );
      return;
    }
    this.child.stdin.write(`${JSON.stringify(message)}\n`, (error) => {
      if (error) {
        const failure = codexExecutableStdioError(
          this.options.codexPath,
          this.options.context,
        );
        failure.message += "\n" + error.message;
        this.fail(failure);
      }
    });
  }

  private consumeStdoutLine(line: string): void {
    if (this.terminalError || line.trim().length === 0) return;
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      this.fail(malformedPreflightError(this.options.context));
      return;
    }
    const message = record(value);
    if (!message) {
      this.fail(malformedPreflightError(this.options.context));
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
      this.fail(malformedPreflightError(this.options.context));
      return;
    }
    this.pending = undefined;
    if (message.error !== undefined) {
      pending.reject(
        jsonRpcPreflightError(
          this.options.codexPath,
          pending.method,
          message.error,
          this.options.context,
        ),
      );
      return;
    }
    const result = record(message.result);
    if (!result) {
      pending.reject(malformedPreflightError(this.options.context));
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
      ? disallowedProfileAllowlistError(options.context)
      : managedPolicyRejectedError(options.context);
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
    throw malformedPreflightError(options.context);

  if (config.default_permissions !== DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID) {
    throw profileNotSelectedError(options.context);
  }

  const expectedProfile = comparableProfile(options.expectedProfile);
  const actualWithoutDescription = comparableProfile(actualProfile);
  if (!isDeepStrictEqual(actualWithoutDescription, expectedProfile)) {
    throw profileCollisionError(options.context);
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
 * strict comparison. A display description does not affect permissions.
 */
function comparableProfile(
  value: Readonly<Record<string, unknown>>,
): JsonRecord {
  const { description: _description, ...rest } = stripNullObjectFields(
    value,
  ) as JsonRecord;
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

// Verified permission incompatibilities explicitly stop the scan. A failed
// transport attempt alone does not establish that the scan cannot proceed.
function disallowedProfileAllowlistError(
  context?: "helper",
): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(
    `${subject(context)} cannot safely start a read-only worker because organization policy does not allow the required \`${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}\` permission profile. Ask your Codex administrator to define this read-only stub in a normal config layer:\n\n[permissions.${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}]\nextends = ":read-only"\n\nand add this entry to your existing allowlist in requirements.toml:\n\n[allowed_permission_profiles]\n${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID} = true\n\n${subject(context)} did not run.`,
  );
}

function managedPolicyRejectedError(
  context?: "helper",
): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(
    `${subject(context)} cannot safely start a read-only worker because managed Codex policy rejected the required \`${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}\` permission profile. Ask your Codex administrator to review the managed permission, sandbox, and filesystem requirements. ${subject(context)} did not run.`,
  );
}

function profileNotSelectedError(
  context?: "helper",
): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(
    `${subject(context)} cannot safely start a read-only worker because Codex did not select the required \`${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}\` permission profile. Ask your Codex administrator to allow that profile for ${subject(context)}. ${subject(context)} did not run.`,
  );
}

function profileCollisionError(context?: "helper"): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(
    `${subject(context)} cannot safely start a read-only worker because existing Codex configuration changes the reserved \`${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}\` permission profile. Ask your Codex administrator to keep the normal-config \`[permissions.${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}]\` stub limited to \`extends = ":read-only"\`; ${subject(context)} supplies its deny rules at runtime. ${subject(context)} did not run.`,
  );
}

function malformedPreflightError(context?: "helper"): Error {
  return new Error(
    `${subject(context)} cannot safely verify its read-only worker permission profile with this Codex configuration. ${subject(context)} did not run.`,
  );
}

function unsupportedCodexApiError(
  codexPath: string,
  api: string,
  context?: "helper",
): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(
    subject(context) +
      " cannot safely verify its read-only worker permission profile because " +
      "the selected Codex executable " +
      JSON.stringify(codexPath) +
      " does not support the required " +
      JSON.stringify(api) +
      " API. " +
      "Update the Codex installation at that path " +
      "(the desktop app if it is bundled, otherwise the selected CLI) and retry." +
      " " +
      subject(context) +
      " did not run.",
  );
}

function jsonRpcPreflightError(
  codexPath: string,
  method: string,
  value: unknown,
  context?: "helper",
): Error {
  const error = record(value);
  const code =
    typeof error?.code === "number" && Number.isFinite(error.code)
      ? error.code
      : undefined;
  if (code === -32601) {
    const failure = unsupportedCodexApiError(codexPath, method, context);
    if (typeof error?.message === "string")
      failure.message += "\n" + error.message;
    return failure;
  }
  return new Error(
    subject(context) +
      " cannot safely verify its read-only worker permission profile because " +
      "the selected Codex executable " +
      JSON.stringify(codexPath) +
      " returned an error for " +
      JSON.stringify(method) +
      (code === undefined ? "" : " (JSON-RPC code " + code + ")") +
      ". Check the Codex configuration and retry. " +
      subject(context) +
      " did not run." +
      (typeof error?.message === "string" ? "\n" + error.message : ""),
  );
}

function codexExecutableStartError(
  codexPath: string,
  error: Error,
  context?: "helper",
): Error {
  const value = "code" in error ? error.code : undefined;
  const code =
    typeof value === "string" && /^[A-Z0-9_]+$/u.test(value)
      ? value
      : undefined;
  const codeDetail = code === undefined ? "" : " (" + code + ")";
  return new Error(
    codexExecutableFailureMessage(
      codexPath,
      "could not start" + codeDetail,
      context,
    ) +
      "\n" +
      error.message,
    { cause: error },
  );
}

function codexExecutableExitError(
  codexPath: string,
  code: number | null,
  signal: NodeJS.Signals | null,
  context?: "helper",
): Error {
  const detail =
    code !== null
      ? "exited before permission-profile verification completed with code " +
        code
      : signal !== null
        ? "was terminated before permission-profile verification completed by signal " +
          signal
        : "exited before permission-profile verification completed";
  return new Error(codexExecutableFailureMessage(codexPath, detail, context));
}

function codexExecutableStdioError(
  codexPath: string,
  context?: "helper",
): Error {
  return new Error(
    codexExecutableFailureMessage(
      codexPath,
      "could not exchange app-server JSON-RPC over stdio",
      context,
    ),
  );
}

function codexExecutableFailureMessage(
  codexPath: string,
  detail: string,
  context?: "helper",
): string {
  return (
    subject(context) +
    " cannot safely verify its read-only worker permission profile because " +
    "the selected Codex executable " +
    JSON.stringify(codexPath) +
    " " +
    detail +
    ". " +
    "Check that the named executable runs with --version, and check CODEX_CLI_PATH/PATH, then retry." +
    " " +
    subject(context) +
    " did not run."
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
  if (
    !isPermissionProfileFallbackWarning(
      message,
      DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
    )
  )
    return undefined;
  return new DeepScanNonRetryableError(
    `Deep Scan stopped a worker because organization policy rejected the required \`${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}\` permission profile after the turn started. The worker was stopped and its results were discarded. Ask your Codex administrator to define this read-only stub in a normal config layer:\n\n[permissions.${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}]\nextends = ":read-only"\n\nand add this entry to your existing allowlist in requirements.toml:\n\n[allowed_permission_profiles]\n${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID} = true\n${message}`,
  );
}

function subject(context?: "helper"): string {
  return context === "helper" ? "Read-only Codex helper" : "Deep Scan";
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
