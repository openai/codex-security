/// <reference lib="esnext.disposable" preserve="true" />

import { lstat, mkdir, realpath } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { basename, isAbsolute, join, relative, sep } from "node:path";
import { Codex, type CodexOptions } from "@openai/codex-sdk";
import {
  accountStatus,
  CodexLoginHandle,
  loginApiKey as persistApiKey,
  logout as codexLogout,
  type AccountStatus,
} from "./auth.js";
import {
  mergedCodexConfig,
  type CodexSecurityConfig,
  writeCodexConfig,
} from "./config.js";
import {
  loadContract,
  requireScanFile,
  type ScanExpectation,
} from "./contract.js";
import {
  AuthenticationRequiredError,
  CodexSecurityError,
  IncompleteScanError,
  InvalidTargetError,
  OutputDirectoryError,
  ScanInterruptedError,
  UnsupportedCodexSdkCapabilityError,
} from "./errors.js";
import { ScanResult, type TurnResultMetadata } from "./result.js";
import {
  bootstrapPlugin,
  cleanupSdkDirectory,
  createIsolatedHome,
  importAmbientAuth,
  pluginExecutionEnvironment,
  prepareOutputDir,
  resolveCodexCommand,
  resolvePluginPath,
  resolvePluginPython,
  type CodexCommand,
  type PluginInstall,
  type ProcessEnvironment,
  validateOutputDir,
  validatePreparedOutputDir,
} from "./runtime.js";
import {
  enclosingGitWorktreeRoot,
  normalizeRepository,
  normalizeTarget,
  repositoryRevision,
  resolveRepositoryPath,
  type NormalizedTarget,
  type ScanMode,
  type ScanTarget,
  validateMode,
} from "./targets.js";

interface CodexThreadLike {
  readonly id: string | null;
  runStreamed(
    input: string,
    options: { signal: AbortSignal },
  ): Promise<{ events: AsyncGenerator<ScanEvent> }>;
}

export interface ScanEvent {
  readonly type: string;
  readonly [key: string]: unknown;
}

interface CodexClientLike {
  startThread(options: {
    workingDirectory: string;
    skipGitRepoCheck: boolean;
    sandboxMode: "workspace-write";
    approvalPolicy: "never";
  }): CodexThreadLike;
}

interface PreparedRuntime {
  codexHome: string;
  plugin: PluginInstall;
  environment: Record<string, string>;
  credentialsAvailable: boolean;
}

interface InFlightPreparation {
  controller: AbortController;
  settled: Promise<void>;
}

export interface ScanOptions {
  target?: ScanTarget;
  mode?: ScanMode;
  outputDir?: string;
  onOutputDirReady?: (scanDir: string) => void;
  signal?: AbortSignal;
}

export interface CodexSecurityMetadata {
  sdk: "@openai/codex-sdk";
  sdkVersion: "0.142.0";
  executable: "@openai/codex";
  executableVersion: "0.142.0";
}

interface ClientDependencies {
  createCodex(options: CodexOptions): CodexClientLike;
  environment: ProcessEnvironment;
  prepareRuntime?: (
    config: Readonly<CodexSecurityConfig>,
    signal?: AbortSignal,
  ) => Promise<PreparedRuntime>;
  resolvePluginPython?: typeof resolvePluginPython;
  prepareOutputDir?: typeof prepareOutputDir;
  repositoryRevision?: typeof repositoryRevision;
  resolveCodexCommand?: () => CodexCommand;
}

const DEFAULT_DEPENDENCIES: ClientDependencies = {
  createCodex: (options) => new Codex(options),
  environment: process.env,
};

export class CodexSecurity {
  public readonly config: Readonly<CodexSecurityConfig>;
  public readonly metadata: CodexSecurityMetadata = {
    sdk: "@openai/codex-sdk",
    sdkVersion: "0.142.0",
    executable: "@openai/codex",
    executableVersion: "0.142.0",
  };

  readonly #dependencies: ClientDependencies;
  readonly #handles = new Set<ScanHandle>();
  readonly #loginHandles = new Set<CodexLoginHandle>();
  readonly #preparations = new Set<InFlightPreparation>();
  #runtimePromise: Promise<PreparedRuntime> | null = null;
  #runtimeAbortController: AbortController | null = null;
  #runtime: PreparedRuntime | null = null;
  #preferFileCredentials = false;
  #closed = false;
  #closePromise: Promise<void> | null = null;

  public constructor(config?: CodexSecurityConfig);
  public constructor(
    config: CodexSecurityConfig = {},
    dependencies: ClientDependencies = DEFAULT_DEPENDENCIES,
  ) {
    this.config = structuredClone(config);
    this.#dependencies = dependencies;
  }

  public async run(
    repository: string,
    options: ScanOptions = {},
  ): Promise<ScanResult> {
    return await (await this.#turn(repository, options, false)).run();
  }

  public async turn(
    repository: string,
    options: ScanOptions = {},
  ): Promise<ScanHandle> {
    return await this.#turn(repository, options, true);
  }

  async #turn(
    repository: string,
    options: ScanOptions,
    replayEvents: boolean,
  ): Promise<ScanHandle> {
    this.#requireOpen();
    const controller = new AbortController();
    const removeExternalAbort = forwardAbort(options.signal, controller);
    let markPreparationSettled!: () => void;
    const preparation: InFlightPreparation = {
      controller,
      settled: new Promise<void>((resolve) => {
        markPreparationSettled = resolve;
      }),
    };
    this.#preparations.add(preparation);
    let scanDir = "";
    let handedOff = false;
    const target = options.target ?? "repository";
    const mode = options.mode ?? "standard";
    try {
      const checkOpen = (): void => {
        this.#requireOpen();
        throwIfAborted(controller.signal, scanDir);
      };

      // Validate all local inputs before runtime initialization or plugin-Python discovery.
      const repositoryPath = resolveRepositoryPath(repository);
      const repo = await normalizeRepository(repositoryPath, controller.signal);
      checkOpen();
      const normalized = await normalizeTarget(repo, target, controller.signal);
      checkOpen();
      validateMode(normalized, mode);
      const targetMetadata =
        normalized.kind === "paths"
          ? await Promise.all(
              normalized.paths.map((path) => lstat(join(repo, path))),
            )
          : [];
      const protectedRoot =
        (await enclosingGitWorktreeRoot(repo, controller.signal)) ?? repo;
      const repositoryMetadata = await lstat(repo);
      const protectedRootMetadata = await lstat(protectedRoot);
      const requireUnchangedRepository = async (): Promise<void> => {
        const currentRepository = await normalizeRepository(
          repositoryPath,
          controller.signal,
        );
        const currentMetadata = await lstat(currentRepository);
        const currentProtectedRoot =
          (await enclosingGitWorktreeRoot(
            currentRepository,
            controller.signal,
          )) ?? currentRepository;
        const currentProtectedRootMetadata = await lstat(currentProtectedRoot);
        if (
          currentRepository !== repo ||
          currentMetadata.dev !== repositoryMetadata.dev ||
          currentMetadata.ino !== repositoryMetadata.ino ||
          currentProtectedRoot !== protectedRoot ||
          currentProtectedRootMetadata.dev !== protectedRootMetadata.dev ||
          currentProtectedRootMetadata.ino !== protectedRootMetadata.ino
        ) {
          throw new InvalidTargetError(
            `Repository changed during scan preparation: ${repo}`,
          );
        }
      };
      const requestedOutput = await validateOutputDir(options.outputDir);
      let temporaryRoot: string | undefined;
      if (requestedOutput === null || this.#runtime === null) {
        temporaryRoot = await realpath(tmpdir());
        requireOutputOutsideRepository(protectedRoot, temporaryRoot);
      }
      if (requestedOutput !== null) {
        requireOutputOutsideRepository(protectedRoot, requestedOutput);
      }
      checkOpen();

      const runtime = await this.#ensureRuntime(
        controller.signal,
        temporaryRoot,
        (path) => requireOutputOutsideRepository(protectedRoot, path),
      );
      const runtimeHome = await realpath(runtime.codexHome);
      requireOutputOutsideRepository(protectedRoot, runtimeHome);
      const runtimeHomeMetadata = await lstat(runtimeHome);
      const requireUnchangedRuntimeHome = async (): Promise<void> => {
        try {
          const currentHome = await realpath(runtime.codexHome);
          requireOutputOutsideRepository(protectedRoot, currentHome);
          const currentMetadata = await lstat(currentHome);
          if (
            currentHome !== runtimeHome ||
            currentMetadata.dev !== runtimeHomeMetadata.dev ||
            currentMetadata.ino !== runtimeHomeMetadata.ino
          ) {
            throw new OutputDirectoryError(
              `Codex runtime directory changed during scan preparation: ${runtime.codexHome}`,
            );
          }
        } catch (error) {
          if (error instanceof OutputDirectoryError) throw error;
          throw new OutputDirectoryError(
            `Unable to inspect Codex runtime directory: ${runtime.codexHome}`,
            { cause: error },
          );
        }
      };
      checkOpen();
      const apiKey = this.#preferFileCredentials
        ? null
        : environmentApiKey(this.#dependencies.environment);
      if (apiKey !== null) {
        const codexCommand = this.#codexCommand();
        await requireUnchangedRuntimeHome();
        const login = await persistApiKey(
          codexCommand,
          withoutApiKeys(runtime.environment),
          apiKey,
          controller.signal,
        );
        if (!login.success) {
          throw new CodexSecurityError(
            `Codex API-key login failed: ${login.stderr.trim() || login.stdout.trim() || "unknown error"}`,
          );
        }
        runtime.credentialsAvailable = true;
        this.#preferFileCredentials = true;
      }
      if (!runtime.credentialsAvailable) {
        throw new AuthenticationRequiredError(
          "The isolated Codex home has no reusable authentication. Set OPENAI_API_KEY or " +
            "CODEX_API_KEY, call a login method, or use file-backed Codex authentication.",
        );
      }
      const python = await (
        this.#dependencies.resolvePluginPython ?? resolvePluginPython
      )({
        configuredPath: this.config.pythonPath,
        environment: withoutApiKeys(this.#dependencies.environment),
        signal: controller.signal,
      });
      checkOpen();
      await requireUnchangedRepository();
      scanDir = await (this.#dependencies.prepareOutputDir ?? prepareOutputDir)(
        requestedOutput ?? undefined,
        basename(repo),
        temporaryRoot,
        (path) => requireOutputOutsideRepository(protectedRoot, path),
      );
      requireOutputOutsideRepository(protectedRoot, scanDir);
      const scanDirMetadata = await lstat(scanDir);
      options.onOutputDirReady?.(scanDir);
      checkOpen();

      const prompt = await scanPrompt(
        runtime.plugin.installedRoot,
        repo,
        normalized,
        mode,
        scanDir,
        python,
      );
      checkOpen();
      const expectation: ScanExpectation = {
        repository: repo,
        repositoryRevision: await (
          this.#dependencies.repositoryRevision ?? repositoryRevision
        )(repo, controller.signal),
        target: normalized,
        mode,
        pluginVersion: runtime.plugin.version,
      };
      checkOpen();
      await requireUnchangedRepository();
      const validateScanOutput = async (): Promise<void> => {
        try {
          await validatePreparedOutputDir(
            scanDir,
            (path) => requireOutputOutsideRepository(protectedRoot, path),
            scanDirMetadata,
          );
        } catch (error) {
          if (error instanceof OutputDirectoryError) throw error;
          throw new OutputDirectoryError(
            `Scan output directory changed during preparation: ${scanDir}`,
            { cause: error },
          );
        }
      };
      await validateScanOutput();
      checkOpen();

      const environment = pluginExecutionEnvironment(
        python,
        withoutApiKeys(runtime.environment),
      );
      const codex = this.#dependencies.createCodex({
        env: definedEnvironment(environment),
        config: { sandbox_workspace_write: { writable_roots: [scanDir] } },
      });
      const thread = codex.startThread({
        workingDirectory: scanDir,
        skipGitRepoCheck: true,
        sandboxMode: "workspace-write",
        approvalPolicy: "never",
      });
      await requireUnchangedRepository();
      if (normalized.kind === "paths") {
        const currentTarget = await normalizeTarget(
          repo,
          normalized.paths,
          controller.signal,
        );
        const currentTargetMetadata =
          currentTarget.kind === "paths"
            ? await Promise.all(
                currentTarget.paths.map((path) => lstat(join(repo, path))),
              )
            : [];
        if (
          currentTarget.kind !== "paths" ||
          currentTarget.paths.length !== normalized.paths.length ||
          currentTarget.paths.some(
            (path, index) => path !== normalized.paths[index],
          ) ||
          currentTargetMetadata.some(
            (metadata, index) =>
              metadata.dev !== targetMetadata[index]?.dev ||
              metadata.ino !== targetMetadata[index]?.ino,
          )
        ) {
          throw new InvalidTargetError(
            `Path target changed during scan preparation: ${repo}`,
          );
        }
      }
      await requireUnchangedRuntimeHome();
      await validateScanOutput();
      checkOpen();
      const { events } = await thread.runStreamed(prompt, {
        signal: controller.signal,
      });
      checkOpen();

      let handle: ScanHandle;
      handle = new ScanHandle({
        thread,
        events,
        abortController: controller,
        scanDir,
        pluginRoot: runtime.plugin.installedRoot,
        expectation,
        replayEvents,
        onSettled: () => {
          removeExternalAbort();
          this.#handles.delete(handle);
        },
      });
      this.#handles.add(handle);
      handedOff = true;
      return handle;
    } catch (error) {
      if (this.#closed) this.#requireOpen();
      if (
        controller.signal.aborted &&
        !(error instanceof ScanInterruptedError)
      ) {
        throwIfAborted(controller.signal, scanDir);
      }
      throw error;
    } finally {
      this.#preparations.delete(preparation);
      markPreparationSettled();
      if (!handedOff) removeExternalAbort();
    }
  }

  public async loginApiKey(apiKey: string): Promise<void> {
    const { result, runtime } = await this.#runOperation(
      async (preparedRuntime, signal) => ({
        runtime: preparedRuntime,
        result: await persistApiKey(
          this.#codexCommand(),
          withoutApiKeys(preparedRuntime.environment),
          apiKey,
          signal,
        ),
      }),
    );
    if (!result.success) {
      throw new CodexSecurityError(
        `Codex API-key login failed: ${result.stderr.trim() || result.stdout.trim() || "unknown error"}`,
      );
    }
    this.#preferFileCredentials = true;
    runtime.credentialsAvailable = true;
  }

  public async loginChatGPT(): Promise<CodexLoginHandle> {
    const runtime = await this.#ensureRuntime();
    this.#requireOpen();
    const handle = this.#trackLoginHandle(
      new CodexLoginHandle(
        this.#codexCommand(),
        ["login"],
        runtime.environment,
        () => {
          this.#preferFileCredentials = true;
          runtime.credentialsAvailable = true;
        },
      ),
    );
    await handle.waitForInstructions();
    this.#requireOpen();
    return handle;
  }

  public async loginChatGPTDeviceCode(): Promise<CodexLoginHandle> {
    const runtime = await this.#ensureRuntime();
    this.#requireOpen();
    const handle = this.#trackLoginHandle(
      new CodexLoginHandle(
        this.#codexCommand(),
        ["login", "--device-auth"],
        runtime.environment,
        () => {
          this.#preferFileCredentials = true;
          runtime.credentialsAvailable = true;
        },
      ),
    );
    await handle.waitForInstructions({ deviceCode: true });
    this.#requireOpen();
    return handle;
  }

  public async account(
    options: { refreshToken?: boolean } = {},
  ): Promise<AccountStatus> {
    return await this.#runOperation(async (runtime, signal) => {
      const apiKey = this.#preferFileCredentials
        ? null
        : environmentApiKey(this.#dependencies.environment);
      if (apiKey !== null) {
        if (options.refreshToken === true) {
          throw new UnsupportedCodexSdkCapabilityError(
            "API-key authentication does not provide a refresh token.",
          );
        }
        return {
          authenticated: true,
          details: "Authenticated with an API key.",
        };
      }
      return await accountStatus(
        this.#codexCommand(),
        runtime.environment,
        options,
        signal,
      );
    });
  }

  public async logout(): Promise<void> {
    const runtime = await this.#runOperation(
      async (preparedRuntime, signal) => {
        await codexLogout(
          this.#codexCommand(),
          preparedRuntime.environment,
          signal,
        );
        return preparedRuntime;
      },
    );
    this.#preferFileCredentials = false;
    runtime.credentialsAvailable = false;
  }

  public async close(): Promise<void> {
    if (this.#closePromise !== null) return await this.#closePromise;
    this.#closed = true;
    this.#closePromise = this.#finishClose();
    await this.#closePromise;
  }

  async #finishClose(): Promise<void> {
    this.#runtimeAbortController?.abort();
    const preparations = [...this.#preparations];
    for (const preparation of preparations) preparation.controller.abort();
    const loginHandles = [...this.#loginHandles];
    for (const handle of loginHandles) handle.cancel();
    for (const handle of this.#handles) handle.interrupt();
    await Promise.allSettled(
      preparations.map(async (preparation) => await preparation.settled),
    );
    await Promise.allSettled(
      loginHandles.map(async (handle) => await handle.wait()),
    );
    for (const handle of this.#handles) handle.interrupt();
    await Promise.allSettled(
      [...this.#handles].map(async (handle) => await handle.settled()),
    );
    const runtime =
      this.#runtime ?? (await this.#runtimePromise?.catch(() => null));
    this.#runtime = null;
    this.#runtimePromise = null;
    this.#runtimeAbortController = null;
    if (runtime !== null && runtime !== undefined) {
      await cleanupSdkDirectory(runtime.codexHome);
    }
  }

  public async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  async #runOperation<T>(
    operation: (runtime: PreparedRuntime, signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    this.#requireOpen();
    const controller = new AbortController();
    let markSettled!: () => void;
    const preparation: InFlightPreparation = {
      controller,
      settled: new Promise<void>((resolve) => {
        markSettled = resolve;
      }),
    };
    this.#preparations.add(preparation);
    try {
      const runtime = await this.#ensureRuntime(controller.signal);
      this.#requireOpen();
      const result = await operation(runtime, controller.signal);
      this.#requireOpen();
      return result;
    } finally {
      this.#preparations.delete(preparation);
      markSettled();
    }
  }

  async #ensureRuntime(
    signal?: AbortSignal,
    temporaryRoot?: string,
    validateLocation?: (path: string) => void,
  ): Promise<PreparedRuntime> {
    this.#requireOpen();
    if (this.#runtime !== null) return this.#runtime;
    if (this.#runtimePromise === null) {
      this.#runtimeAbortController = new AbortController();
      const runtimePromise = this.#prepareRuntime(
        this.#runtimeAbortController.signal,
        temporaryRoot,
        validateLocation,
      );
      this.#runtimePromise = runtimePromise;
      void runtimePromise.catch(() => {
        if (this.#runtimePromise === runtimePromise) {
          this.#runtimePromise = null;
          this.#runtimeAbortController = null;
        }
      });
    }
    const runtime = await waitForPromise(this.#runtimePromise, signal);
    this.#requireOpen();
    this.#runtime = runtime;
    return this.#runtime;
  }

  #trackLoginHandle(handle: CodexLoginHandle): CodexLoginHandle {
    this.#loginHandles.add(handle);
    void handle.wait().then(
      () => this.#loginHandles.delete(handle),
      () => this.#loginHandles.delete(handle),
    );
    return handle;
  }

  #codexCommand(): CodexCommand {
    return (this.#dependencies.resolveCodexCommand ?? resolveCodexCommand)();
  }

  async #prepareRuntime(
    signal: AbortSignal,
    temporaryRoot?: string,
    validateLocation?: (path: string) => void,
  ): Promise<PreparedRuntime> {
    if (this.#dependencies.prepareRuntime !== undefined) {
      return await this.#dependencies.prepareRuntime(this.config, signal);
    }
    const codexHome = await createIsolatedHome(temporaryRoot, validateLocation);
    try {
      throwIfAborted(signal);
      const workspace = join(codexHome, "bootstrap");
      await mkdir(workspace, { recursive: true, mode: 0o700 });
      const pluginRoot = await resolvePluginPath(
        this.config.pluginPath,
        workspace,
        signal,
      );
      await writeCodexConfig(
        join(codexHome, "config.toml"),
        await mergedCodexConfig(this.config, { pluginRoot }),
      );
      throwIfAborted(signal);
      const processEnvironment = this.#dependencies.environment;
      const plugin = await bootstrapPlugin(codexHome, pluginRoot, {
        environment: processEnvironment,
        signal,
      });
      const ambientHome =
        processEnvironment["CODEX_HOME"] ?? join(homedir(), ".codex");
      const credentialsAvailable = await initialCredentialsAvailable(
        processEnvironment,
        ambientHome,
        codexHome,
      );
      return {
        codexHome,
        plugin,
        environment: {
          ...withoutApiKeys(processEnvironment),
          CODEX_HOME: codexHome,
        },
        credentialsAvailable,
      };
    } catch (error) {
      await cleanupSdkDirectory(codexHome);
      throw error;
    }
  }

  #requireOpen(): void {
    if (this.#closed) throw new CodexSecurityError("CodexSecurity is closed.");
  }
}

export async function initialCredentialsAvailable(
  environment: ProcessEnvironment,
  ambientHome: string,
  isolatedHome: string,
  importer: typeof importAmbientAuth = importAmbientAuth,
): Promise<boolean> {
  if (environmentApiKey(environment) !== null) return false;
  return await importer(ambientHome, isolatedHome);
}

interface ScanHandleOptions {
  thread: CodexThreadLike;
  events: AsyncGenerator<ScanEvent>;
  abortController: AbortController;
  scanDir: string;
  pluginRoot: string;
  expectation: ScanExpectation;
  replayEvents?: boolean;
  onSettled: () => void;
}

export class ScanHandle {
  public readonly scanDir: string;
  readonly #thread: CodexThreadLike;
  readonly #abortController: AbortController;
  readonly #eventLog: EventLog<ScanEvent>;
  readonly #completion: Promise<ScanResult>;
  #threadId: string | null;
  #status = "in_progress";
  #finalResponse = "";
  #usage: unknown = null;

  public constructor(options: ScanHandleOptions) {
    this.scanDir = options.scanDir;
    this.#thread = options.thread;
    this.#threadId = options.thread.id;
    this.#abortController = options.abortController;
    this.#eventLog = new EventLog(options.replayEvents ?? true);
    this.#completion = this.#pump(options);
    void this.#completion.catch(() => undefined);
  }

  public get id(): null {
    return null;
  }

  public get threadId(): string | null {
    return this.#threadId ?? this.#thread.id;
  }

  public stream(): AsyncIterable<ScanEvent> {
    return this.#eventLog.iterate();
  }

  public async run(): Promise<ScanResult> {
    return await this.#completion;
  }

  public interrupt(): void {
    this.#abortController.abort();
  }

  public async steer(_input: string): Promise<never> {
    throw new UnsupportedCodexSdkCapabilityError(
      "Active-turn steering is not exposed by @openai/codex-sdk@0.142.0. " +
        "The scan continues unchanged; no private transport was used.",
    );
  }

  public async settled(): Promise<void> {
    await this.#completion.then(
      () => undefined,
      () => undefined,
    );
  }

  async #pump(options: ScanHandleOptions): Promise<ScanResult> {
    try {
      for await (const event of options.events) {
        this.#eventLog.push(event);
        if (event.type === "thread.started") {
          const threadId = event["thread_id"];
          if (typeof threadId === "string") this.#threadId = threadId;
        } else if (
          event.type === "item.completed" &&
          isRecord(event["item"]) &&
          event["item"]["type"] === "agent_message" &&
          typeof event["item"]["text"] === "string"
        ) {
          this.#finalResponse = event["item"]["text"];
        } else if (event.type === "turn.completed") {
          this.#status = "completed";
          this.#usage = event["usage"];
        } else if (
          event.type === "turn.failed" &&
          isRecord(event["error"]) &&
          typeof event["error"]["message"] === "string"
        ) {
          this.#status = "failed";
          throw new CodexSecurityError(event["error"]["message"]);
        } else if (
          event.type === "error" &&
          typeof event["message"] === "string"
        ) {
          this.#status = "failed";
          throw new CodexSecurityError(event["message"]);
        }
      }
      if (this.#abortController.signal.aborted) {
        this.#status = "interrupted";
        throw new ScanInterruptedError(
          `Codex Security scan was interrupted; partial output remains at ${this.scanDir}.`,
          this.scanDir,
        );
      }
      if (this.#status !== "completed") {
        throw new IncompleteScanError(
          "Codex Security event stream ended before the turn completed.",
        );
      }
      const threadId = this.threadId;
      if (threadId === null) {
        throw new IncompleteScanError(
          "Codex Security did not report a thread ID.",
        );
      }
      const turnResult: TurnResultMetadata = {
        status: this.#status,
        finalResponse: this.#finalResponse,
        usage: this.#usage,
      };
      const result = await collectResult(
        turnResult,
        threadId,
        this.scanDir,
        options.pluginRoot,
        options.expectation,
        this.#abortController.signal,
      );
      if (this.#abortController.signal.aborted) {
        this.#status = "interrupted";
        throw new ScanInterruptedError(
          `Codex Security scan was interrupted; partial output remains at ${this.scanDir}.`,
          this.scanDir,
        );
      }
      this.#eventLog.finish();
      return result;
    } catch (error) {
      if (
        this.#abortController.signal.aborted &&
        !(error instanceof ScanInterruptedError)
      ) {
        error = new ScanInterruptedError(
          `Codex Security scan was interrupted; partial output remains at ${this.scanDir}.`,
          this.scanDir,
          { cause: error },
        );
      }
      this.#eventLog.finish(error);
      throw error;
    } finally {
      options.onSettled();
    }
  }
}

async function scanPrompt(
  pluginRoot: string,
  repository: string,
  target: NormalizedTarget,
  mode: ScanMode,
  scanDir: string,
  python: string,
): Promise<string> {
  const skillName = skillNameFor(target, mode);
  const skillPath = join(pluginRoot, "skills", skillName, "SKILL.md");
  const metadata = await lstat(skillPath).catch(() => null);
  if (metadata === null || !metadata.isFile() || metadata.isSymbolicLink()) {
    throw new IncompleteScanError(
      `Installed plugin is missing scan skill: ${skillName}`,
    );
  }
  return [
    `Use the installed $codex-security:${skillName} skill at ${skillPath}.`,
    "Run this Codex Security scan non-interactively.",
    "This SDK host does not render MCP Apps; use the terminal/chat workflow.",
    `Use ${JSON.stringify(python)} as <python_command> for every plugin helper; replace any literal python or python3 helper invocation with this exact interpreter.`,
    `Repository root: ${repository}`,
    `Use this exact scan directory for all scan output: ${scanDir}`,
    targetInstruction(target),
    "Complete and seal the canonical JSON contract before returning.",
  ].join("\n");
}

function skillNameFor(target: NormalizedTarget, mode: ScanMode): string {
  if (target.kind === "refs" || target.kind === "working_tree")
    return "security-diff-scan";
  return mode === "deep" ? "deep-security-scan" : "security-scan";
}

function targetInstruction(target: NormalizedTarget): string {
  if (target.kind === "repository")
    return "Scan target: the entire repository.";
  if (target.kind === "paths")
    return `Scan target paths: ${target.paths.join(", ")}`;
  if (target.kind === "refs") {
    return `Scan target: Git diff from ${target.baseRef} to ${target.headRef}.`;
  }
  return `Scan target: staged and unstaged working-tree changes against ${target.baseRef}.`;
}

async function collectResult(
  turnResult: TurnResultMetadata,
  threadId: string,
  scanDir: string,
  pluginRoot: string,
  expectation: ScanExpectation,
  signal: AbortSignal,
): Promise<ScanResult> {
  const required = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
  ];
  const missing: string[] = [];
  for (const name of required) {
    try {
      await requireScanFile(scanDir, name, name, signal);
    } catch (error) {
      if (signal.aborted) throw signal.reason ?? error;
      missing.push(name);
    }
  }
  if (missing.length > 0) {
    throw new IncompleteScanError(
      `Codex Security scan completed without required artifacts: ${missing.join(", ")}`,
    );
  }
  const { manifest, findings, coverage } = await loadContract(scanDir, {
    pluginRoot,
    expectation,
    signal,
  });
  let sarifPath: string | null = null;
  try {
    sarifPath = await requireScanFile(
      scanDir,
      "exports/results.sarif",
      "exports/results.sarif",
      signal,
    );
  } catch (error) {
    if (signal.aborted) throw signal.reason ?? error;
  }
  return new ScanResult({
    manifest,
    findings,
    coverage,
    scanDir,
    threadId,
    turnResult,
    sarifPath,
  });
}

class EventLog<T> {
  readonly #items: T[] = [];
  readonly #waiters = new Set<() => void>();
  #finished = false;
  #error: unknown;

  public constructor(private readonly replay: boolean) {}

  public push(item: T): void {
    if (this.replay) this.#items.push(item);
    this.#wake();
  }

  public finish(error?: unknown): void {
    this.#error = error;
    this.#finished = true;
    this.#wake();
  }

  public async *iterate(): AsyncGenerator<T> {
    let index = 0;
    while (true) {
      while (index < this.#items.length) {
        yield this.#items[index++]!;
      }
      if (this.#finished) {
        if (this.#error !== undefined) throw this.#error;
        return;
      }
      await new Promise<void>((resolve) => this.#waiters.add(resolve));
    }
  }

  #wake(): void {
    for (const waiter of this.#waiters) waiter();
    this.#waiters.clear();
  }
}

function environmentApiKey(environment: ProcessEnvironment): string | null {
  for (const requested of ["OPENAI_API_KEY", "CODEX_API_KEY"]) {
    for (const [name, value] of Object.entries(environment)) {
      if (name.toUpperCase() === requested && value) return value;
    }
  }
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function forwardAbort(
  source: AbortSignal | undefined,
  destination: AbortController | null,
): () => void {
  if (source === undefined || destination === null) return () => undefined;
  const abort = () => destination.abort(source.reason);
  if (source.aborted) abort();
  else source.addEventListener("abort", abort, { once: true });
  return () => source.removeEventListener("abort", abort);
}

async function waitForPromise<T>(
  promise: Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  if (signal === undefined) return await promise;
  if (signal.aborted) throw abortReason(signal);
  return await new Promise<T>((resolve, reject) => {
    const aborted = () => {
      signal.removeEventListener("abort", aborted);
      reject(abortReason(signal));
    };
    signal.addEventListener("abort", aborted, { once: true });
    void promise.then(
      (value) => {
        signal.removeEventListener("abort", aborted);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", aborted);
        reject(error);
      },
    );
  });
}

function requireOutputOutsideRepository(
  repository: string,
  outputDirectory: string,
): void {
  const outputRelative = relative(repository, outputDirectory);
  if (
    outputRelative === "" ||
    (outputRelative !== ".." &&
      !outputRelative.startsWith(`..${sep}`) &&
      !isAbsolute(outputRelative))
  ) {
    throw new OutputDirectoryError(
      `Scan output directory must be outside the repository: ${outputDirectory}`,
    );
  }
}

function abortReason(signal: AbortSignal): unknown {
  return (
    signal.reason ??
    new DOMException("The operation was aborted.", "AbortError")
  );
}

function throwIfAborted(signal?: AbortSignal, scanDir = ""): void {
  if (!signal?.aborted) return;
  const message = scanDir
    ? `Codex Security scan was interrupted; partial output remains at ${scanDir}.`
    : "Codex Security scan was interrupted during preparation.";
  throw new ScanInterruptedError(message, scanDir, { cause: signal.reason });
}

function definedEnvironment(
  environment: ProcessEnvironment,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(environment).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  );
}

function withoutApiKeys(
  environment: ProcessEnvironment,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(definedEnvironment(environment)).filter(
      ([name]) =>
        name.toUpperCase() !== "OPENAI_API_KEY" &&
        name.toUpperCase() !== "CODEX_API_KEY",
    ),
  );
}
