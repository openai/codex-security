import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { isIP } from "node:net";
import { PluginBootstrapError } from "./errors.js";
import type { CodexCommand, ProcessEnvironment } from "./runtime.js";

const LOGIN_CHILD_TERMINATION_GRACE_MS = 1_000;

export interface LoginResult {
  success: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

export interface AccountStatus {
  authenticated: boolean;
  details: string;
}

export class CodexLoginHandle {
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #completion: Promise<LoginResult>;
  readonly #urlReady: Promise<void>;
  readonly #deviceReady: Promise<void>;
  #resolveUrlReady!: () => void;
  #rejectUrlReady!: (error: unknown) => void;
  #resolveDeviceReady!: () => void;
  #rejectDeviceReady!: (error: unknown) => void;
  #urlReadySettled = false;
  #deviceReadySettled = false;
  #canceled = false;
  #forcedTermination: ReturnType<typeof setTimeout> | undefined;
  #forceCompletion: (() => void) | null = null;
  #stdout = "";
  #stderr = "";

  public constructor(
    command: CodexCommand,
    args: readonly string[],
    environment: ProcessEnvironment,
    onSuccess: () => void,
  ) {
    this.#urlReady = new Promise<void>((resolve, reject) => {
      this.#resolveUrlReady = resolve;
      this.#rejectUrlReady = reject;
    });
    this.#deviceReady = new Promise<void>((resolve, reject) => {
      this.#resolveDeviceReady = resolve;
      this.#rejectDeviceReady = reject;
    });
    void this.#urlReady.catch(() => undefined);
    void this.#deviceReady.catch(() => undefined);
    this.#child = spawn(command.command, [...command.prefixArgs, ...args], {
      env: environment,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    this.#child.stdin.end();
    this.#child.stdout.setEncoding("utf8");
    this.#child.stderr.setEncoding("utf8");
    this.#child.stdout.on("data", (chunk: string) => {
      this.#stdout += chunk;
      this.#notifyInstructions();
    });
    this.#child.stderr.on("data", (chunk: string) => {
      this.#stderr += chunk;
      this.#notifyInstructions();
    });
    this.#completion = new Promise((resolve, reject) => {
      let fallback: ReturnType<typeof setTimeout> | undefined;
      let completed = false;
      const complete = (exitCode: number | null): void => {
        if (completed) return;
        completed = true;
        if (fallback !== undefined) clearTimeout(fallback);
        this.#clearForcedTermination();
        this.#forceCompletion = null;
        this.#destroyPipes();
        const result = {
          success: exitCode === 0 && !this.#canceled,
          exitCode,
          stdout: this.#stdout,
          stderr: this.#stderr,
        };
        this.#settleInstructionWaiters(result);
        if (result.success) onSuccess();
        resolve(result);
      };
      this.#forceCompletion = () => complete(this.#child.exitCode);
      this.#child.once("error", (error) => {
        if (completed) return;
        completed = true;
        if (fallback !== undefined) clearTimeout(fallback);
        this.#clearForcedTermination();
        this.#forceCompletion = null;
        this.#destroyPipes();
        this.#settleInstructionWaiters({
          success: false,
          exitCode: null,
          stdout: this.#stdout,
          stderr: error.message,
        });
        reject(error);
      });
      this.#child.once("close", complete);
      this.#child.once("exit", (exitCode) => {
        fallback = setTimeout(() => {
          this.#destroyPipes();
          complete(exitCode);
        }, LOGIN_CHILD_TERMINATION_GRACE_MS);
      });
    });
  }

  public get loginId(): null {
    return null;
  }

  public get authUrl(): string | null {
    return preferredAuthUrl(`${this.#stdout}\n${this.#stderr}`);
  }

  public get verificationUrl(): string | null {
    return this.authUrl;
  }

  public get userCode(): string | null {
    const output = plainTerminalText(`${this.#stdout}\n${this.#stderr}`);
    return (
      output.match(/(?:code|user code)\s*[:=]\s*([A-Z0-9-]{4,})/i)?.[1] ??
      output.match(/\b[A-Z0-9]{4,}(?:-[A-Z0-9]{4,})+\b/)?.[0] ??
      null
    );
  }

  public async wait(): Promise<LoginResult> {
    return await this.#completion;
  }

  public async waitForInstructions(
    options: { deviceCode?: boolean } = {},
  ): Promise<void> {
    await (options.deviceCode === true ? this.#deviceReady : this.#urlReady);
  }

  public cancel(): void {
    this.#canceled = true;
    if (
      this.#child.exitCode !== null ||
      this.#child.signalCode !== null ||
      this.#forceCompletion === null
    ) {
      this.#destroyPipes();
      this.#forceCompletion?.();
      return;
    }
    this.#child.kill("SIGTERM");
    if (this.#forcedTermination !== undefined) return;
    this.#forcedTermination = setTimeout(() => {
      this.#forcedTermination = undefined;
      if (this.#child.exitCode === null && this.#child.signalCode === null) {
        this.#child.kill("SIGKILL");
      }
      this.#destroyPipes();
      this.#forceCompletion?.();
    }, LOGIN_CHILD_TERMINATION_GRACE_MS);
  }

  #clearForcedTermination(): void {
    if (this.#forcedTermination === undefined) return;
    clearTimeout(this.#forcedTermination);
    this.#forcedTermination = undefined;
  }

  #destroyPipes(): void {
    this.#child.stdin.destroy();
    this.#child.stdout.destroy();
    this.#child.stderr.destroy();
  }

  #notifyInstructions(): void {
    if (!this.#urlReadySettled && this.authUrl !== null) {
      this.#urlReadySettled = true;
      this.#resolveUrlReady();
    }
    if (
      !this.#deviceReadySettled &&
      this.verificationUrl !== null &&
      this.userCode !== null
    ) {
      this.#deviceReadySettled = true;
      this.#resolveDeviceReady();
    }
  }

  #settleInstructionWaiters(result: LoginResult): void {
    this.#notifyInstructions();
    if (result.success) {
      if (!this.#urlReadySettled) {
        this.#urlReadySettled = true;
        this.#resolveUrlReady();
      }
      if (!this.#deviceReadySettled) {
        this.#deviceReadySettled = true;
        this.#resolveDeviceReady();
      }
      return;
    }
    const error = new PluginBootstrapError(
      this.#canceled
        ? "Codex login was canceled."
        : `Codex login exited before authentication instructions were available: ${result.stderr.trim() || result.stdout.trim() || result.exitCode || "unknown error"}`,
    );
    if (!this.#urlReadySettled) {
      this.#urlReadySettled = true;
      this.#rejectUrlReady(error);
    }
    if (!this.#deviceReadySettled) {
      this.#deviceReadySettled = true;
      this.#rejectDeviceReady(error);
    }
  }
}

export async function loginApiKey(
  command: CodexCommand,
  environment: ProcessEnvironment,
  apiKey: string,
  signal?: AbortSignal,
): Promise<LoginResult> {
  if (apiKey.trim().length === 0) {
    throw new PluginBootstrapError("The API key must be non-empty.");
  }
  return await runCodex(
    command,
    ["login", "--with-api-key"],
    environment,
    `${apiKey}\n`,
    signal,
  );
}

export async function accountStatus(
  command: CodexCommand,
  environment: ProcessEnvironment,
  signal?: AbortSignal,
): Promise<AccountStatus> {
  const result = await runCodex(
    command,
    ["login", "status"],
    environment,
    undefined,
    signal,
  );
  const details = [result.stdout.trim(), result.stderr.trim()]
    .filter(Boolean)
    .join("\n");
  return {
    authenticated:
      result.exitCode === 0 && !/not logged in|unauthenticated/i.test(details),
    details,
  };
}

export async function logout(
  command: CodexCommand,
  environment: ProcessEnvironment,
  signal?: AbortSignal,
): Promise<void> {
  const result = await runCodex(
    command,
    ["logout"],
    environment,
    undefined,
    signal,
  );
  if (!result.success) {
    throw new PluginBootstrapError(
      `Codex logout failed: ${result.stderr.trim() || result.stdout.trim() || "unknown error"}`,
    );
  }
}

export async function runCodex(
  command: CodexCommand,
  args: readonly string[],
  environment: ProcessEnvironment,
  input?: string,
  signal?: AbortSignal,
): Promise<LoginResult> {
  const child = spawn(command.command, [...command.prefixArgs, ...args], {
    env: environment,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
    signal,
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const completion = new Promise<LoginResult>((resolve, reject) => {
    let processError: Error | null = null;
    child.once("error", (error) => {
      processError = error;
    });
    child.stdin.on("error", (error: NodeJS.ErrnoException) => {
      // A short-lived command can close stdin before Node flushes the input.
      // Its exit status remains authoritative; the stream error must not escape
      // as an uncaught exception.
      if (
        error.code !== "EPIPE" &&
        error.code !== "ECONNRESET" &&
        error.code !== "EOF" &&
        error.code !== "ERR_STREAM_DESTROYED"
      ) {
        processError ??= error;
      }
    });
    child.once("close", (exitCode) => {
      if (processError !== null) {
        reject(processError);
      } else {
        resolve({ success: exitCode === 0, exitCode, stdout, stderr });
      }
    });
  });
  child.stdin.end(input);
  return await completion;
}

function preferredAuthUrl(value: string): string | null {
  const urls = [
    ...plainTerminalText(value).matchAll(/https?:\/\/[^\s<>]+/g),
  ].map((match) => match[0].replace(/[.,;:!?)\]}]+$/, ""));
  return (
    urls.find((url) => {
      try {
        const hostname = new URL(url).hostname.toLowerCase().replace(/\.$/, "");
        return (
          hostname !== "localhost" &&
          !hostname.endsWith(".localhost") &&
          !(isIP(hostname) === 4 && hostname.startsWith("127.")) &&
          hostname !== "0.0.0.0" &&
          hostname !== "[::1]" &&
          hostname !== "[::]" &&
          hostname !== "[::ffff:0:0]" &&
          !hostname.startsWith("[::ffff:7f") &&
          !hostname.startsWith("[::7f")
        );
      } catch {
        return false;
      }
    }) ?? null
  );
}

function plainTerminalText(value: string): string {
  return value
    .replace(/\u001b\][^\u0007]*(?:\u0007|\u001b\\)/g, "")
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\r/g, "");
}
