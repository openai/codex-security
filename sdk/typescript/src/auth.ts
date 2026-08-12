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
  #stdout = "";
  #stderr = "";
  #stdoutInstructionTail = "";
  #stderrInstructionTail = "";
  #stdoutAuthUrl: string | null = null;
  #stderrAuthUrl: string | null = null;
  #stdoutUserCode: string | null = null;
  #stderrUserCode: string | null = null;

  public constructor(
    command: CodexCommand,
    args: readonly string[],
    environment: ProcessEnvironment,
    onSuccess: () => void | Promise<void>,
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
      this.#recordOutput("stdout", chunk);
    });
    this.#child.stderr.on("data", (chunk: string) => {
      this.#recordOutput("stderr", chunk);
    });
    this.#completion = new Promise((resolve, reject) => {
      this.#child.once("close", (exitCode) => {
        if (this.#forcedTermination !== undefined) {
          clearTimeout(this.#forcedTermination);
        }
        if (!this.#canceled) {
          this.#flushInstructionTails();
        }
        const result = {
          success: exitCode === 0 && !this.#canceled,
          exitCode,
          stdout: this.#stdout,
          stderr: this.#stderr,
        };
        this.#settleInstructionWaiters(result);
        if (result.success) {
          Promise.resolve(onSuccess()).then(() => resolve(result), reject);
        } else {
          resolve(result);
        }
      });
      this.#child.once("error", (error) => {
        if (this.#forcedTermination !== undefined) {
          clearTimeout(this.#forcedTermination);
        }
        this.#settleInstructionWaiters({
          success: false,
          exitCode: null,
          stdout: this.#stdout,
          stderr: error.message,
        });
        reject(error);
      });
    });
  }

  public get loginId(): null {
    return null;
  }

  public get authUrl(): string | null {
    return this.#stdoutAuthUrl ?? this.#stderrAuthUrl;
  }

  public get verificationUrl(): string | null {
    return this.authUrl;
  }

  public get userCode(): string | null {
    return this.#stdoutUserCode ?? this.#stderrUserCode;
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
    if (this.#child.exitCode !== null || this.#child.signalCode !== null)
      return;
    this.#child.kill("SIGTERM");
    if (this.#forcedTermination !== undefined) return;
    this.#forcedTermination = setTimeout(() => {
      if (this.#child.exitCode === null && this.#child.signalCode === null) {
        this.#child.kill("SIGKILL");
      }
    }, LOGIN_CHILD_TERMINATION_GRACE_MS);
  }

  #recordOutput(stream: "stdout" | "stderr", chunk: string): void {
    if (stream === "stdout") {
      this.#stdout += chunk;
    } else {
      this.#stderr += chunk;
    }

    const tail =
      stream === "stdout"
        ? this.#stdoutInstructionTail
        : this.#stderrInstructionTail;
    const output = `${tail}${chunk.replaceAll("\r", "\n")}`;
    const lastDelimiter = output.lastIndexOf("\n");
    const completed =
      lastDelimiter === -1 ? "" : output.slice(0, lastDelimiter + 1);
    const url = preferredAuthUrl(completed);
    const userCode = userCodeFromOutput(completed);
    const nextTail =
      lastDelimiter === -1 ? output : output.slice(lastDelimiter + 1);
    if (stream === "stdout") {
      this.#stdoutAuthUrl ??= url;
      this.#stdoutUserCode ??= userCode;
      this.#stdoutInstructionTail = nextTail;
    } else {
      this.#stderrAuthUrl ??= url;
      this.#stderrUserCode ??= userCode;
      this.#stderrInstructionTail = nextTail;
    }
    this.#notifyInstructions();
  }

  #flushInstructionTails(): void {
    this.#stdoutAuthUrl ??= preferredAuthUrl(this.#stdoutInstructionTail);
    this.#stdoutUserCode ??= userCodeFromOutput(this.#stdoutInstructionTail);
    this.#stderrAuthUrl ??= preferredAuthUrl(this.#stderrInstructionTail);
    this.#stderrUserCode ??= userCodeFromOutput(this.#stderrInstructionTail);
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
  let processError: Error | null = null;
  let forcedTermination: ReturnType<typeof setTimeout> | undefined;
  const terminate = (): void => {
    if (child.exitCode !== null || child.signalCode !== null) {
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
      return;
    }
    child.kill("SIGTERM");
    if (forcedTermination !== undefined) return;
    forcedTermination = setTimeout(() => {
      forcedTermination = undefined;
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
      }
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
    }, LOGIN_CHILD_TERMINATION_GRACE_MS);
  };
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const completion = new Promise<LoginResult>((resolve, reject) => {
    child.once("error", (error) => {
      processError ??= error;
      terminate();
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
      if (forcedTermination !== undefined) clearTimeout(forcedTermination);
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
  for (const match of plainTerminalText(value).matchAll(
    /https?:\/\/[^\s<>"']+/g,
  )) {
    const url = match[0].replace(/[.,;:!?)\]}]+$/, "");
    try {
      const hostname = new URL(url).hostname.toLowerCase().replace(/\.$/, "");
      if (
        hostname !== "localhost" &&
        !hostname.endsWith(".localhost") &&
        !(isIP(hostname) === 4 && hostname.startsWith("127.")) &&
        hostname !== "0.0.0.0" &&
        hostname !== "[::1]" &&
        hostname !== "[::]" &&
        hostname !== "[::ffff:0:0]" &&
        !hostname.startsWith("[::ffff:7f") &&
        !hostname.startsWith("[::7f")
      ) {
        return url;
      }
    } catch {
      continue;
    }
  }
  return null;
}

function userCodeFromOutput(value: string): string | null {
  const output = plainTerminalText(value);
  return (
    output.match(/(?:code|user code)\s*[:=]\s*([A-Z0-9-]{4,})/i)?.[1] ??
    output.match(/\b[A-Z0-9]{4,}(?:-[A-Z0-9]{4,})+\b/)?.[0] ??
    null
  );
}

function plainTerminalText(value: string): string {
  return value
    .replace(/\u001b\][^\u0007]*(?:\u0007|\u001b\\)/g, "")
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\r/g, "");
}
