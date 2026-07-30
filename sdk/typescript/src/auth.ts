import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { isIP } from "node:net";
import { PluginBootstrapError } from "./errors.js";
import type { CodexCommand, ProcessEnvironment } from "./runtime.js";

const LOGIN_CHILD_TERMINATION_GRACE_MS = 1_000;
const MAX_CODEX_AUTH_OUTPUT_BYTES = 64 * 1024;
const LOGIN_OUTPUT_LIMIT_MESSAGE =
  "Codex login output exceeded the 64 KiB safety limit.";
const COMMAND_OUTPUT_LIMIT_MESSAGE =
  "Codex authentication command output exceeded the 64 KiB safety limit.";
const INSTRUCTION_TAIL_BYTES = 4 * 1024;
type TerminalEscapeState = "text" | "escape" | "csi" | "osc" | "osc-escape";

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
  #stdoutInstructionTail = "";
  #stderrInstructionTail = "";
  #stdoutTerminalState: TerminalEscapeState = "text";
  #stderrTerminalState: TerminalEscapeState = "text";
  #stdoutAuthUrl: string | null = null;
  #stderrAuthUrl: string | null = null;
  #stdoutUserCode: string | null = null;
  #stderrUserCode: string | null = null;
  #outputLimitExceeded = false;

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
      this.#recordOutput("stdout", chunk);
    });
    this.#child.stderr.on("data", (chunk: string) => {
      this.#recordOutput("stderr", chunk);
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
        if (!this.#outputLimitExceeded && !this.#canceled) {
          this.#flushInstructionTails();
        }
        const result = this.#outputLimitExceeded
          ? {
              success: false,
              exitCode,
              stdout: "",
              stderr: LOGIN_OUTPUT_LIMIT_MESSAGE,
            }
          : {
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
    this.#requestTermination();
  }

  #requestTermination(): void {
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

  #recordOutput(stream: "stdout" | "stderr", chunk: string): void {
    if (this.#outputLimitExceeded) return;
    const current = stream === "stdout" ? this.#stdout : this.#stderr;
    const appended = appendUtf8Tail(
      current,
      chunk,
      MAX_CODEX_AUTH_OUTPUT_BYTES,
    );
    if (stream === "stdout") {
      this.#stdout = appended.value;
    } else {
      this.#stderr = appended.value;
    }
    if (appended.exceeded) {
      this.#outputLimitExceeded = true;
      this.#stdout = "";
      this.#stderr = LOGIN_OUTPUT_LIMIT_MESSAGE;
      this.#requestTermination();
      return;
    }

    const tail =
      stream === "stdout"
        ? this.#stdoutInstructionTail
        : this.#stderrInstructionTail;
    const visible = visibleTerminalChunk(
      chunk,
      stream === "stdout"
        ? this.#stdoutTerminalState
        : this.#stderrTerminalState,
    );
    const candidate = `${tail}${visible.text}`;
    const lastDelimiter = Math.max(
      candidate.lastIndexOf("\n"),
      candidate.lastIndexOf("\r"),
    );
    const completed = candidate.slice(0, lastDelimiter + 1);
    const url = preferredAuthUrl(completed);
    const userCode = userCodeFromOutput(completed);
    const nextTail = appendUtf8Tail(
      "",
      candidate.slice(lastDelimiter + 1),
      INSTRUCTION_TAIL_BYTES,
    ).value;
    if (stream === "stdout") {
      this.#stdoutAuthUrl ??= url;
      this.#stdoutUserCode ??= userCode;
      this.#stdoutInstructionTail = nextTail;
      this.#stdoutTerminalState = visible.state;
    } else {
      this.#stderrAuthUrl ??= url;
      this.#stderrUserCode ??= userCode;
      this.#stderrInstructionTail = nextTail;
      this.#stderrTerminalState = visible.state;
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
  const recordOutput = (stream: "stdout" | "stderr", chunk: string): void => {
    if (processError !== null) return;
    const appended = appendUtf8Tail(
      stream === "stdout" ? stdout : stderr,
      chunk,
      MAX_CODEX_AUTH_OUTPUT_BYTES,
    );
    if (stream === "stdout") stdout = appended.value;
    else stderr = appended.value;
    if (!appended.exceeded) return;
    stdout = "";
    stderr = "";
    processError = new PluginBootstrapError(COMMAND_OUTPUT_LIMIT_MESSAGE);
    terminate();
  };
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    recordOutput("stdout", chunk);
  });
  child.stderr.on("data", (chunk: string) => {
    recordOutput("stderr", chunk);
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
    /https?:\/\/[^\s<>]+/g,
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

function appendUtf8Tail(
  current: string,
  chunk: string,
  maximumBytes: number,
): { value: string; exceeded: boolean } {
  const currentBytes = Buffer.from(current);
  const chunkBytes = Buffer.from(chunk);
  const exceeded = currentBytes.length + chunkBytes.length > maximumBytes;
  if (!exceeded) return { value: `${current}${chunk}`, exceeded: false };
  if (chunkBytes.length >= maximumBytes) {
    return {
      value: chunkBytes.subarray(chunkBytes.length - maximumBytes).toString(),
      exceeded: true,
    };
  }
  const retained = currentBytes.subarray(
    Math.max(0, currentBytes.length - (maximumBytes - chunkBytes.length)),
  );
  return {
    value: Buffer.concat([retained, chunkBytes]).toString(),
    exceeded: true,
  };
}

function plainTerminalText(value: string): string {
  return value
    .replace(/\u001b\][^\u0007]*(?:\u0007|\u001b\\)/g, "")
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\r/g, "");
}

function visibleTerminalChunk(
  value: string,
  initialState: TerminalEscapeState,
): { text: string; state: TerminalEscapeState } {
  let state = initialState;
  let text = "";
  for (const character of value) {
    if (state === "text") {
      if (character === "\u001b") {
        state = "escape";
      } else {
        text += character === "\r" ? "\n" : character;
      }
      continue;
    }
    if (state === "escape") {
      if (character === "[") {
        state = "csi";
      } else if (character === "]") {
        state = "osc";
      } else {
        text += `\u001b${character}`;
        state = "text";
      }
      continue;
    }
    if (state === "csi") {
      if (character >= "@" && character <= "~") state = "text";
      continue;
    }
    if (state === "osc") {
      if (character === "\u0007") state = "text";
      else if (character === "\u001b") state = "osc-escape";
      continue;
    }
    if (character === "\\" || character === "\u0007") state = "text";
    else if (character !== "\u001b") state = "osc";
  }
  return { text, state };
}
