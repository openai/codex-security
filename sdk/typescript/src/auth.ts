import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { isIP } from "node:net";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { parse } from "smol-toml";
import type { JsonObject } from "./config.js";
import { CodexSecurityError, PluginBootstrapError } from "./errors.js";
import {
  executablePathForSpawn,
  expandHome,
  runCodexCommand,
  type CodexCommand,
  type ProcessEnvironment,
} from "./runtime.js";

const LOGIN_CHILD_TERMINATION_GRACE_MS = 1_000;

/** @internal */
export function environmentEntry(
  environment: ProcessEnvironment,
  requested: string,
): string | undefined {
  const exact = environment[requested];
  if (exact !== undefined || process.platform !== "win32") return exact;
  const upper = requested.toUpperCase();
  return Object.entries(environment).find(
    ([name]) => name.toUpperCase() === upper,
  )?.[1];
}

/** @internal */
export function configuredCodexHome(environment: ProcessEnvironment): string {
  return resolve(
    expandHome(
      environmentEntry(environment, "CODEX_HOME")?.trim() ||
        join(homedir(), ".codex"),
      environment,
    ),
  );
}

/** @internal */
export async function readCodexHomeConfig(
  environment: ProcessEnvironment,
  signal?: AbortSignal,
): Promise<JsonObject> {
  try {
    return parse(
      await readFile(join(configuredCodexHome(environment), "config.toml"), {
        encoding: "utf8",
        signal,
      }),
    ) as JsonObject;
  } catch (error) {
    signal?.throwIfAborted();
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw new CodexSecurityError(
      "Could not read the configured Codex provider.",
    );
  }
}

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
  readonly #urlReady = Promise.withResolvers<void>();
  readonly #deviceReady = Promise.withResolvers<void>();
  #canceled = false;
  #forcedTermination: ReturnType<typeof setTimeout> | undefined;
  readonly #output = { stdout: "", stderr: "" };
  readonly #tails = { stdout: "", stderr: "" };
  readonly #urls: Record<"stdout" | "stderr", string | null> = {
    stdout: null,
    stderr: null,
  };
  readonly #codes: Record<"stdout" | "stderr", string | null> = {
    stdout: null,
    stderr: null,
  };

  public constructor(
    command: CodexCommand,
    args: readonly string[],
    environment: ProcessEnvironment,
    onSuccess: () => void | Promise<void>,
  ) {
    void this.#urlReady.promise.catch(() => undefined);
    void this.#deviceReady.promise.catch(() => undefined);
    this.#child = spawn(executablePathForSpawn(command.command), [...args], {
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
        clearTimeout(this.#forcedTermination);
        if (!this.#canceled) {
          this.#flushInstructionTails();
        }
        const result = {
          success: exitCode === 0 && !this.#canceled,
          exitCode,
          ...this.#output,
        };
        this.#settleInstructionWaiters(result);
        if (result.success) {
          Promise.resolve(onSuccess()).then(() => resolve(result), reject);
        } else {
          resolve(result);
        }
      });
      this.#child.once("error", (error) => {
        clearTimeout(this.#forcedTermination);
        this.#settleInstructionWaiters({
          success: false,
          exitCode: null,
          stdout: this.#output.stdout,
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
    return this.#urls.stdout ?? this.#urls.stderr;
  }

  public get verificationUrl(): string | null {
    return this.authUrl;
  }

  public get userCode(): string | null {
    return this.#codes.stdout ?? this.#codes.stderr;
  }

  public async wait(): Promise<LoginResult> {
    return await this.#completion;
  }

  public async waitForInstructions(
    options: { deviceCode?: boolean } = {},
  ): Promise<void> {
    await (options.deviceCode === true ? this.#deviceReady : this.#urlReady)
      .promise;
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
      this.#child.stdin.destroy();
      this.#child.stdout.destroy();
      this.#child.stderr.destroy();
    }, LOGIN_CHILD_TERMINATION_GRACE_MS);
  }

  #recordOutput(stream: "stdout" | "stderr", chunk: string): void {
    this.#output[stream] += chunk;
    const output = `${this.#tails[stream]}${chunk.replaceAll("\r", "\n")}`;
    const lastDelimiter = output.lastIndexOf("\n");
    const completed =
      lastDelimiter === -1 ? "" : output.slice(0, lastDelimiter + 1);
    this.#urls[stream] ??= preferredAuthUrl(completed);
    this.#codes[stream] ??= userCodeFromOutput(completed);
    this.#tails[stream] =
      lastDelimiter === -1 ? output : output.slice(lastDelimiter + 1);
    this.#notifyInstructions();
  }

  #flushInstructionTails(): void {
    for (const stream of ["stdout", "stderr"] as const) {
      this.#urls[stream] ??= preferredAuthUrl(this.#tails[stream]);
      this.#codes[stream] ??= userCodeFromOutput(this.#tails[stream]);
    }
  }

  #notifyInstructions(): void {
    if (this.authUrl !== null) this.#urlReady.resolve();
    if (this.verificationUrl !== null && this.userCode !== null)
      this.#deviceReady.resolve();
  }

  #settleInstructionWaiters(result: LoginResult): void {
    this.#notifyInstructions();
    if (result.success) {
      this.#urlReady.resolve();
      this.#deviceReady.resolve();
      return;
    }
    const error = new PluginBootstrapError(
      this.#canceled
        ? "Codex login was canceled."
        : `Codex login exited before authentication instructions were available: ${result.stderr.trim() || result.stdout.trim() || result.exitCode || "unknown error"}`,
    );
    this.#urlReady.reject(error);
    this.#deviceReady.reject(error);
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
  return await runCodexCommand(
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
  const result = await runCodexCommand(
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
  const result = await runCodexCommand(
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
