import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface, type Interface } from "node:readline";
import { executablePathForSpawn } from "./executable-path.js";
import { MCP_APP_VERSION } from "./version.js";

export interface AppServerClientOptions {
  readonly codexPath: string;
  /** Startup cwd also selects authentication and managed configuration. */
  readonly cwd: string;
  readonly configOverrides: readonly string[];
  /** A caller-supplied snapshot; omit to inherit the current environment. */
  readonly env?: Readonly<Record<string, string>>;
  readonly signal: AbortSignal;
}

type JsonRecord = Record<string, unknown>;

type AppServerFailure =
  | { readonly kind: "protocol" | "stdio" }
  | { readonly kind: "start"; readonly error: Error }
  | {
      readonly kind: "exit";
      readonly code: number | null;
      readonly signal: NodeJS.Signals | null;
    }
  | {
      readonly kind: "rpc";
      readonly method: string;
      readonly code: number | undefined;
    };

/** Transport details let each caller retain its own error handling and messages. */
export class AppServerError extends Error {
  constructor(readonly failure: AppServerFailure) {
    super(appServerFailureMessage(failure));
    this.name = "AppServerError";
  }
}

type PendingRequest = {
  readonly id: number;
  readonly method: string;
  readonly resolve: (message: JsonRecord) => void;
  readonly reject: (error: Error) => void;
};

/** A short-lived connection for sequential RPCs without starting a turn. */
export class AppServerClient {
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly childClose: Promise<void>;
  private readonly stdoutLines: Interface;
  private pending: PendingRequest | undefined;
  private nextId = 1;
  private terminalError: Error | undefined;
  private closed = false;
  private childClosed = false;
  private readonly removeAbortListener: () => void;

  constructor(options: AppServerClientOptions) {
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
    // cannot block, but never retain or surface it in client errors.
    this.child.stderr.resume();
    this.stdoutLines = createInterface({
      input: this.child.stdout,
      crlfDelay: Infinity,
    });
    this.stdoutLines.on("line", (line) => this.consumeStdoutLine(line));
    this.stdoutLines.on("error", () => {
      this.fail(new AppServerError({ kind: "stdio" }));
    });
    this.child.stdin.on("error", () => {
      this.fail(new AppServerError({ kind: "stdio" }));
    });
    this.child.on("error", (error) => {
      this.fail(new AppServerError({ kind: "start", error }));
    });
    this.child.on("exit", (code, signal) => {
      if (!this.closed) {
        this.fail(new AppServerError({ kind: "exit", code, signal }));
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

  async initialize(clientInfo: {
    name: string;
    title?: string;
  }): Promise<void> {
    await this.request("initialize", {
      clientInfo: {
        ...clientInfo,
        version: MCP_APP_VERSION,
      },
      capabilities: { experimentalApi: true },
    });
    this.notify("initialized", {});
  }

  request(method: string, params?: JsonRecord): Promise<JsonRecord> {
    if (this.terminalError) return Promise.reject(this.terminalError);
    const id = this.nextId++;
    return new Promise<JsonRecord>((resolve, reject) => {
      // Callers await each request before sending the next.
      this.pending = { id, method, resolve, reject };
      this.write({
        jsonrpc: "2.0",
        id,
        method,
        ...(params === undefined ? {} : { params }),
      });
    });
  }

  notify(method: string, params: JsonRecord): void {
    if (this.terminalError) throw this.terminalError;
    this.write({ jsonrpc: "2.0", method, params });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.removeAbortListener();
    this.pending?.reject(
      this.terminalError ?? new AppServerError({ kind: "stdio" }),
    );
    this.pending = undefined;
    this.stopChild();
    if (this.childClosed) return;
    await this.childClose;
  }

  private write(message: JsonRecord): void {
    if (!this.child.stdin.writable) {
      this.fail(new AppServerError({ kind: "stdio" }));
      return;
    }
    this.child.stdin.write(`${JSON.stringify(message)}\n`, (error) => {
      if (error) this.fail(new AppServerError({ kind: "stdio" }));
    });
  }

  private consumeStdoutLine(line: string): void {
    if (this.terminalError || line.trim().length === 0) return;
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      this.fail(new AppServerError({ kind: "protocol" }));
      return;
    }
    const message = record(value);
    if (!message) {
      this.fail(new AppServerError({ kind: "protocol" }));
      return;
    }
    this.handleMessage(message);
  }

  private handleMessage(message: JsonRecord): void {
    const id = message.id;
    if (typeof id !== "number") {
      // Notifications and server-initiated requests are irrelevant to this
      // no-turn client. We never answer them or start a turn.
      return;
    }
    const pending = this.pending;
    if (!pending || pending.id !== id) {
      this.fail(new AppServerError({ kind: "protocol" }));
      return;
    }
    this.pending = undefined;
    if (message.error !== undefined) {
      pending.reject(
        new AppServerError({
          kind: "rpc",
          method: pending.method,
          code: jsonRpcErrorCode(message.error),
        }),
      );
      return;
    }
    const result = record(message.result);
    if (!result) {
      pending.reject(new AppServerError({ kind: "protocol" }));
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

function record(value: unknown): JsonRecord | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonRecord)
    : undefined;
}

function jsonRpcErrorCode(value: unknown): number | undefined {
  const error = record(value);
  return typeof error?.code === "number" && Number.isFinite(error.code)
    ? error.code
    : undefined;
}

function appServerFailureMessage(failure: AppServerFailure): string {
  switch (failure.kind) {
    case "start":
      return "The selected Codex app-server could not start.";
    case "exit":
      return "Codex app-server exited before the request completed.";
    case "stdio":
      return "Could not exchange Codex app-server JSON-RPC over stdio.";
    case "protocol":
      return "Codex app-server returned a malformed response.";
    case "rpc": {
      const code =
        failure.code === undefined ? "" : ` (JSON-RPC code ${failure.code})`;
      return `Codex app-server returned an error for ${JSON.stringify(failure.method)}${code}.`;
    }
  }
}

function abortError(reason: unknown): Error {
  if (reason instanceof Error) return reason;
  return new DOMException("Codex app-server request aborted.", "AbortError");
}
