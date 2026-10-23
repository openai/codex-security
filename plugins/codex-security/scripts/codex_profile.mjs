import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, win32 } from "node:path";
import { createInterface } from "node:readline";

// Native startup needs provider identity and auth selection, while exec reads
// the full provider configuration from its private profile file.
export function preflightProviderDefinitions(providers) {
  return Object.fromEntries(
    Object.entries(providers)
      .filter(([, provider]) => provider != null)
      .map(([id, provider]) => [
        id,
        Object.fromEntries(
          ["name", "wire_api", "requires_openai_auth"]
            .filter((key) => Object.hasOwn(provider, key))
            .map((key) => [key, provider[key]]),
        ),
      ]),
  );
}

export function isPermissionProfileFallbackWarning(message, profileId) {
  if (typeof message !== "string") return false;
  const prefix =
    "Configured value for `permission_profile` is disallowed by requirements; " +
    `falling back from \`${profileId}\` to required value \``;
  const warning = message.trim();
  return warning.startsWith(prefix) && warning.endsWith("`.");
}

export function profileConfigOverrides(config) {
  return Object.entries(config)
    .filter(([, value]) => value != null)
    .map(([key, value]) => `${key}=${toml(value)}`);
}

/** Read native configuration origins and ordered layers without starting a thread. */
export async function readCodexRuntimeConfigWithOrigins(options) {
  const abortError = () =>
    options.signal.reason instanceof Error
      ? options.signal.reason
      : new DOMException("Codex configuration read aborted.", "AbortError");
  if (options.signal.aborted) throw abortError();
  const args = [...(options.appServerArgs ?? options.commandArgs ?? [])];
  if (options.appServerArgs === undefined) {
    for (const override of [
      ...options.configOverrides,
      ...(options.providerConfigOverrides ?? []),
    ])
      args.push("--config", override);
    args.push("app-server", "--stdio");
  }
  let executable = options.codexPath;
  if (process.platform === "win32" && win32.isAbsolute(executable)) {
    const root = win32.parse(executable).root;
    if (root !== "\\" && root !== "/")
      executable = win32.toNamespacedPath(executable);
  }
  const child = spawn(executable, args, {
    cwd: options.cwd,
    ...(options.env === undefined ? {} : { env: options.env }),
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const stderr = [];
  let pending;
  let nextId = 1;
  let failure;
  let closing = false;
  let closed = false;
  const fail = (error) => {
    failure ??= error;
    pending?.reject(failure);
    pending = undefined;
  };
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  child.on("error", fail);
  child.stdin.on("error", fail);
  lines.on("error", fail);
  const childClose = new Promise((resolve) => {
    child.once("close", (code, signal) => {
      closed = true;
      if (!closing)
        fail(
          new Error(
            `Codex ${JSON.stringify(options.codexPath)} exited before configuration read completed (${signal ? `signal ${signal}` : `code ${code}`}).`,
          ),
        );
      resolve();
    });
  });
  const malformed = () =>
    new Error("Codex returned a malformed configuration-read response.");
  lines.on("line", (line) => {
    if (failure || !line.trim()) return;
    try {
      const message = JSON.parse(line);
      if (!isRecord(message)) throw malformed();
      // Ignore notifications and server requests; this client only reads configuration.
      if (typeof message.id !== "number") return;
      if (!pending || message.id !== pending.id) throw malformed();
      if (message.error !== undefined) {
        const detail = isRecord(message.error) ? message.error : {};
        throw new Error(
          `Codex returned an error for ${JSON.stringify(pending.method)}${typeof detail.code === "number" ? ` (${detail.code})` : ""}.${typeof detail.message === "string" ? `\n${detail.message}` : ""}`,
          { cause: message.error },
        );
      }
      if (!isRecord(message.result)) throw malformed();
      pending.resolve(message.result);
      pending = undefined;
    } catch (error) {
      fail(error);
    }
  });
  const write = (message) => {
    if (!child.stdin.writable) {
      fail(
        new Error("Codex could not exchange app-server JSON-RPC over stdio."),
      );
      return;
    }
    child.stdin.write(`${JSON.stringify(message)}\n`, (error) => {
      if (error) fail(error);
    });
  };
  const request = (method, params) => {
    if (failure) return Promise.reject(failure);
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending = { id, method, resolve, reject };
      write({ jsonrpc: "2.0", id, method, params });
    });
  };
  const stop = () => {
    lines.close();
    if (!child.stdin.destroyed) child.stdin.end();
    if (child.exitCode === null && child.signalCode === null)
      child.kill("SIGTERM");
  };
  const onAbort = () => {
    fail(abortError());
    stop();
  };
  options.signal.addEventListener("abort", onAbort, { once: true });
  const close = async () => {
    closing = true;
    options.signal.removeEventListener("abort", onAbort);
    stop();
    if (closed) return;
    const forcedTermination = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null)
        child.kill("SIGKILL");
      // Descendants may retain the pipes after the app-server process exits.
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
    }, 1_000);
    try {
      await childClose;
    } finally {
      clearTimeout(forcedTermination);
    }
  };
  try {
    await request("initialize", {
      clientInfo: {
        name: "codex-security",
        title: "Codex Security",
        version: options.clientVersion,
      },
      capabilities: { experimentalApi: true },
    });
    if (failure) throw failure;
    write({ jsonrpc: "2.0", method: "initialized", params: {} });
    return await request("config/read", {
      cwd: options.cwd,
      includeLayers: true,
    });
  } catch (error) {
    await close();
    const diagnostic = Buffer.concat(stderr).toString("utf8");
    if (error instanceof Error && diagnostic)
      error.message += `\n${diagnostic}`;
    throw error;
  } finally {
    await close();
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// Native profile files keep provider configuration off process arguments while
// retaining the existing CODEX_HOME credential store.
export function createCodexProfileClient(options) {
  return {
    startThread: (threadOptions = {}) =>
      new ProfileThread(options, threadOptions),
    resumeThread: (id, threadOptions = {}) =>
      new ProfileThread(options, threadOptions, id),
  };
}

class ProfileThread {
  constructor(options, threadOptions, id = null) {
    this.options = options;
    this.threadOptions = threadOptions;
    this.id = id;
  }

  async runStreamed(input, turnOptions = {}) {
    return { events: this.events(input, turnOptions) };
  }

  async run(input, turnOptions = {}) {
    const items = [];
    let finalResponse = "";
    let usage = null;
    for await (const event of this.events(input, turnOptions)) {
      if (event.type === "item.completed") {
        items.push(event.item);
        if (event.item.type === "agent_message")
          finalResponse = event.item.text;
      } else if (event.type === "turn.completed") {
        usage = event.usage;
      } else if (event.type === "turn.failed") {
        throw new Error(event.error.message);
      }
    }
    return { items, finalResponse, usage };
  }

  async *events(input, turnOptions) {
    let schemaDirectory;
    try {
      let schemaPath;
      if (turnOptions.outputSchema !== undefined) {
        const schema = turnOptions.outputSchema;
        if (
          schema === null ||
          typeof schema !== "object" ||
          Array.isArray(schema)
        ) {
          throw new Error("outputSchema must be a plain JSON object");
        }
        schemaDirectory = await mkdtemp(join(tmpdir(), "codex-output-schema-"));
        schemaPath = join(schemaDirectory, "schema.json");
        await writeFile(schemaPath, JSON.stringify(schema), "utf8");
      }
      const args = nativeArguments(
        this.options,
        this.threadOptions,
        this.id,
        turnOptions,
        schemaPath,
      );
      for await (const line of execute(
        this.options,
        args,
        input,
        turnOptions.signal,
      )) {
        let event;
        try {
          event = JSON.parse(line);
        } catch (cause) {
          throw new Error(`Failed to parse item: ${line}`, { cause });
        }
        const item = event.type === "item.completed" ? event.item : event;
        if (
          this.options.requestedPermissionProfile !== undefined &&
          item.type === "error" &&
          isPermissionProfileFallbackWarning(
            item.message,
            this.options.requestedPermissionProfile,
          )
        ) {
          throw new Error(
            "Read-only Codex helper stopped because organization policy changed its permission profile. Its results were discarded.\n" +
              item.message,
          );
        }
        if (event.type === "thread.started") this.id = event.thread_id;
        if (event.type === "turn.completed" && event.usage != null)
          event.usage.cache_write_input_tokens ??= 0;
        yield event;
      }
    } finally {
      if (schemaDirectory) {
        await rm(schemaDirectory, { recursive: true, force: true }).catch(
          () => {},
        );
      }
    }
  }
}

function nativeArguments(options, thread, id, turn, schemaPath) {
  const args = [
    "exec",
    "--experimental-json",
    "--profile",
    options.profileName,
  ];
  const config = (key, value) => args.push("--config", `${key}=${toml(value)}`);
  for (const override of profileConfigOverrides(options.config ?? {}))
    args.push("--config", override);
  for (const override of options.configOverrides ?? [])
    args.push("--config", override);
  if (options.baseUrl) config("openai_base_url", options.baseUrl);
  if (thread.model) args.push("--model", thread.model);
  if (thread.threadSource !== undefined && !id)
    args.push("--thread-source", thread.threadSource);
  if (thread.sandboxMode) args.push("--sandbox", thread.sandboxMode);
  if (thread.workingDirectory) args.push("--cd", thread.workingDirectory);
  for (const directory of thread.additionalDirectories ?? [])
    args.push("--add-dir", directory);
  if (thread.skipGitRepoCheck) args.push("--skip-git-repo-check");
  if (schemaPath) args.push("--output-schema", schemaPath);
  if (turn.cyberAccessProgram !== undefined)
    args.push("--cyber-access-program", turn.cyberAccessProgram);
  if (thread.modelReasoningEffort)
    config("model_reasoning_effort", thread.modelReasoningEffort);
  if (thread.networkAccessEnabled !== undefined)
    config(
      "sandbox_workspace_write.network_access",
      thread.networkAccessEnabled,
    );
  if (thread.webSearchMode) config("web_search", thread.webSearchMode);
  else if (thread.webSearchEnabled !== undefined)
    config("web_search", thread.webSearchEnabled ? "live" : "disabled");
  if (thread.approvalPolicy) config("approval_policy", thread.approvalPolicy);
  if (id) args.push("resume", id);
  return args;
}

function toml(value) {
  if (typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value).replace(/\u007f/g, "\\u007f");
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(toml).join(", ")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .filter(([, child]) => child != null)
      .map(
        ([key, child]) =>
          `${/^[A-Za-z0-9_-]+$/.test(key) ? key : toml(key)} = ${toml(child)}`,
      )
      .join(", ")}}`;
  }
  throw new Error("Codex config overrides must contain finite TOML values");
}

async function* execute(options, args, input, signal) {
  const env = { ...(options.env ?? process.env) };
  env.CODEX_INTERNAL_ORIGINATOR_OVERRIDE ||= "codex_sdk_ts";
  if (options.apiKey) env.CODEX_API_KEY = options.apiKey;
  const child = spawn(options.codexPathOverride, args, {
    env,
    signal,
    windowsHide: true,
  });
  let processError;
  let inputError;
  child.on("error", (error) => {
    processError = error;
  });
  child.stdin.on("error", (error) => {
    inputError = error;
  });
  const closed = new Promise((resolve) => {
    child.once("close", (code, exitSignal) => resolve({ code, exitSignal }));
  });
  const stderr = [];
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  child.stdin.end(input);
  try {
    for await (const line of lines) yield line;
    const { code, exitSignal } = await closed;
    if (processError) throw processError;
    if (code !== 0 || exitSignal) {
      const detail = exitSignal ? `signal ${exitSignal}` : `code ${code ?? 1}`;
      throw new Error(
        `Codex Exec exited with ${detail}: ${Buffer.concat(stderr).toString("utf8")}`,
      );
    }
    if (inputError) throw inputError;
  } finally {
    lines.close();
    if (child.exitCode === null && child.signalCode === null) child.kill();
  }
}
