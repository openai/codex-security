import { spawn, type ChildProcess } from "node:child_process";
import { win32 } from "node:path";
import type { ToolAnnotations } from "@modelcontextprotocol/server";

const readLocal = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};
const readRemote = { ...readLocal, openWorldHint: true };
const writeLocal = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: false,
};
const writeRemote = { ...writeLocal, openWorldHint: true };

// This is the supported MCP surface; new CLI commands stay CLI-only until added here.
const commandAnnotations: Record<string, ToolAnnotations> = {
  "bulk-scan": writeRemote,
  export: writeLocal,
  "findings false-positive": writeLocal,
  "findings list": readLocal,
  "import github": readRemote,
  "install-hook": writeLocal,
  login: readLocal,
  logout: writeLocal,
  patch: writeRemote,
  "publish check": readRemote,
  "publish scan": writeRemote,
  "scan-components": writeRemote,
  "scans compare": writeRemote,
  "scans list": readLocal,
  "scans logs": readLocal,
  "scans match": writeRemote,
  "scans rerun": writeRemote,
  "scans show": readLocal,
  validate: writeRemote,
  "verify-fix": readRemote,
};

export function mcpCommandMetadata(command: string) {
  return Object.hasOwn(commandAnnotations, command)
    ? { annotations: commandAnnotations[command]! }
    : false;
}

export interface CliMcpSchema {
  [key: string]: unknown;
  type?: string;
  properties?: Record<string, CliMcpSchema>;
  required?: string[];
  default?: unknown;
}

export interface CliMcpManifest {
  commands: {
    name: string;
    description?: string;
    schema?: {
      args?: CliMcpSchema;
      options?: CliMcpSchema;
      output?: CliMcpSchema;
    };
  }[];
}

export interface CliMcpCommand {
  name: string;
  path: string[];
  description: string;
  inputSchema: CliMcpSchema;
  jsonOutput: boolean;
  annotations: ToolAnnotations;
}

export interface CliMcpInput {
  workingDirectory?: string;
  args?: Record<string, unknown>;
  options?: Record<string, unknown>;
}

export interface CliMcpResult {
  exitCode: number;
  data?: unknown;
  output?: string;
  error?: string;
  diagnostics?: string;
}

export interface CliMcpOutputOptions {
  jsonOutput?: boolean;
}

export interface CliMcpRunOptions {
  executable: string;
  entrypoint: string;
  cwd: string;
  environment: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  forceSignal?: AbortSignal;
  onStderr?: (chunk: string) => void;
}

/** Adapt the public CLI manifest without maintaining a second command schema. */
export function buildCliMcpCommands(manifest: CliMcpManifest): CliMcpCommand[] {
  return manifest.commands
    .filter(({ name }) => Object.hasOwn(commandAnnotations, name))
    .map(({ name, description, schema }) => {
      const properties: Record<string, CliMcpSchema> = {
        workingDirectory: {
          type: "string",
          description:
            "Working directory for this invocation (default: server working directory).",
        },
      };
      const required: string[] = [];
      for (const kind of ["args", "options"] as const) {
        if (name === "login" && kind === "options") continue;
        const fields = schema?.[kind];
        if (fields === undefined) continue;
        properties[kind] = adaptFields(fields, kind === "args");
        if (name === "login" && kind === "args") {
          properties[kind].required = ["action"];
        }
        if (name === "publish scan" && kind === "options") {
          // Only the documented destination and its options belong in MCP.
          const options = properties[kind];
          const destination = options.properties?.["to"];
          if (destination !== undefined) destination["enum"] = ["linear"];
          const cliOnly = ["csv", "findingsUrl", "workflowId"];
          for (const field of cliOnly) delete options.properties?.[field];
          if (options.required !== undefined) {
            options.required = options.required.filter(
              (field) => !cliOnly.includes(field),
            );
            if (options.required.length === 0) delete options.required;
          }
        }
        if ((properties[kind].required?.length ?? 0) > 0) required.push(kind);
      }
      return {
        name: name.replaceAll(" ", "_"),
        path: name.split(" "),
        description:
          name === "login"
            ? "Report login status. Complete sign-in locally with the CLI before using authenticated tools."
            : (description ?? name),
        inputSchema: {
          type: "object",
          properties,
          ...(required.length > 0 ? { required } : {}),
          additionalProperties: false,
        },
        jsonOutput: schema?.output !== undefined,
        annotations: commandAnnotations[name]!,
      };
    });
}

function adaptFields(schema: CliMcpSchema, positional: boolean): CliMcpSchema {
  const properties: Record<string, CliMcpSchema> = {};
  const required: string[] = [];
  for (const [name, field] of Object.entries(schema.properties ?? {})) {
    const variadic = positional && name.endsWith("...");
    const inputName = variadic ? name.slice(0, -3) : name;
    const isRequired =
      schema.required?.includes(name) === true && !("default" in field);
    const inputField = structuredClone(field);
    if (positional) {
      inputField["description"] = [
        field["description"],
        "Positional values cannot start with '-'; prefix paths with './', or put finding text in a file.",
      ]
        .filter(Boolean)
        .join(" ");
    }
    properties[inputName] = variadic
      ? {
          type: "array",
          items: inputField,
          description: inputField["description"],
          ...(isRequired ? { minItems: 1 } : {}),
        }
      : inputField;
    if (isRequired) required.push(inputName);
  }
  const result = { ...schema, properties };
  if (required.length > 0) result.required = required;
  else delete result.required;
  return result;
}

export function buildCliMcpArguments(
  command: CliMcpCommand,
  input: CliMcpInput,
): string[] {
  const argv = [...command.path];
  if (command.jsonOutput) argv.push("--json");
  for (const name of Object.keys(
    command.inputSchema.properties?.["options"]?.properties ?? {},
  )) {
    const value = input.options?.[name];
    if (value === undefined) continue;
    const flag = name.replace(
      /[A-Z]/gu,
      (letter) => `-${letter.toLowerCase()}`,
    );
    if (typeof value === "boolean") {
      argv.push(value ? `--${flag}` : `--no-${flag}`);
    } else {
      for (const item of Array.isArray(value) ? value : [value]) {
        argv.push(`--${flag}=${String(item)}`);
      }
    }
  }
  let omittedArgument: string | undefined;
  for (const name of Object.keys(
    command.inputSchema.properties?.["args"]?.properties ?? {},
  )) {
    const value = input.args?.[name];
    const values =
      value === undefined
        ? []
        : (Array.isArray(value) ? value : [value]).map(String);
    if (values.length === 0) {
      omittedArgument ??= name;
      continue;
    }
    if (omittedArgument !== undefined) {
      throw new Error(
        `Positional argument '${name}' requires the preceding '${omittedArgument}' argument.`,
      );
    }
    if (values.some((item) => item.startsWith("-"))) {
      throw new Error(
        `Positional argument '${name}' cannot start with '-'; prefix paths with './', or put finding text in a file.`,
      );
    }
    argv.push(...values);
  }
  return argv;
}

export function parseCliMcpResult(
  exitCode: number,
  stdout: string,
  stderr: string,
  options: CliMcpOutputOptions = {},
): CliMcpResult {
  const result: CliMcpResult = { exitCode };
  if (options.jsonOutput) {
    try {
      result.data = JSON.parse(stdout) as unknown;
    } catch {
      if (stdout.length > 0) result.output = stdout;
      if (exitCode === 0) {
        result.exitCode = 2;
        result.error = "Command returned invalid JSON.";
      }
    }
  } else if (stdout.length > 0) {
    result.output = stdout;
  }
  if (exitCode !== 0) {
    result.error =
      stderr.trim() ||
      stdout.trim() ||
      `Command exited with status ${exitCode}.`;
  } else if (stderr.length > 0) {
    result.diagnostics = stderr;
  }
  return result;
}

/** Run a CLI invocation with its own streams and wait for process cleanup. */
export async function runCliMcpCommand(
  command: CliMcpCommand,
  input: CliMcpInput,
  options: CliMcpRunOptions,
): Promise<CliMcpResult> {
  if (options.signal?.aborted || options.forceSignal?.aborted) {
    return { exitCode: 130, error: "Command cancelled." };
  }
  const jsonOutput = command.jsonOutput;
  let argv: string[];
  try {
    argv = buildCliMcpArguments(command, input);
  } catch (error) {
    return { exitCode: 2, error: (error as Error).message };
  }
  return new Promise((resolve) => {
    const child = spawn(options.executable, [options.entrypoint, ...argv], {
      cwd: options.cwd,
      env: options.environment,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      detached: process.platform !== "win32" && options.signal !== undefined,
    });
    let stdout = "";
    let stderr = "";
    let startError: Error | undefined;
    let cancelled = false;
    let termination: Promise<void> | undefined;
    let cancellationSignal: "SIGINT" | "SIGTERM" = "SIGTERM";
    const abort = (): void => {
      if (cancelled) return;
      cancelled = true;
      cancellationSignal =
        options.signal?.reason === "SIGINT" ? "SIGINT" : "SIGTERM";
      termination = terminateProcess(child, cancellationSignal);
      // The CLI owns its subprocess cleanup, including detached workers and
      // their termination grace periods. Wait for that cleanup before closing.
    };
    const force = (): void => {
      const forcePublication =
        cancelled &&
        command.name === "publish_scan" &&
        input.options?.["to"] === "linear" &&
        input.options?.["dryRun"] !== true;
      cancelled = true;
      // Linear publication owns detached Codex processes. Its repeated-signal
      // handler kills those before exiting; a different signal bypasses the
      // duplicate-delivery debounce. Other commands may ignore repeated signals.
      termination = terminateProcess(
        child,
        forcePublication
          ? cancellationSignal === "SIGINT"
            ? "SIGTERM"
            : "SIGINT"
          : "SIGKILL",
      );
    };
    options.signal?.addEventListener("abort", abort, { once: true });
    options.forceSignal?.addEventListener("abort", force, { once: true });
    if (options.signal?.aborted) abort();
    if (options.forceSignal?.aborted) force();
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
      try {
        options.onStderr?.(chunk);
      } catch {
        // Progress observers must not interrupt the command.
      }
    });
    child.once("error", (error) => {
      startError = error;
    });
    child.once("close", (code, signal) => {
      void (termination ?? Promise.resolve()).then(() => {
        if (cancelled && process.platform !== "win32") {
          terminateProcessGroup(child, "SIGKILL");
        }
        options.signal?.removeEventListener("abort", abort);
        options.forceSignal?.removeEventListener("abort", force);
        const result = parseCliMcpResult(
          cancelled ? 130 : signal !== null ? 1 : (code ?? 2),
          stdout,
          stderr,
          { jsonOutput },
        );
        if (startError !== undefined) {
          result.exitCode = 2;
          result.error = startError.message;
        } else if (cancelled) result.error = "Command cancelled.";
        resolve(result);
      });
    });
  });
}

function terminateProcess(
  child: ChildProcess,
  signal: NodeJS.Signals,
): Promise<void> {
  if (process.platform !== "win32" || child.pid === undefined) {
    terminateProcessGroup(child, signal);
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    const taskkill = spawn(
      win32.join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
        "taskkill.exe",
      ),
      ["/PID", String(child.pid), "/T", "/F"],
      { stdio: "ignore", windowsHide: true },
    );
    taskkill.once("error", () => {
      terminateProcessGroup(child, "SIGKILL");
      resolve();
    });
    taskkill.once("close", (code) => {
      if (code !== 0) terminateProcessGroup(child, "SIGKILL");
      resolve();
    });
  });
}

function terminateProcessGroup(
  child: ChildProcess,
  signal: NodeJS.Signals,
): void {
  if (child.pid === undefined) return;
  if (process.platform !== "win32") {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch {
      // The group may have exited before the cancellation request arrived.
    }
  }
  try {
    child.kill(signal);
  } catch {
    // The direct child may have exited as well.
  }
}
