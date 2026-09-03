import { spawn, type ChildProcess } from "node:child_process";
import { win32 } from "node:path";

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

export interface CliMcpRunOptions extends CliMcpOutputOptions {
  executable: string;
  entrypoint: string;
  cwd: string;
  environment: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  onStderr?: (chunk: string) => void;
}

/** Adapt the public CLI manifest without maintaining a second command schema. */
export function buildCliMcpCommands(manifest: CliMcpManifest): CliMcpCommand[] {
  return manifest.commands
    .filter(({ name }) => !["scan", "info", "serve", "dedupe"].includes(name))
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
            : description ?? name,
        inputSchema: {
          type: "object",
          properties,
          ...(required.length > 0 ? { required } : {}),
          additionalProperties: false,
        },
        // Patch chooses between structured saved-finding output and direct
        // workflow text. Its caller supplies that decision for each invocation.
        jsonOutput: schema?.output !== undefined && name !== "patch",
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
  options: CliMcpOutputOptions = {},
): string[] {
  const argv = [...command.path];
  if (options.jsonOutput ?? command.jsonOutput) argv.push("--json");
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
  if (options.signal?.aborted) {
    return { exitCode: 130, error: "Command cancelled." };
  }
  const jsonOutput = options.jsonOutput ?? command.jsonOutput;
  let argv: string[];
  try {
    argv = buildCliMcpArguments(command, input, { jsonOutput });
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
    const abort = (): void => {
      if (cancelled) return;
      cancelled = true;
      termination = terminateProcess(child, options.signal);
      // The CLI owns its subprocess cleanup, including detached workers and
      // their termination grace periods. Wait for that cleanup before closing.
    };
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) abort();
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
        const result = parseCliMcpResult(
          cancelled ? 130 : signal !== null ? 1 : code ?? 2,
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
  signal?: AbortSignal,
): Promise<void> {
  if (process.platform !== "win32" || child.pid === undefined) {
    terminateProcessGroup(
      child,
      signal?.reason === "SIGINT" ? "SIGINT" : "SIGTERM",
    );
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
