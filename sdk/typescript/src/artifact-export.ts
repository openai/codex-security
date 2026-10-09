import { spawn } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { Writable as NodeWritable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { JsonObject } from "./config.js";
import { CodexSecurityError } from "./errors.js";
import { relativePathIsOutside as isOutsidePath } from "./targets.js";
import {
  bundledPluginRoot,
  codexSecurityStateDirectory,
  expandHome,
  pythonUtf8Environment,
  resolvePluginPython,
  runWorkbench,
} from "./runtime.js";

export type ArtifactOutput = Pick<NodeJS.WriteStream, "write">;

export const ARTIFACT_EXPORT_FILENAMES = {
  csv: "findings.csv",
  json: "findings.json",
  sarif: "results.sarif",
  md: "threatmodel.md",
} as const;
export type ExportFormat = keyof typeof ARTIFACT_EXPORT_FILENAMES;
export type ExportArtifactKind = "findings" | "threat-model";

export interface ArtifactExportArguments {
  scanDir: string;
  artifact?: ExportArtifactKind;
  format: ExportFormat;
  output: string;
  sourceRoot?: string;
  pythonPath?: string;
  signal?: AbortSignal;
  includeMetadata?: boolean;
}

export type ExportArtifactOptions = {
  source:
    | { directory: string; scanId?: never }
    | { scanId: string; directory?: never };
  output: string;
  pythonPath?: string;
  signal?: AbortSignal;
} & (
  | { artifact: "threat-model"; format?: "md"; sourceRoot?: never }
  | {
      artifact?: "findings";
      format?: "csv" | "json" | "sarif";
      sourceRoot?: string;
    }
);

export interface ArtifactExportResult {
  path: string | null;
  provenance: JsonObject | null;
}

interface HelperOptions {
  pythonPath?: string;
  protectedRoot?: string;
  pluginRoot?: string;
  signal?: AbortSignal;
  output?: ArtifactOutput;
  failureMessage?: string;
}

export function resolveArtifactFormat(
  artifact: ExportArtifactKind,
  format?: ExportFormat,
): ExportFormat {
  const selected = format ?? (artifact === "threat-model" ? "md" : "sarif");
  if ((artifact === "threat-model") !== (selected === "md")) {
    throw new CodexSecurityError(
      artifact === "threat-model"
        ? "Threat-model exports only support --export-format md."
        : "Findings exports support --export-format csv, json, or sarif.",
    );
  }
  return selected;
}

export async function runArtifactHelper(
  args: readonly string[],
  options: HelperOptions = {},
): Promise<{ stdout: string; stderr: string }> {
  const environment = exportEnvironment();
  const python = await resolvePluginPython({
    configuredPath: options.pythonPath,
    environment,
    protectedRoot: options.protectedRoot,
    signal: options.signal,
  });
  const plugin = options.pluginRoot ?? (await bundledPluginRoot());
  const invocation = spawn(
    python,
    [
      "-I",
      "-X",
      "utf8",
      "-B",
      join(plugin, "scripts", "finalize_scan_contract.py"),
      ...args,
    ],
    {
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      signal: options.signal,
    },
  );
  let stderr = "";
  let stdout = "";
  invocation.stderr.setEncoding("utf8");
  invocation.stderr.on("data", (chunk: string) => {
    stderr = `${stderr}${chunk}`.slice(-64 * 1024);
  });
  const forwarded =
    options.output === undefined
      ? (async () => {
          invocation.stdout.setEncoding("utf8");
          for await (const chunk of invocation.stdout) stdout += chunk;
        })()
      : writeArtifactOutput(options.output, invocation.stdout);
  let status: number;
  try {
    [status] = await Promise.all([
      new Promise<number>((resolve, reject) => {
        invocation.once("error", reject);
        invocation.once("close", (code, signal) =>
          resolve(signal === null ? (code ?? 1) : 1),
        );
      }),
      forwarded,
    ]);
  } catch (error) {
    invocation.stdout.destroy();
    invocation.kill();
    throw error;
  }
  if (status !== 0) {
    const detail = stderr.trim().split("\n").at(-1);
    throw new CodexSecurityError(
      detail?.replace(/^finalize_scan_contract\.py: error: /, "") ||
        options.failureMessage ||
        "Could not export Codex Security artifacts.",
    );
  }
  return { stdout, stderr };
}

export async function writeThreatModel(
  directory: string,
  options: HelperOptions = {},
): Promise<string> {
  const result = await runArtifactHelper(
    ["--scan-dir", directory, "--write-threat-model"],
    options,
  );
  return result.stderr.trim().replace(/^codex-security: warning: /u, "");
}

/** Read the current document path without making an optional projection required. */
export async function readThreatModelPath(
  directory: string,
  options: HelperOptions = {},
): Promise<string | null> {
  try {
    options.signal?.throwIfAborted();
    const result = await runArtifactHelper(
      ["--scan-dir", directory, "--describe-threat-model"],
      options,
    );
    return (JSON.parse(result.stdout) as ArtifactExportResult).path;
  } catch {
    options.signal?.throwIfAborted();
    return null;
  }
}

export async function runArtifactExport(
  arguments_: ArtifactExportArguments,
  output?: ArtifactOutput,
): Promise<string | undefined> {
  const artifact = arguments_.artifact ?? "findings";
  resolveArtifactFormat(artifact, arguments_.format);
  const result = await runArtifactHelper(
    [
      "--scan-dir",
      arguments_.scanDir,
      ...(artifact === "findings" ? [] : ["--export-artifact", artifact]),
      "--export-format",
      arguments_.format,
      ...(arguments_.output === "-"
        ? []
        : ["--export-output", arguments_.output]),
      ...(arguments_.sourceRoot === undefined
        ? []
        : ["--source-root", arguments_.sourceRoot]),
      ...(arguments_.includeMetadata ? ["--export-metadata"] : []),
    ],
    {
      pythonPath: arguments_.pythonPath,
      signal: arguments_.signal,
      failureMessage:
        artifact === "findings"
          ? `Could not export Codex Security findings as ${arguments_.format.toUpperCase()}.`
          : "Could not export the saved threat model as Markdown.",
      ...(arguments_.output === "-" && output !== undefined ? { output } : {}),
    },
  );
  return (arguments_.output === "-" && output === undefined) ||
    arguments_.includeMetadata
    ? result.stdout
    : undefined;
}

export async function resolveArtifactExportOutput(
  arguments_: ArtifactExportArguments,
  currentDirectory: string,
): Promise<ArtifactExportArguments> {
  const canonicalScan = await realpath(arguments_.scanDir).catch(
    () => arguments_.scanDir,
  );
  const scanRelativeOutput = relative(arguments_.scanDir, arguments_.output);
  const scanLocalOutput = join(
    "exports",
    ARTIFACT_EXPORT_FILENAMES[arguments_.format],
  );
  if (
    arguments_.output !== "-" &&
    !isOutsidePath(scanRelativeOutput) &&
    scanRelativeOutput !== scanLocalOutput
  ) {
    throw new CodexSecurityError(
      "The export output path cannot overwrite a scan artifact.",
    );
  }
  const outputPath =
    arguments_.output === "-"
      ? "-"
      : !isOutsidePath(scanRelativeOutput)
        ? join(canonicalScan, scanRelativeOutput)
        : join(
            await realpath(dirname(arguments_.output)).catch(
              (error: NodeJS.ErrnoException) => {
                if (error.code === "ENOENT")
                  throw new CodexSecurityError(
                    `Export output directory does not exist: ${dirname(arguments_.output)}. Create the directory and retry.`,
                  );
                throw error;
              },
            ),
            basename(arguments_.output),
          );
  if (arguments_.output !== "-") {
    const outputFromCurrent = relative(currentDirectory, arguments_.output);
    if (outputFromCurrent !== "" && !isOutsidePath(outputFromCurrent)) {
      let existingParent: string | undefined;
      for (
        let directory = dirname(arguments_.output);
        relative(currentDirectory, directory) !== "";
        directory = dirname(directory)
      ) {
        const metadata = await lstat(directory).catch(
          (error: NodeJS.ErrnoException) => {
            if (error.code === "ENOENT") return undefined;
            throw error;
          },
        );
        if (metadata?.isSymbolicLink()) {
          throw new CodexSecurityError(
            "The export output path cannot traverse a repository symlink.",
          );
        }
        if (metadata !== undefined) existingParent ??= directory;
      }
      const canonicalCurrent = await realpath(currentDirectory).catch(
        () => currentDirectory,
      );
      const expectedOutput =
        existingParent === undefined
          ? resolve(canonicalCurrent, outputFromCurrent)
          : resolve(
              await realpath(existingParent),
              relative(existingParent, arguments_.output),
            );
      if (
        isOutsidePath(relative(canonicalCurrent, outputPath)) ||
        relative(expectedOutput, outputPath) !== ""
      ) {
        throw new CodexSecurityError(
          "The export output path cannot traverse a repository symlink.",
        );
      }
    }
  }
  return { ...arguments_, scanDir: canonicalScan, output: outputPath };
}

/** Resolve saved artifacts after the workbench validates their recorded identity. */
export async function resolveSavedArtifactDirectory(
  scanId: string,
  artifact: ExportArtifactKind,
  format: ExportFormat,
  workbench: (args: readonly string[]) => Promise<JsonObject>,
): Promise<string> {
  // Reuse the workbench's recorded digest and scan binding checks without
  // requiring a writable saved-scan directory for stdout or external exports.
  const context = await workbench([
    "export-findings",
    "--scan-id",
    scanId,
    "--artifact",
    artifact,
    "--format",
    format,
    "--validate-only",
  ]);
  const scan = context["scan"] as JsonObject | undefined;
  if (typeof scan?.["scanDir"] !== "string")
    throw new CodexSecurityError(
      `Artifacts for scan ${scanId} are unavailable.`,
    );
  return resolve(expandHome(scan["scanDir"]));
}

/** Export saved artifacts without authenticating or starting Codex. */
export async function exportArtifact(
  options: ExportArtifactOptions,
): Promise<ArtifactExportResult> {
  const artifact = options.artifact ?? "findings";
  const format = resolveArtifactFormat(artifact, options.format);
  const environment = {
    ...exportEnvironment(),
    CODEX_SECURITY_STATE_DIR: codexSecurityStateDirectory(),
  };
  let directory: string;
  if (options.source.directory !== undefined) {
    directory = resolve(expandHome(options.source.directory));
  } else {
    const python = await resolvePluginPython({
      configuredPath: options.pythonPath,
      environment,
      signal: options.signal,
    });
    const pluginRoot = await bundledPluginRoot();
    directory = await resolveSavedArtifactDirectory(
      options.source.scanId,
      artifact,
      format,
      (args) =>
        runWorkbench(
          {
            python,
            pluginRoot,
            environment,
            signal: options.signal,
            failureMessage: "Could not export Codex Security scan artifacts",
          },
          args,
        ),
    );
  }
  const arguments_ = await resolveArtifactExportOutput(
    {
      scanDir: directory,
      artifact,
      format,
      output:
        options.output === "-" ? "-" : resolve(expandHome(options.output)),
      pythonPath: options.pythonPath,
      signal: options.signal,
      includeMetadata: artifact === "threat-model" && options.output !== "-",
      ...(options.sourceRoot === undefined
        ? {}
        : { sourceRoot: resolve(expandHome(options.sourceRoot)) }),
    },
    process.cwd(),
  );
  const metadata = await runArtifactExport(
    arguments_,
    options.output === "-" ? process.stdout : undefined,
  );
  const description =
    metadata === undefined
      ? null
      : (JSON.parse(metadata) as ArtifactExportResult);
  return {
    path: arguments_.output === "-" ? null : arguments_.output,
    provenance: description?.provenance ?? null,
  };
}

export async function writeArtifactOutput(
  output: ArtifactOutput,
  value: string | Uint8Array | AsyncIterable<Uint8Array>,
): Promise<void> {
  const destination = new NodeWritable({
    write(chunk, _encoding, callback) {
      try {
        if (output instanceof NodeWritable) {
          output.write(chunk, callback);
        } else if (output.write(chunk)) {
          callback();
        } else {
          callback(
            new CodexSecurityError(
              "The export stdout stream cannot report backpressure safely.",
            ),
          );
        }
      } catch (error) {
        callback(error instanceof Error ? error : new Error(String(error)));
      }
    },
  });
  const forwardError = (error: Error): void => {
    destination.destroy(error);
  };
  if (output instanceof NodeWritable) output.once("error", forwardError);
  try {
    await pipeline(
      typeof value === "string" || value instanceof Uint8Array
        ? [value]
        : value,
      destination,
    );
  } finally {
    if (output instanceof NodeWritable) {
      output.removeListener("error", forwardError);
    }
  }
}

export function exportEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  return pythonUtf8Environment(
    Object.fromEntries(
      [
        "PATH",
        "Path",
        "PATHEXT",
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "TMP",
        "TEMP",
        "TMPDIR",
        "PYTHON",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
      ]
        .filter((key) => environment[key] !== undefined)
        .map((key) => [key, environment[key]]),
    ),
  );
}
