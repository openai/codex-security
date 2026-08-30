import { readFile } from "node:fs/promises";
import { dirname, extname, resolve } from "node:path";
import Ajv from "ajv";
import { parseDocument } from "yaml";
import {
  DEFAULT_CODEX_CONFIG,
  mergeCodexOverrides,
  type JsonObject,
} from "./config.js";
import { ConfigurationError } from "./errors.js";
import {
  projectConfigJsonSchema,
  type ProjectConfigInput,
  type ProjectScope,
} from "./project-config-schema.js";
import { expandHome } from "./runtime.js";
import {
  DEFAULT_SCAN_AUTH,
  DEFAULT_SCAN_MODE,
  DEEP_SCAN_SETTINGS,
  scanSettings,
  type DeepScanOptions,
  type ResolvedScanSettings,
  type ScanSettings,
} from "./scan-settings.js";
import { DiffTarget, type ScanTarget } from "./targets.js";

const validateProjectConfig = new Ajv({
  allErrors: true,
}).compile<ProjectConfigInput>(projectConfigJsonSchema());

export interface ProjectConfigSource {
  path?: string;
  directory: string;
  input: ProjectConfigInput;
}

export interface ResolvedProjectConfig {
  config: { codexOverrides: JsonObject };
  options: ResolvedScanSettings;
  projectConfig?: ProjectConfigProvenance;
}

export type ConfigurationSource = "default" | "legacy" | "project" | "cli";
export interface ProjectConfigProvenance {
  path: string;
  sources: Record<string, ConfigurationSource>;
}

export async function loadProjectConfig(
  file: string,
  directory = process.cwd(),
): Promise<ResolvedProjectConfig> {
  return resolveScanSettings(
    await readProjectConfig(file, directory),
    {},
    directory,
  );
}

export function resolveProjectConfig(
  input: ProjectConfigInput,
  directory = process.cwd(),
): ResolvedProjectConfig {
  requireProjectConfig(input);
  return resolveScanSettings(
    { input, directory: resolve(directory) },
    {},
    directory,
  );
}

export async function readProjectConfig(
  file: string,
  directory = process.cwd(),
): Promise<ProjectConfigSource> {
  const path = resolve(directory, expandHome(file));
  const extension = extname(path).toLowerCase();
  if (![".yaml", ".yml", ".json"].includes(extension)) {
    throw new ConfigurationError(
      "Project configuration must be a .yaml, .yml, or .json file.",
    );
  }
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    throw new ConfigurationError(
      `Cannot read project configuration at ${path}.`,
      { cause: error },
    );
  }
  let value: unknown;
  try {
    if (extension === ".json") {
      value = JSON.parse(text);
    } else {
      const document = parseDocument(text, { prettyErrors: false });
      if (document.errors.length > 0) throw document.errors[0];
      value = document.toJS();
    }
  } catch (error) {
    throw new ConfigurationError(
      `Cannot parse project configuration at ${path}.`,
      { cause: error },
    );
  }
  requireProjectConfig(value, path);
  return { path, directory: dirname(path), input: value };
}

function requireProjectConfig(
  value: unknown,
  path?: string,
): asserts value is ProjectConfigInput {
  if (!validateProjectConfig(value)) {
    const issues = validateProjectConfig
      .errors!.map((issue) => {
        const message =
          issue.keyword === "additionalProperties"
            ? `Unknown key ${issue.params["additionalProperty"]}.`
            : issue.message;
        return `${issue.instancePath || "configuration"}: ${message}`;
      })
      .join("; ");
    throw new ConfigurationError(
      `Invalid project configuration${path === undefined ? "" : ` at ${path}`}: ${issues}`,
    );
  }
}

export function resolveScanSettings(
  project: ProjectConfigSource | undefined,
  overrides: Partial<ScanSettings> & { codexOverrides?: JsonObject },
  directory: string,
): ResolvedProjectConfig {
  const file = project?.input;
  const sources: Record<string, ConfigurationSource> = {
    auth: "default",
    "scan.mode": "default",
    "scan.scope": "default",
    "scan.knowledgeBase": "default",
  };
  const choose = <T>(
    key: string,
    configured: T | undefined,
    explicit: T | undefined,
  ): T | undefined => {
    if (explicit !== undefined) {
      sources[key] = "cli";
      return explicit;
    }
    if (configured !== undefined) {
      sources[key] = "project";
      return configured;
    }
    return undefined;
  };
  const filePath = (value: string | undefined): string | undefined =>
    value === undefined
      ? undefined
      : resolve(project!.directory, expandHome(value));
  const cliPath = (value: string | undefined): string | undefined =>
    value === undefined ? undefined : resolve(directory, expandHome(value));

  const mode =
    choose("scan.mode", file?.scan?.mode, overrides.mode) ?? DEFAULT_SCAN_MODE;
  if (
    mode !== "deep" &&
    DEEP_SCAN_SETTINGS.some(([name]) => overrides[name] !== undefined)
  ) {
    throw new ConfigurationError("Deep scan settings require --mode deep.");
  }
  const target =
    choose(
      "scan.scope",
      projectScopeTarget(file?.scan?.scope),
      overrides.target,
    ) ?? "repository";
  const configuredDeep = file?.scan?.deep;
  const deep: DeepScanOptions = {};
  if (mode === "deep") {
    for (const [name] of DEEP_SCAN_SETTINGS) {
      const field = name === "subagents" ? "subagentsPerWorker" : name;
      const value = choose(
        `scan.deep.${field}`,
        configuredDeep?.[field],
        overrides[name],
      );
      if (value !== undefined) deep[name] = value;
    }
  }

  const codexOverrides = mergeCodexOverrides(
    file?.codex ?? {},
    overrides.codexOverrides ?? {},
  );
  const recordNativeSources = (
    value: JsonObject,
    source: ConfigurationSource,
    prefix = "codex",
  ) => {
    for (const [key, item] of Object.entries(value)) {
      const path = `${prefix}.${key}`;
      if (item !== null && typeof item === "object" && !Array.isArray(item)) {
        delete sources[path];
        recordNativeSources(item, source, path);
      } else {
        for (const existing of Object.keys(sources)) {
          if (existing.startsWith(`${path}.`)) delete sources[existing];
        }
        sources[path] = source;
      }
    }
  };
  recordNativeSources(DEFAULT_CODEX_CONFIG, "default");
  recordNativeSources(file?.codex ?? {}, "project");
  recordNativeSources(overrides.codexOverrides ?? {}, "cli");
  const knowledgeBasePaths =
    choose(
      "scan.knowledgeBase",
      file?.scan?.knowledgeBase?.map((value) => filePath(value)!),
      overrides.knowledgeBasePaths?.map((value) => cliPath(value)!),
    ) ?? [];
  const settings: ResolvedScanSettings = {
    ...scanSettings(overrides),
    auth: choose("auth", file?.auth, overrides.auth) ?? DEFAULT_SCAN_AUTH,
    mode,
    target,
    knowledgeBasePaths,
    scanPromptFile: choose(
      "scan.instructionsFile",
      filePath(file?.scan?.instructionsFile),
      cliPath(overrides.scanPromptFile),
    ),
    validationPromptFile: choose(
      "scan.validationFile",
      filePath(file?.scan?.validationFile),
      cliPath(overrides.validationPromptFile),
    ),
    outputDir: choose(
      "output.directory",
      filePath(file?.output?.directory),
      cliPath(overrides.outputDir),
    ),
    failureSeverity: choose(
      "policy.failOnSeverity",
      file?.policy?.failOnSeverity,
      overrides.failureSeverity,
    ),
    maxCostUsd: choose(
      "limits.maxCostUsdPerScan",
      file?.limits?.maxCostUsdPerScan,
      overrides.maxCostUsd,
    ),
    ...deep,
  };
  return {
    config: { codexOverrides },
    options: settings,
    ...(project?.path === undefined
      ? {}
      : { projectConfig: { path: project.path, sources } }),
  };
}

export function projectScopeTarget(
  scope: ProjectScope | undefined,
): ScanTarget | undefined {
  if (scope === undefined) return undefined;
  if ("paths" in scope) return [...scope.paths];
  if ("diff" in scope) return DiffTarget.refs(scope.diff);
  return DiffTarget.workingTree(scope.workingTree);
}
