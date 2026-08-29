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
  DEEP_SCAN_SETTINGS,
  type DeepScanOptions,
  type ScanAuthMode,
} from "./scan-settings.js";
import type { ScanMode } from "./targets.js";
import type { SeverityLevel } from "./models.js";

const validateProjectConfig = new Ajv({
  allErrors: true,
}).compile<ProjectConfigInput>(projectConfigJsonSchema());

export interface LoadedProjectConfig {
  path: string;
  input: ProjectConfigInput;
}

export interface ScanSettings extends DeepScanOptions {
  auth?: ScanAuthMode;
  mode: ScanMode;
  paths: string[];
  diff?: string;
  workingTree: boolean;
  base?: string;
  head?: string;
  knowledgeBasePaths: string[];
  scanPromptFile?: string;
  validationPromptFile?: string;
  outputDir?: string;
  failOnSeverity?: Exclude<SeverityLevel, "informational">;
  maxCostUsd?: number;
  codexOverrides: JsonObject;
}

export type ConfigurationSource = "default" | "legacy" | "project" | "cli";
export interface ProjectConfigProvenance {
  path: string;
  sources: Record<string, ConfigurationSource>;
}

export async function loadProjectConfig(
  file: string,
  directory = process.cwd(),
): Promise<LoadedProjectConfig> {
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
      `Invalid project configuration at ${path}: ${issues}`,
    );
  }
  return { path, input: value };
}

export function resolveProjectConfig(
  project: LoadedProjectConfig | undefined,
  overrides: Partial<ScanSettings>,
  directory: string,
): { settings: ScanSettings; provenance?: ProjectConfigProvenance } {
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
      : resolve(dirname(project!.path), expandHome(value));
  const cliPath = (value: string | undefined): string | undefined =>
    value === undefined ? undefined : resolve(directory, expandHome(value));

  const mode =
    choose("scan.mode", file?.scan?.mode, overrides.mode) ?? "standard";
  if (
    mode !== "deep" &&
    DEEP_SCAN_SETTINGS.some(([name]) => overrides[name] !== undefined)
  ) {
    throw new ConfigurationError("Deep scan settings require --mode deep.");
  }
  const explicitScopes =
    Number(!!overrides.paths?.length) +
    Number(overrides.diff !== undefined) +
    Number(overrides.workingTree === true);
  if (explicitScopes > 1)
    throw new ConfigurationError(
      "--path, --diff, and --working-tree are mutually exclusive.",
    );
  let scope: ProjectScope | undefined = file?.scan?.scope;
  if (scope !== undefined) sources["scan.scope"] = "project";
  if (overrides.paths?.length) scope = { paths: overrides.paths };
  else if (overrides.diff !== undefined)
    scope = { diff: { base: overrides.diff } };
  else if (overrides.workingTree === true) scope = { workingTree: {} };
  else if (
    overrides.workingTree === false &&
    scope !== undefined &&
    "workingTree" in scope
  ) {
    scope = undefined;
    sources["scan.scope"] = "cli";
  }
  if (explicitScopes > 0) sources["scan.scope"] = "cli";
  if (overrides.head !== undefined) {
    if (scope === undefined || !("diff" in scope))
      throw new ConfigurationError("--head requires --diff.");
    scope = { diff: { ...scope.diff, head: overrides.head } };
    sources["scan.scope.diff.head"] = "cli";
  }
  if (overrides.base !== undefined) {
    if (scope === undefined || !("workingTree" in scope))
      throw new ConfigurationError("--base requires --working-tree.");
    scope = { workingTree: { base: overrides.base } };
    sources["scan.scope.workingTree.base"] = "cli";
  }
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
  const settings: ScanSettings = {
    auth: choose("auth", file?.auth, overrides.auth) ?? "auto",
    mode,
    paths: scope !== undefined && "paths" in scope ? [...scope.paths] : [],
    workingTree: scope !== undefined && "workingTree" in scope,
    ...(scope !== undefined && "diff" in scope
      ? { diff: scope.diff.base, head: scope.diff.head ?? "HEAD" }
      : {}),
    ...(scope !== undefined && "workingTree" in scope
      ? { base: scope.workingTree.base ?? "HEAD" }
      : {}),
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
    failOnSeverity: choose(
      "policy.failOnSeverity",
      file?.policy?.failOnSeverity,
      overrides.failOnSeverity,
    ),
    maxCostUsd: choose(
      "limits.maxCostUsdPerScan",
      file?.limits?.maxCostUsdPerScan,
      overrides.maxCostUsd,
    ),
    codexOverrides,
    ...deep,
  };
  return {
    settings,
    ...(project === undefined
      ? {}
      : { provenance: { path: project.path, sources } }),
  };
}
