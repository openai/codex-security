import { readFile } from "node:fs/promises";
import {
  dirname,
  extname,
  isAbsolute,
  relative,
  resolve,
  sep,
} from "node:path";
import { pathToFileURL } from "node:url";
import Ajv from "ajv";
import {
  DEFAULT_CODEX_CONFIG,
  mergeCodexOverrides,
  type JsonObject,
} from "./config.js";
import { ConfigurationError, errorMessage } from "./errors.js";
import { DEFAULT_DEEP_SCAN_SETTINGS } from "./deep-scan-defaults.js";
import { resolveConfigPath, type AbsolutePath } from "./config-path.js";
import { deepScanOptions, type DeepScanSources } from "./deep-config.js";
import {
  DEFAULT_DECISIONS_CUTOFF,
  projectConfigJsonSchema,
  type ProjectConfigInput,
  type ProjectScope,
} from "./project-config-schema.js";
import { expandHome } from "./runtime.js";
import {
  DEFAULT_SCAN_AUTH,
  DEFAULT_SCAN_MODE,
  DEEP_SCAN_SETTINGS,
  pickScanSettings,
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
  reviewEvents?: ReturnType<typeof projectReviewEventSettings>;
  sources: ConfigurationSources;
  projectConfig?: ProjectConfigProvenance;
}

export function projectReviewEventSettings(
  settings: NonNullable<ProjectConfigInput["review_events"]>,
) {
  return {
    screenWithDecisions: settings.screen_with_decisions,
    decisionsCutoff: settings.decisions_cutoff,
  };
}

export type ConfigurationSource = "default" | "legacy" | "project" | "cli";
const PROJECT_SETTING_KEYS = {
  auth: "auth",
  mode: "scan.mode",
  maxTimeMinutes: "scan.max_time_minutes",
  cyberAccessProgram: "scan.cyber_access_program",
  ownerSuggestions: "scan.owner_suggestions",
  target: "scan.scope",
  knowledgeBasePaths: "scan.knowledge_base",
  scanPromptFile: "scan.instructions_file",
  validationPromptFile: "scan.validation_file",
  outputDir: "output.directory",
  failureSeverity: "policy.fail_on_severity",
  maxCostUsd: "limits.max_cost_usd_per_scan",
} as const satisfies Partial<Record<keyof ScanSettings, string>>;
type SettingProvenanceKey =
  (typeof PROJECT_SETTING_KEYS)[keyof typeof PROJECT_SETTING_KEYS];
export type ScopeProvenanceKey =
  "scan.scope" | "scan.scope.diff.head" | "scan.scope.working_tree.base";
export type ProvenanceKey =
  | SettingProvenanceKey
  | ScopeProvenanceKey
  | `scan.deep.${(typeof DEEP_SCAN_SETTINGS)[number][2]}`
  | `codex.${string}`;
export type ConfigurationSources = Readonly<
  Record<SettingProvenanceKey, ConfigurationSource> &
    Partial<Record<ProvenanceKey, ConfigurationSource>>
>;
export interface ProjectConfigProvenance {
  path: string;
  sources: ConfigurationSources;
}

/** Build a complete, immutable source map after layer and preflight resolution. */
export function configurationSources(
  values: Partial<Record<ProvenanceKey, ConfigurationSource>> = {},
  deepSources?: DeepScanSources,
): ConfigurationSources {
  const sources = {
    ...Object.fromEntries(
      Object.values(PROJECT_SETTING_KEYS).map((key) => [key, "default"]),
    ),
    ...values,
  } as Record<SettingProvenanceKey, ConfigurationSource> &
    Partial<Record<ProvenanceKey, ConfigurationSource>>;
  for (const [name, , key] of DEEP_SCAN_SETTINGS) {
    const source = deepSources?.[name];
    if (source !== undefined && source !== "override")
      sources[`scan.deep.${key}`] = source;
  }
  return Object.freeze(sources);
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
  const extension = projectConfigExtension(path);
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    throw new ConfigurationError(
      `Cannot read project configuration at ${path}: ${errorMessage(error)}`,
      { cause: error },
    );
  }
  let value: unknown;
  try {
    if (extension === ".json") {
      value = JSON.parse(text.replace(/^\uFEFF/u, ""));
    } else {
      const { parseDocument } = await import("yaml");
      const document = parseDocument(text, { prettyErrors: false });
      if (document.errors.length > 0) throw document.errors[0];
      // Keep YAML's expansion guard while allowing repeated native profiles.
      value = document.toJS({ maxAliasCount: 10_000 });
    }
  } catch (error) {
    throw new ConfigurationError(
      `Cannot parse project configuration at ${path}: ${errorMessage(error)}`,
      { cause: error },
    );
  }
  requireProjectConfig(value, path);
  return { path, directory: dirname(path), input: value };
}

function projectConfigExtension(path: string): string {
  const extension = extname(path).toLowerCase();
  if (![".yaml", ".yml", ".json"].includes(extension)) {
    throw new ConfigurationError(
      "Project configuration must be a .yaml, .yml, or .json file.",
    );
  }
  return extension;
}

export function projectConfigStarter(
  path: string,
  directory = process.cwd(),
): string {
  const schemaPath = resolve(
    directory,
    "node_modules/@openai/codex-security/schemas/project-config.schema.json",
  );
  const relativeSchema = relative(
    dirname(resolve(directory, path)),
    schemaPath,
  );
  const schema = isAbsolute(relativeSchema)
    ? pathToFileURL(schemaPath).href
    : `${relativeSchema.startsWith(".") ? "" : "./"}${encodeURI(
        relativeSchema.split(sep).join("/"),
      ).replace(/[#?]/gu, encodeURIComponent)}`;
  if (projectConfigExtension(path) === ".json")
    return `${JSON.stringify({ $schema: schema }, null, 2)}\n`;
  return [
    "# This file is trusted like CLI options. Keep it outside untrusted inputs.",
    `$schema: ${schema}`,
    "",
    "# Uncomment the settings you want to override. Defaults remain unpinned.",
    `# auth: ${DEFAULT_SCAN_AUTH}`,
    "# scan:",
    `#   mode: ${DEFAULT_SCAN_MODE}`,
    "#   scope:",
    "#     paths: [src] # Relative to each selected repository.",
    "#   knowledge_base: [] # Paths relative to this file.",
    "#   instructions_file: instructions.md",
    "#   validation_file: validation.md # Standard mode only.",
    "#   max_time_minutes: 15 # Advisory in Standard; enforced discovery limit in Deep.",
    "#   deep: # Used when mode is deep.",
    ...DEEP_SCAN_SETTINGS.filter(([name]) => name !== "maxTimeHours").map(
      ([name, , key]) => `#     ${key}: ${DEFAULT_DEEP_SCAN_SETTINGS[name]}`,
    ),
    "# codex:",
    `#   model: ${DEFAULT_CODEX_CONFIG["model"]}`,
    `#   model_reasoning_effort: ${DEFAULT_CODEX_CONFIG["model_reasoning_effort"]}`,
    "# limits:",
    "#   max_cost_usd_per_scan: 10 # Optional limit per scan attempt.",
    "# review_events:",
    "#   screen_with_decisions: false",
    `#   decisions_cutoff: ${DEFAULT_DECISIONS_CUTOFF}`,
    "# policy:",
    "#   fail_on_severity: high # Omitted by default (report only).",
    "# output:",
    "#   directory: ../scan-results # Outside the selected repositories.",
    "",
  ].join("\n");
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
  scopeSources: Partial<Record<ScopeProvenanceKey, ConfigurationSource>> = {},
): ResolvedProjectConfig {
  const file = project?.input;
  const sources: Partial<Record<ProvenanceKey, ConfigurationSource>> = {};
  const choose = <T>(
    key: ProvenanceKey,
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
  const projectDirectory = project?.directory ?? directory;
  const filePath = (value: string | undefined): AbsolutePath | undefined =>
    value === undefined
      ? undefined
      : resolveConfigPath(projectDirectory, value);
  const cliPath = (value: string | undefined): AbsolutePath | undefined =>
    value === undefined ? undefined : resolveConfigPath(directory, value);

  const mode =
    choose("scan.mode", file?.scan?.mode, overrides.mode) ?? DEFAULT_SCAN_MODE;
  const explicitDeep = deepScanOptions({
    ...overrides,
    maxTimeMinutes: undefined,
    mode,
  });
  const target =
    choose(
      "scan.scope",
      projectScopeTarget(file?.scan?.scope),
      overrides.target,
    ) ?? "repository";
  const configuredDeep = file?.scan?.deep;
  const explicitTime =
    overrides.maxTimeMinutes !== undefined ||
    overrides.maxTimeHours !== undefined;
  const maxTimeMinutes = choose(
    "scan.max_time_minutes",
    explicitTime ? undefined : file?.scan?.max_time_minutes,
    overrides.maxTimeMinutes,
  );
  const deep: DeepScanOptions = {};
  if (mode === "deep") {
    for (const [name, , field] of DEEP_SCAN_SETTINGS) {
      const value = choose(
        `scan.deep.${field}`,
        name === "maxTimeHours" && explicitTime
          ? undefined
          : configuredDeep?.[field],
        explicitDeep[name],
      );
      if (value !== undefined) deep[name] = value;
    }
  }

  const codexOverrides = mergeCodexOverrides(
    file?.codex ?? {},
    overrides.codexOverrides ?? {},
  );
  const nativeSourceTree = (
    value: JsonObject,
    source: ConfigurationSource,
  ): JsonObject =>
    Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        item !== null && typeof item === "object" && !Array.isArray(item)
          ? nativeSourceTree(item, source)
          : source,
      ]),
    );
  const recordNativeSources = (
    value: JsonObject,
    source: ConfigurationSource,
    prefix: "codex" | `codex.${string}` = "codex",
  ) => {
    for (const [key, item] of Object.entries(value)) {
      const path: `codex.${string}` = `${prefix}.${key}`;
      if (item !== null && typeof item === "object" && !Array.isArray(item)) {
        recordNativeSources(item, source, path);
      } else if (item === source) {
        sources[path] = source;
      }
    }
  };
  // Match the value merge: defaults beneath the combined project/CLI overrides.
  const nativeSources = mergeCodexOverrides(
    nativeSourceTree(DEFAULT_CODEX_CONFIG, "default"),
    mergeCodexOverrides(
      nativeSourceTree(file?.codex ?? {}, "project"),
      nativeSourceTree(overrides.codexOverrides ?? {}, "cli"),
    ),
  );
  // Literal dotted keys can share a flattened name; retain layer precedence.
  for (const source of ["default", "project", "cli"] as const) {
    recordNativeSources(nativeSources, source);
  }
  const knowledgeBasePaths =
    choose(
      "scan.knowledge_base",
      file?.scan?.knowledge_base?.map((value) =>
        resolveConfigPath(projectDirectory, value),
      ),
      overrides.knowledgeBasePaths?.map((value) =>
        resolveConfigPath(directory, value),
      ),
    ) ?? [];
  const settings: ResolvedScanSettings = {
    ...pickScanSettings(overrides),
    auth: choose("auth", file?.auth, overrides.auth) ?? DEFAULT_SCAN_AUTH,
    cyberAccessProgram: choose(
      "scan.cyber_access_program",
      file?.scan?.cyber_access_program,
      overrides.cyberAccessProgram,
    ),
    mode,
    maxTimeMinutes,
    target,
    ownerSuggestions: choose(
      "scan.owner_suggestions",
      file?.scan?.owner_suggestions,
      overrides.ownerSuggestions,
    ),
    knowledgeBasePaths,
    scanPromptFile: choose(
      "scan.instructions_file",
      filePath(file?.scan?.instructions_file),
      cliPath(overrides.scanPromptFile),
    ),
    validationPromptFile: choose(
      "scan.validation_file",
      filePath(file?.scan?.validation_file),
      cliPath(overrides.validationPromptFile),
    ),
    postScanPromptFile: cliPath(overrides.postScanPromptFile),
    outputDir: choose(
      "output.directory",
      filePath(file?.output?.directory),
      cliPath(overrides.outputDir),
    ),
    failureSeverity: choose(
      "policy.fail_on_severity",
      file?.policy?.fail_on_severity,
      overrides.failureSeverity,
    ),
    maxCostUsd: choose(
      "limits.max_cost_usd_per_scan",
      file?.limits?.max_cost_usd_per_scan,
      overrides.maxCostUsd,
    ),
    ...deep,
  };
  const resolvedSources = configurationSources({ ...sources, ...scopeSources });
  return {
    config: { codexOverrides },
    options: settings,
    ...(file?.review_events === undefined
      ? {}
      : { reviewEvents: projectReviewEventSettings(file.review_events) }),
    sources: resolvedSources,
    ...(project?.path === undefined
      ? {}
      : { projectConfig: { path: project.path, sources: resolvedSources } }),
  };
}

export function projectScopeTarget(
  scope: ProjectScope | undefined,
): ScanTarget | undefined {
  if (scope === undefined) return undefined;
  if ("paths" in scope) return [...scope.paths];
  if ("diff" in scope) return DiffTarget.refs(scope.diff);
  return DiffTarget.workingTree(scope.working_tree);
}
