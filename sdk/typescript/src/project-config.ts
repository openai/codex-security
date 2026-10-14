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
import { parseDocument } from "yaml";
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
  sources: ConfigurationSources;
  projectConfig?: ProjectConfigProvenance;
}

export type ConfigurationSource = "default" | "legacy" | "project" | "cli";
const PROJECT_SETTING_KEYS = {
  auth: "auth",
  mode: "scan.mode",
  cyberAccessProgram: "scan.cyber_access_program",
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

function requireProjectConfig(
  value: unknown,
  path?: string,
): asserts value is ProjectConfigInput {
  if (!validateProjectConfig(value)) {
    const errors = validateProjectConfig.errors ?? [];
    const detail = errors
      .map((error) => `${error.instancePath || "/"}: ${error.message}`)
      .join("; ");
    throw new ConfigurationError(
      path
        ? `Invalid project configuration at ${path}: ${detail}`
        : `Invalid project configuration: ${detail}`,
    );
  }
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
      `Cannot read project configuration at ${path}: ${errorMessage(error)}.`,
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
      // Keep YAML's expansion guard while allowing repeated native profiles.
      value = document.toJS({ maxAliasCount: 10_000 });
    }
  } catch (error) {
    throw new ConfigurationError(
      `Cannot parse project configuration at ${path}: ${errorMessage(error)}.`,
      { cause: error },
    );
  }
  requireProjectConfig(value, path);
  return { path, directory: dirname(path), input: value };
}

function projectConfigExtension(path: string): string {
  const extension = extname(path).toLowerCase();
  if (!["\.yaml", "\.yml", "\.json"].includes(extension)) {
    throw new ConfigurationError(
      "Project configuration must be a .yaml, .yml, or .json file.",
    );
  }
  return extension;
}
