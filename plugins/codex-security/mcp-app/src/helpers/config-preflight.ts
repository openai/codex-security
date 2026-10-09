import { statSync } from "node:fs";
import { dirname, isAbsolute, join, relative, sep, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual, parseArgs } from "node:util";
import { parse as parseToml } from "smol-toml";
import {
  readFile,
  normalizePath,
  resolvedPathText,
  environmentValue,
  isMissingPathError,
} from "./helper-files";
import { escapeControls, object, stringifyJson } from "./json";
import { encodePosixPath } from "./posix-path";
import { expandHome, windowsFiles, windowsJoin } from "./resolve-security-md";
import { decodeUtf8 } from "./utf8";

type Table = Record<string, unknown>;
const isTable = (value: unknown): value is Table =>
  object(value) && !(value instanceof Date);
type Layer = { path: string; config: Table };
type Value = { value: unknown; source: string };
interface Requirement {
  capability: string;
  severity: string;
  reason: string;
  modes?: string[];
}
interface Capability {
  kind: string;
  check: string;
  path: string;
  op: string;
  value: unknown;
  default?: unknown;
  v1_default?: unknown;
  owner: string;
  version: string;
  plugin: string;
  required: string[];
}
interface Remediation extends Table {
  patches?: Table[];
  variants?: { mode: string; patches?: Table[] }[];
}
interface Profile {
  description: string;
  requirements: Requirement[];
  remediation?: Remediation;
}
interface Registry {
  version: bigint;
  profiles: Record<string, Profile>;
  capabilities: Record<string, Capability>;
  routes: { skill: string; profile: string }[];
}
interface Context {
  mode: string;
  owner: string;
  owner_source: string | null;
  version: string;
  version_source: string | null;
  runtime_provenance: string | null;
  config_v2_enabled: boolean;
  agent_max_threads_configured: boolean;
  agent_max_threads: unknown;
  agent_max_threads_source: string | null;
}

const optionNames = [
  "profile",
  "skill",
  "registry",
  "cwd",
  "codex-config-profile",
  "multi-agent-runtime-owner",
  "multi-agent-runtime-version",
  "multi-agent-session-cap",
  "multi-agent-runtime-provenance",
] as const;
const repeatedOptions = [
  "config",
  "runtime-check",
  "available-plugin-skill",
  "effective-config",
] as const;
type Options = Partial<
  Record<(typeof optionNames)[number], string> &
    Record<(typeof repeatedOptions)[number], string[]>
> & { help?: boolean };
const choices: Record<string, string[]> = {
  "multi-agent-runtime-owner": ["native", "codex-bridge"],
  "multi-agent-runtime-version": ["v1", "v2"],
  "multi-agent-runtime-provenance": [
    "app-server",
    "thread-context",
    "tool-surface",
    "verified-bridge",
  ],
};
const optionHelp: Record<
  (typeof optionNames)[number] | (typeof repeatedOptions)[number],
  [string, string]
> = {
  profile: ["ID", "Capability profile id to evaluate."],
  skill: ["ID", "Top-level skill id to resolve through the registry routes."],
  registry: [
    "PATH",
    "Capability registry path. Defaults to the bundled registry.",
  ],
  config: [
    "PATH",
    "Codex config.toml layer, from lower to higher precedence. Repeat to override automatic cwd-based discovery.",
  ],
  cwd: [
    "PATH",
    "Working directory used to discover trusted project config layers.",
  ],
  "codex-config-profile": [
    "NAME",
    "Selected Codex config profile name, when the session uses one.",
  ],
  "multi-agent-runtime-owner": [
    "OWNER",
    "Verified owner of the active multi-agent runtime. Do not infer bridge ownership from a backend_config value alone.",
  ],
  "multi-agent-runtime-version": [
    "VERSION",
    "Version exposed by the active multi-agent tool surface.",
  ],
  "multi-agent-session-cap": [
    "INTEGER",
    "Resolved V2 session cap from the active runtime; includes the root thread. Accepts a positive ASCII decimal integer, such as 1000 or +1000.",
  ],
  "multi-agent-runtime-provenance": [
    "SOURCE",
    "Evidence source for explicitly supplied multi-agent runtime facts.",
  ],
  "runtime-check": [
    "NAME=BOOL",
    "Known runtime capability, such as delegation_available=true.",
  ],
  "available-plugin-skill": [
    "SKILL_NAME",
    "Plugin-local skill name exposed by the current runtime, such as security-scan. Repeat only for skills from the capability's plugin.",
  ],
  "effective-config": [
    "PATH=JSON",
    "Known effective config value, such as agents.max_threads=8.",
  ],
};
const windows = process.platform === "win32";
const encodePath = (path: string) =>
  windows ? Buffer.from(path, "utf16le") : encodePosixPath(path);
const diagnostic = (value: unknown) =>
  typeof value === "string"
    ? `'${value}'`
    : stringifyJson(diagnosticValue(value), 0);

function diagnosticValue(value: unknown): unknown {
  // JSON would otherwise collapse distinct TOML nonfinite values to null.
  if (typeof value === "number" && !Number.isFinite(value))
    return String(value);
  if (Array.isArray(value)) return value.map(diagnosticValue);
  if (isTable(value))
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, diagnosticValue(item)]),
    );
  return value;
}

function metadata(path: string) {
  if (path.includes("\0")) return undefined;
  try {
    return windows
      ? windowsFiles().stat(encodePath(path))
      : statSync(encodePath(path));
  } catch (error) {
    if (isMissingPathError(error)) return undefined;
    throw error;
  }
}

function readToml(path: string, required = false): Table {
  try {
    // TOML distinguishes integer capacities from floats, including 8 versus 8.0.
    return parseToml(decodeUtf8(readFile(path)), { integersAsBigInt: true });
  } catch (error) {
    if (!required && (error as NodeJS.ErrnoException).code === "ENOENT")
      return {};
    throw error;
  }
}

function lookup(table: unknown, path: string): { value: unknown } | undefined {
  let value = table;
  for (const part of path.split(".")) {
    if (!isTable(value) || !Object.hasOwn(value, part)) return undefined;
    value = value[part];
  }
  return { value };
}

function layered(layers: Layer[], path: string): Value | undefined {
  for (const layer of layers) {
    const value = lookup(layer.config, path);
    if (value) return { ...value, source: layer.path };
  }
}

function configViews(layers: Layer[], profile?: string): Layer[] {
  return layers.toReversed().flatMap((layer) => {
    const profiles = layer.config.profiles;
    const selected = isTable(profiles) ? profiles[profile ?? ""] : undefined;
    // Legacy profiles support features, but not agents or multiagent_config.
    return profile !== undefined &&
      isTable(selected) &&
      Object.hasOwn(selected, "features")
      ? [
          {
            path: `${layer.path} [profiles.${profile}]`,
            config: { features: selected.features },
          },
          layer,
        ]
      : [layer];
  });
}

function assignments(
  values: string[],
  parse: (value: string, key: string) => unknown,
): Table {
  return Object.fromEntries(
    values.map((raw) => {
      const separator = raw.indexOf("=");
      if (separator < 1 || separator === raw.length - 1)
        throw new Error(`expected NAME=VALUE, got ${diagnostic(raw)}`);
      const key = raw.slice(0, separator);
      return [key, parse(raw.slice(separator + 1), key)];
    }),
  );
}

function effectiveValue(value: string, key: string): unknown {
  try {
    return JSON.parse(
      value,
      (_key, item: unknown, context?: { source: string }) =>
        typeof item === "number" && /^-?\d+$/u.test(context?.source ?? "")
          ? BigInt(context!.source)
          : item,
    );
  } catch {
    throw new Error(
      `expected JSON value for ${diagnostic(key)}, got ${diagnostic(value)}`,
    );
  }
}

function booleanValue(value: string): boolean {
  if (value.toLowerCase() === "true") return true;
  if (value.toLowerCase() === "false") return false;
  throw new Error(`expected true or false, got ${diagnostic(value)}`);
}

function requiredField<T extends object, K extends keyof T>(
  table: T,
  key: K,
): T[K] {
  if (!Object.hasOwn(table, key)) throw new Error(diagnostic(key));
  return table[key];
}

function equalityValue(value: unknown): unknown {
  // Match Python numeric equality without rounding bigint integers to numbers.
  if (typeof value === "boolean") return value ? 1n : 0n;
  // Distinct markers keep NaN unequal, including within arrays and tables.
  if (typeof value === "number" && Number.isNaN(value)) return Symbol("NaN");
  if (typeof value === "number" && Number.isInteger(value))
    return BigInt(value);
  if (Array.isArray(value)) return value.map(equalityValue);
  if (isTable(value))
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, equalityValue(item)]),
    );
  return value;
}

function compare(actual: unknown, op: string, expected: unknown): boolean {
  if (op === "==")
    return isDeepStrictEqual(equalityValue(actual), equalityValue(expected));
  if (op === ">=") {
    if (typeof actual !== "bigint") return false;
    if (
      typeof expected !== "bigint" &&
      typeof expected !== "number" &&
      typeof expected !== "boolean"
    )
      throw new TypeError(
        `unsupported comparison threshold for >=: ${diagnostic(expected)}`,
      );
    return (
      actual >= (typeof expected === "boolean" ? Number(expected) : expected)
    );
  }
  throw new Error(`unsupported comparison operator: ${diagnostic(op)}`);
}

function printJson(value: unknown): void {
  // Keep the helper's JSON output ASCII, including terminal controls in paths.
  console.log(
    stringifyJson(diagnosticValue(value)).replace(
      /[\u007f-\uffff]/g,
      (unit) => `\\u${unit.charCodeAt(0).toString(16).padStart(4, "0")}`,
    ),
  );
}

function requiresMultiAgent(
  profile: Profile,
  capabilities: Registry["capabilities"],
): boolean {
  const runtimePath = (path: unknown) =>
    typeof path === "string" &&
    /^(?:agents(?:\.|$)|features(?:$|\.multi_agent_v2(?:\.|$))|multiagent_config(?:\.|$))/u.test(
      path,
    );
  return (
    profile.requirements.some((requirement) => {
      const capability = capabilities[requirement.capability];
      return (
        ["multi_agent_capacity", "multi_agent_mode"].includes(
          requiredField(capability, "kind"),
        ) ||
        Boolean(requirement.modes?.length) ||
        runtimePath(capability.path)
      );
    }) ||
    Boolean(profile.remediation?.variants?.length) ||
    Boolean(
      profile.remediation?.patches?.some((patch) => runtimePath(patch.path)),
    )
  );
}

function v2Setting(views: Layer[], effective: Table): Value | undefined {
  if (Object.hasOwn(effective, "features.multi_agent_v2.enabled")) {
    const value = effective["features.multi_agent_v2.enabled"];
    if (typeof value !== "boolean")
      throw new Error("features.multi_agent_v2.enabled must be a boolean");
    return { value, source: "effective-config" };
  }
  const settings: Value[] = [];
  if (Object.hasOwn(effective, "features.multi_agent_v2"))
    settings.push({
      value: effective["features.multi_agent_v2"],
      source: "effective-config",
    });
  for (const layer of views) {
    const setting = lookup(layer.config, "features.multi_agent_v2");
    if (setting) settings.push({ ...setting, source: layer.path });
  }
  let tableOverride = false;
  for (const { value, source } of settings) {
    if (tableOverride && !isTable(value) && typeof value !== "boolean") break;
    if (typeof value === "boolean") return { value, source };
    if (!isTable(value))
      throw new Error("features.multi_agent_v2 must be a boolean or table");
    if (Object.hasOwn(value, "enabled")) {
      if (typeof value.enabled !== "boolean")
        throw new Error("features.multi_agent_v2.enabled must be a boolean");
      return { value: value.enabled, source };
    }
    tableOverride = true;
  }
  return tableOverride
    ? { value: false, source: "documented-default" }
    : undefined;
}

function remediationTable(value: unknown): Remediation {
  if (isTable(value)) return value;
  // The Python helper also accepted dict-compatible sequences of key/value pairs.
  if (!Array.isArray(value) && value !== "")
    throw new TypeError(
      `expected remediation table or sequence of pairs, got ${diagnostic(value)}`,
    );
  return Object.fromEntries(
    Array.from(value, (entry: unknown) => {
      const pair =
        typeof entry === "string"
          ? [...entry]
          : isTable(entry)
            ? Object.keys(entry)
            : entry;
      if (!Array.isArray(pair) || pair.length !== 2)
        throw new TypeError(
          `expected remediation key/value pair, got ${diagnostic(entry)}`,
        );
      // Legacy sorted JSON output cannot mix non-string keys with multi_agent_mode.
      if (typeof pair[0] !== "string")
        throw new TypeError(
          `unsupported remediation key: ${diagnostic(pair[0])}`,
        );
      return pair;
    }),
  );
}

function remediation(profile: Profile, context: Context): Table {
  const { variants = [], ...result } = remediationTable(
    profile.remediation ?? {},
  );
  result.multi_agent_mode = context.mode;
  const variant = variants.find(
    (item) => requiredField(item, "mode") === context.mode,
  );
  if (variant && (context.mode !== "v2" || context.owner === "native")) {
    const patches = (variant.patches ?? []).filter(
      (patch) =>
        context.mode !== "v2" ||
        context.agent_max_threads_configured ||
        patch.kind !== "remove" ||
        patch.path !== "agents.max_threads",
    );
    result.patches = [...(result.patches ?? []), ...patches];
  } else if (variants.length) {
    result.note =
      "Do not apply a concurrency patch until the active runtime version and config ownership are known.";
  }
  return result;
}

export function* projectAncestors(directory: string): Iterable<string> {
  for (let current = directory; ;) {
    yield current;
    // node:path recognizes ordinary UNC share roots, but not extended UNC roots.
    const extendedUnc =
      windows && current.slice(0, 8).toUpperCase() === "\\\\?\\UNC\\";
    const ordinary = extendedUnc ? `\\\\${current.slice(8)}` : current;
    const parent = windows ? win32.dirname(ordinary) : dirname(ordinary);
    if (parent === ordinary) return;
    current = extendedUnc ? win32.toNamespacedPath(parent) : parent;
  }
}

function appendConfigPath(directory: string, suffix: string): string {
  const parent = directory || ".";
  // Keep relative spelling and symlink-sensitive ".." in configured paths.
  return normalizePath(
    parent +
      (parent.endsWith(sep) || (windows && /^[a-z]:$/iu.test(parent))
        ? ""
        : sep) +
      suffix,
  );
}

function resolveWorkingDirectory(value: string): string {
  if (windows) return resolvedPathText(value, false);
  let current = resolvedPathText(isAbsolute(value) ? "/" : ".");
  for (const part of value.split("/")) {
    if (!part || part === ".") continue;
    // Resolve each prefix before applying parent traversal through symlinks.
    if (part === "..") {
      current = dirname(current);
      continue;
    }
    const candidate = appendConfigPath(current, part);
    try {
      current = resolvedPathText(candidate, false);
    } catch (error) {
      // A later parent component can cancel a non-directory prefix too.
      if ((error as NodeJS.ErrnoException).code !== "ENOTDIR") throw error;
      current = candidate;
    }
  }
  return current;
}

function evaluate(values: Options): Table {
  const home = environmentValue("HOME");
  const path = (value: string) => normalizePath(expandHome(value, home));
  const configuredHome = environmentValue("CODEX_HOME");
  const codexHome = path(configuredHome?.trim() ? configuredHome : "~/.codex");
  const defaultConfig = appendConfigPath(codexHome, "config.toml");
  // Bundles replace import.meta.url with the installed helper filename.
  const filename = import.meta.url.startsWith("file:")
    ? fileURLToPath(import.meta.url)
    : import.meta.url;
  const registry = readToml(
    values.registry ??
      join(dirname(filename), "../preflight/capability-profiles.toml"),
    true,
  ) as unknown as Registry;
  const capabilities = requiredField(registry, "capabilities");
  for (const [id, profile] of Object.entries(registry.profiles)) {
    for (const requirement of profile.requirements) {
      if (!Object.hasOwn(capabilities, requirement.capability))
        throw new Error(
          `profile ${diagnostic(id)} references unknown capability ${diagnostic(requirement.capability)}`,
        );
      if (!["block", "warn", "suggest"].includes(requirement.severity))
        throw new Error(
          `profile ${diagnostic(id)} has unsupported severity ${diagnostic(requirement.severity)}`,
        );
    }
  }
  const profileId =
    values.profile ??
    new Map(
      registry.routes.map((route) => [
        requiredField(route, "skill"),
        requiredField(route, "profile"),
      ]),
    ).get(values.skill!);
  if (profileId === undefined)
    throw new Error(
      `no capability profile route for skill ${diagnostic(values.skill)}`,
    );
  const profile = registry.profiles[profileId];
  if (!profile)
    throw new Error(`unknown capability profile: ${diagnostic(profileId)}`);
  const explicitProfile = values["codex-config-profile"];
  let profileLayer: string | undefined;
  if (explicitProfile !== undefined && values.config === undefined) {
    if (!/^[A-Za-z0-9_-]+$/u.test(explicitProfile))
      throw new Error(
        `invalid config profile name ${diagnostic(explicitProfile)}; pass a plain name such as 'work'`,
      );
    const candidate = appendConfigPath(
      codexHome,
      `${explicitProfile}.config.toml`,
    );
    if (metadata(candidate)?.isFile()) profileLayer = candidate;
  }
  let discovery: Table | null = null;
  const layers: Layer[] = [];
  if (values.config !== undefined) {
    for (const file of values.config) {
      const normalized = normalizePath(file);
      layers.push({ path: normalized, config: readToml(normalized) });
    }
  } else {
    const systemConfig = windows
      ? appendConfigPath(
          environmentValue("ProgramData") ?? "C:\\ProgramData",
          "OpenAI/Codex/config.toml",
        )
      : "/etc/codex/config.toml";
    for (const file of [
      systemConfig,
      defaultConfig,
      ...(profileLayer ? [profileLayer] : []),
    ])
      layers.push({ path: file, config: readToml(file) });
    const cwd = resolveWorkingDirectory(path(values.cwd ?? "."));
    if (!metadata(cwd)?.isDirectory())
      throw new Error(`cwd must be a directory, got ${diagnostic(cwd)}`);
    const configuredMarkers = layered(
      layers.toReversed(),
      "project_root_markers",
    );
    const markers = configuredMarkers ? configuredMarkers.value : [".git"];
    if (
      !Array.isArray(markers) ||
      markers.some((marker) => typeof marker !== "string")
    )
      throw new Error("project_root_markers must be an array of strings");
    let root = cwd;
    if (markers.length) {
      for (const candidate of projectAncestors(cwd)) {
        if (
          markers.some((marker) =>
            metadata(
              windows
                ? windowsJoin(candidate, marker)
                : isAbsolute(marker)
                  ? marker
                  : appendConfigPath(candidate, marker),
            ),
          )
        ) {
          root = candidate;
          break;
        }
      }
    }
    let trust: string | null = null;
    for (const layer of layers.toReversed()) {
      if (!isTable(layer.config.projects)) continue;
      let project = layer.config.projects[root];
      if (!isTable(project) && windows) {
        const files = windowsFiles();
        const rootIdentity = files.identity(encodePath(root));
        project = Object.entries(layer.config.projects).find(([name]) => {
          try {
            const identity = files.identity(encodePath(name));
            return (
              identity.volume === rootIdentity.volume &&
              identity.fileId.equals(rootIdentity.fileId)
            );
          } catch {
            // Unavailable saved projects do not affect trust for this directory.
            return false;
          }
        })?.[1];
      }
      if (isTable(project) && typeof project.trust_level === "string") {
        trust = project.trust_level;
        break;
      }
    }
    discovery = {
      cwd,
      project_root: root,
      project_trust_level: trust,
      project_layers_loaded: trust === "trusted",
    };
    if (trust === "trusted") {
      let directory = root;
      for (const component of [
        "",
        ...relative(root, cwd).split(sep).filter(Boolean),
      ]) {
        directory = join(directory, component);
        const file = join(directory, ".codex/config.toml");
        const {
          profile: _profile,
          profiles: _profiles,
          ...config
        } = readToml(file);
        layers.push({ path: file, config });
      }
    }
  }
  const configProfile =
    explicitProfile ?? layered(layers.toReversed(), "profile")?.value;
  if (configProfile !== undefined && typeof configProfile !== "string")
    throw new Error("profile must be a string");
  if (explicitProfile === undefined && configProfile !== undefined) {
    const selected = layers.flatMap(({ config }) =>
      isTable(config.profiles) &&
      Object.hasOwn(config.profiles, configProfile as string)
        ? [config.profiles[configProfile as string]]
        : [],
    );
    if (!selected.length)
      throw new Error(`config profile ${diagnostic(configProfile)} not found`);
    if (selected.some((item) => !isTable(item)))
      throw new Error(
        `config profile ${diagnostic(configProfile)} must be a table`,
      );
  }
  const views = configViews(
    layers,
    explicitProfile === undefined
      ? (configProfile as string | undefined)
      : undefined,
  );
  const effective = assignments(
    values["effective-config"] ?? [],
    effectiveValue,
  );
  const runtime = assignments(values["runtime-check"] ?? [], booleanValue);
  const available = values["available-plugin-skill"];
  for (const skill of available ?? [])
    if (skill.includes(":"))
      throw new Error(
        `expected plugin-local skill name, got ${diagnostic(skill)}; omit the plugin prefix`,
      );
  const configValue = (key: string, fallback?: Value): Value | undefined => {
    if (Object.hasOwn(effective, key))
      return { value: effective[key], source: "effective-config" };
    return layered(views, key) ?? fallback;
  };
  const owner = values["multi-agent-runtime-owner"];
  const version = values["multi-agent-runtime-version"];
  const provenance = values["multi-agent-runtime-provenance"] as
    string | undefined;
  const capText = values["multi-agent-session-cap"];
  const cap = capText === undefined ? undefined : BigInt(capText);
  const runtimeFacts =
    owner !== undefined || version !== undefined || cap !== undefined;
  if (runtimeFacts && provenance === undefined)
    throw new Error(
      "explicit multi-agent runtime facts require --multi-agent-runtime-provenance",
    );
  if (!runtimeFacts && provenance !== undefined)
    throw new Error(
      "--multi-agent-runtime-provenance requires an explicit runtime owner, version, or cap",
    );
  if (owner === "codex-bridge" && provenance !== "verified-bridge")
    throw new Error(
      "codex-bridge ownership requires --multi-agent-runtime-provenance verified-bridge",
    );
  if (owner === "native" && provenance === "verified-bridge")
    throw new Error("native ownership cannot use verified-bridge provenance");
  const feature = v2Setting(views, effective);
  const activeVersion =
    version ??
    (feature
      ? feature.value
        ? "v2"
        : "v1"
      : owner === "codex-bridge"
        ? "v2"
        : "unknown");
  const activeOwner = owner ?? (feature ? "native" : "unknown");
  if (activeOwner === "codex-bridge" && activeVersion !== "v2")
    throw new Error(
      "codex-bridge ownership requires multi-agent runtime version v2",
    );
  if (cap !== undefined && activeVersion !== "v2")
    throw new Error("--multi-agent-session-cap is valid only for a V2 runtime");
  const validateMultiAgentConfig = requiresMultiAgent(profile, capabilities);
  const bridgeCap = configValue("multiagent_config.max_concurrency");
  if (
    bridgeCap &&
    activeOwner !== "codex-bridge" &&
    (runtimeFacts || validateMultiAgentConfig)
  )
    throw new Error(
      "multiagent_config.max_concurrency does not prove bridge ownership; pass --multi-agent-runtime-owner codex-bridge only when the active runtime is verified as bridge-managed",
    );
  if (bridgeCap && cap !== undefined && !compare(bridgeCap.value, "==", cap))
    throw new Error(
      `conflicting bridge concurrency facts: multiagent_config.max_concurrency from ${bridgeCap.source} is ${diagnostic(bridgeCap.value)}, but --multi-agent-session-cap is ${cap}`,
    );
  const threads = configValue("agents.max_threads");
  if (activeOwner !== "codex-bridge" && feature?.value && threads)
    throw new Error(
      "agents.max_threads cannot be set when multi_agent_v2 is enabled",
    );
  const context: Context = {
    mode:
      activeVersion === "v1"
        ? "v1"
        : activeVersion === "v2" && activeOwner === "codex-bridge"
          ? "bridge-v2"
          : activeVersion === "v2" && activeOwner === "native"
            ? "v2"
            : "unknown",
    owner: activeOwner,
    owner_source: owner ? "runtime-fact" : (feature?.source ?? null),
    version: activeVersion,
    version_source: version
      ? "runtime-fact"
      : (feature?.source ??
        (owner === "codex-bridge" ? "runtime-owner" : null)),
    runtime_provenance: provenance ?? null,
    config_v2_enabled: Boolean(feature?.value),
    agent_max_threads_configured: threads !== undefined,
    agent_max_threads: threads?.value ?? null,
    agent_max_threads_source: threads?.source ?? null,
  };
  const results = profile.requirements
    .filter(
      (requirement) =>
        !requirement.modes?.length || requirement.modes.includes(context.mode),
    )
    .map((requirement): Table => {
      const capability = capabilities[requirement.capability];
      const kind = requiredField(capability, "kind");
      const result = {
        capability: requirement.capability,
        severity: requirement.severity,
        reason: requiredField(requirement, "reason"),
      };
      if (kind === "runtime") {
        const check = requiredField(capability, "check");
        return Object.hasOwn(runtime, check)
          ? {
              ...result,
              status: runtime[check] ? "pass" : "fail",
              actual: runtime[check],
              check,
            }
          : { ...result, status: "unknown", check };
      }
      if (kind === "multi_agent_mode") {
        const actual = { owner: context.owner, version: context.version };
        const expected = {
          owner: requiredField(capability, "owner"),
          version: requiredField(capability, "version"),
        };
        return {
          ...result,
          status: Object.values(actual).includes("unknown")
            ? "unknown"
            : isDeepStrictEqual(actual, expected)
              ? "pass"
              : "fail",
          ...(Object.values(actual).includes("unknown")
            ? { check: "active_multi_agent_mode" }
            : {}),
          actual,
          expected,
        };
      }
      if (kind === "plugin_skills") {
        const skills = requiredField(capability, "required");
        const required = skills.map(
          (skill) => `${requiredField(capability, "plugin")}:${skill}`,
        );
        const unavailable = skills
          .filter((skill) => !available?.includes(skill))
          .map((skill) => `${capability.plugin}:${skill}`);
        return available === undefined
          ? {
              ...result,
              status: "unknown",
              check: "available_plugin_skills",
              required,
            }
          : {
              ...result,
              status: unavailable.length ? "fail" : "pass",
              unavailable,
              required,
            };
      }
      if (kind === "multi_agent_capacity") {
        if (context.mode === "unknown")
          return {
            ...result,
            status: "unknown",
            check: "active_multi_agent_mode",
          };
        let key: string;
        let selected: Value | undefined;
        if (context.mode === "v1") {
          key = "agents.max_threads";
          selected = configValue(
            key,
            Object.hasOwn(capability, "v1_default")
              ? { value: capability.v1_default, source: "documented-default" }
              : undefined,
          );
        } else if (cap !== undefined) {
          key = "runtime.multi_agent.session_cap";
          selected = { value: cap, source: "runtime-fact" };
        } else if (context.owner === "codex-bridge") {
          key = "multiagent_config.max_concurrency";
          selected = configValue(key);
        } else if (context.owner === "native" && context.config_v2_enabled) {
          key = "features.multi_agent_v2.max_concurrent_threads_per_session";
          selected = configValue(key, {
            value: 4n,
            source: "documented-default",
          });
        } else {
          key = "runtime.multi_agent.session_cap";
          selected = undefined;
        }
        if (!selected)
          return {
            ...result,
            status: "unknown",
            path: key,
            multi_agent_mode: context.mode,
          };
        const actual =
          context.mode !== "v1" && typeof selected.value === "bigint"
            ? selected.value - 1n
            : selected.value;
        const op = requiredField(capability, "op");
        const value = requiredField(capability, "value");
        return {
          ...result,
          status: compare(actual, op, value) ? "pass" : "fail",
          path: key,
          actual,
          configured_value: selected.value,
          expected: { op, value },
          source: selected.source,
          multi_agent_mode: context.mode,
        };
      }
      const key = requiredField(capability, "path");
      const selected =
        typeof key === "string"
          ? configValue(
              key,
              kind !== "config_absent" && Object.hasOwn(capability, "default")
                ? { value: capability.default, source: "documented-default" }
                : undefined,
            )
          : undefined;
      if (kind === "config_absent")
        return {
          ...result,
          status: selected ? "fail" : "pass",
          path: key,
          ...(selected
            ? { actual: selected.value, source: selected.source }
            : {}),
          expected: "unset",
        };
      return selected
        ? {
            ...result,
            status: compare(
              selected.value,
              requiredField(capability, "op"),
              requiredField(capability, "value"),
            )
              ? "pass"
              : "fail",
            path: key,
            actual: selected.value,
            expected: { op: capability.op, value: capability.value },
            source: selected.source,
          }
        : { ...result, status: "unknown", path: key };
    });
  const failed = results.filter((item) => item.status === "fail");
  const unknown = results.filter((item) => item.status === "unknown");
  return {
    version: requiredField(registry, "version"),
    profile: profileId,
    description: requiredField(profile, "description"),
    config_resolution: discovery ? "cwd-discovery" : "manual-layers",
    user_config_path: discovery ? (profileLayer ?? defaultConfig) : null,
    config_paths: layers.map((layer) => layer.path),
    config_discovery: discovery,
    config_profile: configProfile ?? null,
    config_profile_path: profileLayer ?? null,
    multi_agent_mode: context.mode,
    multi_agent_context: context,
    status: failed.some((item) => item.severity === "block")
      ? "blocked"
      : unknown.some((item) => item.severity === "block")
        ? "incomplete"
        : "ready",
    results,
    failed,
    unknown,
    remediation: remediation(profile, context),
  };
}

function expandOptionPrefixes(args: string[]): string[] {
  const names = [...optionNames, ...repeatedOptions, "help"];
  let terminated = false;
  return args.map((argument) => {
    if (argument === "--") terminated = true;
    if (terminated || !argument.startsWith("--")) return argument;
    const separator = argument.indexOf("=");
    const name = argument.slice(2, separator < 0 ? undefined : separator);
    if (names.includes(name)) return argument;
    const matches = names.filter((option) => option.startsWith(name));
    if (matches.length > 1)
      throw new Error(
        `ambiguous option ${diagnostic(`--${name}`)}: ${matches.map((option) => `--${option}`).join(", ")}`,
      );
    return matches.length === 1
      ? `--${matches[0]}${separator < 0 ? "" : argument.slice(separator)}`
      : argument;
  });
}

export function configPreflightCommand(args: string[]): number {
  let values: Record<string, string | string[] | boolean | undefined>;
  try {
    ({ values } = parseArgs({
      args: expandOptionPrefixes(args),
      options: {
        ...Object.fromEntries(
          optionNames.map((name) => [name, { type: "string" as const }]),
        ),
        ...Object.fromEntries(
          repeatedOptions.map((name) => [
            name,
            { type: "string" as const, multiple: true },
          ]),
        ),
        help: { type: "boolean", short: "h" },
      },
    }));
    if (values.help) {
      console.log(
        "Usage: launch_codex_security_mcp[.cmd] --helper config-preflight (--profile ID | --skill ID) [options]\n\nEvaluate Codex Security capability profiles against the current Codex setup.\n\nOptions:\n" +
          [...optionNames, ...repeatedOptions]
            .map((name) => {
              const [metavar, description] = optionHelp[name];
              const value = choices[name]?.join(",");
              return `  --${name} ${value ? `{${value}}` : metavar}${repeatedOptions.includes(name as (typeof repeatedOptions)[number]) ? " (repeatable)" : ""}\n      ${description}`;
            })
            .join("\n") +
          "\n  -h, --help\n      Show this help message and exit.",
      );
      return 0;
    }
    if ((values.profile === undefined) === (values.skill === undefined))
      throw new Error("specify exactly one of --profile or --skill");
    for (const [key, allowed] of Object.entries(choices))
      if (values[key] !== undefined && !allowed.includes(values[key] as string))
        throw new Error(`--${key} must be one of: ${allowed.join(", ")}`);
    const cap = values["multi-agent-session-cap"] as string | undefined;
    if (
      cap !== undefined &&
      (!/^[+]?\d+$/u.test(cap.trim()) || BigInt(cap) < 1n)
    )
      throw new Error(
        "--multi-agent-session-cap must be a positive ASCII decimal integer (optional leading +)",
      );
  } catch (error) {
    console.error(
      escapeControls(error instanceof Error ? error.message : String(error)),
    );
    return 2;
  }
  try {
    const result = evaluate(values as Options);
    printJson(result);
    return result.status === "blocked"
      ? 1
      : result.status === "incomplete"
        ? 2
        : 0;
  } catch (error) {
    printJson({
      status: "error",
      error: error instanceof Error ? error.message : String(error),
    });
    return 2;
  }
}
