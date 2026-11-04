import { lstat, readlink, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, sep } from "node:path";
import { ConfigurationError } from "./errors.js";
import type { JsonObject } from "./config.js";
import { isRecord } from "./record.js";
import { enclosingGitWorktreeRoot } from "./targets.js";
import { isWithin } from "./trusted-executable.js";

export interface ProjectProviderRouting {
  field: string;
  paths: readonly string[];
}

// Native provider definitions own their endpoint, auth command, environment
// keys and headers. The built-in OpenAI routes also have standalone settings.
const routingKeys = new Set([
  "model_providers",
  "openai_base_url",
  "chatgpt_base_url",
]);

function providerRoutingField(
  config: JsonObject,
  prefix = "codex",
): string | undefined {
  for (const [name, value] of Object.entries(config)) {
    // Codex's -c parser splits at the first "=" and at literal dots in the
    // key. Quotes within that key are literal; the SDK leaves them intact.
    const [root = "", profile, setting] = name
      .split("=", 1)[0]!
      .trim()
      .split(".");
    if (routingKeys.has(root)) return `${prefix}.${root}`;
    if (prefix !== "codex" || root !== "profiles") continue;
    if (setting !== undefined) {
      if (routingKeys.has(setting))
        return `codex.profiles.${profile}.${setting}`;
      continue;
    }
    // A raw assignment can supply an entire profile through the key itself.
    if (name.includes("="))
      return profile === undefined
        ? "codex.profiles"
        : `codex.profiles.${profile}`;
    if (!isRecord(value)) continue;
    // Structured TOML tables retain literal names, including dots in a name.
    const profiles =
      profile === undefined
        ? Object.entries(value)
        : [[profile, value] as const];
    for (const [name, layer] of profiles) {
      if (!isRecord(layer)) continue;
      const field = providerRoutingField(layer, `codex.profiles.${name}`);
      if (field) return field;
    }
  }
  return undefined;
}

export async function projectFileProviderRouting(
  codex: JsonObject | undefined,
  path: string,
  canonical: string,
): Promise<ProjectProviderRouting | undefined> {
  const field = codex && providerRoutingField(codex);
  if (!field) return undefined;

  // Remember each traversed link while the file is loaded. SDK callers can
  // retain the parsed config after the original path is moved or removed.
  const paths = new Set([path, canonical]);
  const inspected = new Set<string>();
  const inspect = async (candidate: string): Promise<void> => {
    if (inspected.has(candidate)) return;
    inspected.add(candidate);
    const parent = dirname(candidate);
    if (parent === candidate) return;
    await inspect(parent);
    const entry = join(await realpath(parent), basename(candidate));
    if ((await lstat(entry)).isSymbolicLink()) {
      paths.add(entry);
      const target = await readlink(entry);
      await inspect(
        isAbsolute(target) ? target : `${dirname(entry)}${sep}${target}`,
      );
    }
  };
  await inspect(path);
  return { field, paths: [...paths] };
}

export async function requireTrustedProjectProvider(
  source: ProjectProviderRouting | undefined,
  repository: string,
  signal?: AbortSignal,
): Promise<void> {
  if (source === undefined) return;
  const directory = await realpath(repository);
  const root =
    (await enclosingGitWorktreeRoot(directory, signal, {
      requireIfPresent: true,
    })) ?? directory;
  requireOperatorProviderSource(source, root);
}

export function requireOperatorProviderSource(
  source: ProjectProviderRouting,
  root: string,
): void {
  if (source.paths.some((candidate) => isWithin(root, candidate))) {
    throw new ConfigurationError(
      `Remove ${source.field} from the checkout project file. Define it in an operator-controlled --config file outside the scanned checkout or pass it with --codex. Use codex.model_provider in the checkout to select a configured provider.`,
    );
  }
}
