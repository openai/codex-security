
import type { AgentType, McpServerConfig } from "add-mcp";
import { existsSync } from "node:fs";
import {
  lstat,
  mkdir,
  readFile,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { splitCommand } from "./command-words.js";
import { isRecord } from "./record.js";
import { isWithin } from "./trusted-executable.js";

// These CLI aliases are accepted by add-mcp in addition to its exported agent IDs.
const agentAliases: Readonly<Record<string, AgentType>> = {
  "cline-vscode": "cline",
  codeium: "windsurf",
  cascade: "windsurf",
  droid: "factory-droid",
  factory: "factory-droid",
  gemini: "gemini-cli",
  "github-copilot": "vscode",
  grok: "grok-build",
  "hermes-agent": "hermes",
  kilo: "kilo-code",
  kilocode: "kilo-code",
  kimi: "kimi-code",
  kiro: "kiro-cli",
  mastra: "mastracode",
  "pi-agent": "pi",
};

type Launcher = {
  command?: string | undefined;
  exec?: string | undefined;
  package?: string | undefined;
  arg?: string[] | undefined;
};

function mcpServerConfig(
  options: Launcher,
  defaultCommand: string,
): McpServerConfig {
  const { command, exec, package: pkg, arg = [] } = options;
  if ([command, exec, pkg].filter((value) => value !== undefined).length > 1)
    throw new Error("Choose one of --exec, --package or --command.");
  if (exec !== undefined) return { command: exec, args: arg };
  if (pkg !== undefined)
    return { command: "npx", args: ["--yes", "--", pkg, ...arg] };
  if (arg.length) throw new Error("Use --arg with --exec or --package.");
  const value = (command ?? defaultCommand).trim();
  if (!value) throw new Error("--command requires a launcher.");
  if (/^https?:\/\//iu.test(value)) return { url: value, type: "http" };
  // Preserve an existing literal path with spaces. Otherwise a path starts
  // a command line and can be followed by positional arguments or flags.
  const isPath = /^(?:\/|~(?:\/|$)|\.{1,2}\/|[A-Za-z]:[\\/]|\\\\)/u.test(value);
  const argsAt = isPath ? value.search(/\s/u) : 0;
  if (argsAt === -1 || (isPath && existsSync(value)))
    return { command: value, args: [] };
  const words = value.slice(argsAt).trim();
  // Quotes group launcher words. Keep backslashes literal, including in
  // unquoted Windows paths that occur alongside a quoted argument.
  const tokens = splitCommand(words, "literal");
  if (!tokens?.length)
    throw new Error(
      "Invalid --command quoting. Use --exec and --arg for literal values.",
    );
  return isPath
    ? { command: value.slice(0, argsAt), args: tokens }
    : { command: tokens[0]!, args: tokens.slice(1) };
}

async function ampSettings(
  path: string,
  cliName: string,
  config: McpServerConfig,
) {
  const text = await readFile(path, "utf8").catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
      return "{}";
    },
  );
  const settings: unknown = JSON.parse(text);
  if (!isRecord(settings) || !isRecord(settings["amp.mcpServers"] ?? {}))
    throw new Error(`Invalid Amp settings in ${path}.`);
  const servers = (settings["amp.mcpServers"] ?? {}) as Record<string, unknown>;
  settings["amp.mcpServers"] = {
    ...servers,
    [cliName]: config.url ? { url: config.url } : config,
  };
  return JSON.stringify(settings, null, 2) + "\n";
}

async function checkProjectConfig(root: string, file: string) {
  if (!isWithin(root, file))
    throw new Error(`Project configuration must stay inside ${root}: ${file}`);
  for (let path = file; path !== root; path = dirname(path)) {
    let entry = await lstat(path).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
    });
    if (entry?.isSymbolicLink()) {
      const target = await realpath(path);
      if (!isWithin(root, target))
        throw new Error(
          `Project configuration resolves outside ${root}: ${file}`,
        );
      if (path === file) entry = await stat(target);
    }
    if (path === file && entry && (!entry.isFile() || entry.nlink !== 1))
      throw new Error(
        `Project configuration must be a regular file with one link: ${path}`,
      );
  }
}

export async function registerMcp(
  cliName: string,
  options: Launcher & {
    agent?: string[] | undefined;
    all?: boolean | undefined;
  },
  defaultCommand: string,
  local: boolean,
) {
  const requested = options.agent ?? [];
  const config = mcpServerConfig(options, defaultCommand);
  if (options.all && requested.length)
    throw new Error("Choose --all or --agent NAME.");
  // Import from the SDK installation. Never resolve or launch a package manager
  // or installer from the project being configured.
  const {
    agents,
    getAgentTypes,
    detectGlobalAgents,
    detectProjectAgents,
    upsertServer,
  } = await import("add-mcp");
  const cwd = await realpath(process.cwd());
  const all = getAgentTypes();
  const targets = new Set<AgentType>();
  const ampDir = join(homedir(), ".config", "amp");
  let amp = false;
  if (requested.length) {
    for (const target of requested) {
      const key = target.toLowerCase();
      if (key === "amp") {
        if (local) throw new Error("Amp supports only --scope user.");
        amp = true;
        continue;
      }
      const type =
        all.find((type) => type === key) ??
        (Object.hasOwn(agentAliases, key) ? agentAliases[key] : undefined);
      if (!type)
        throw new Error(
          `Unknown MCP agent: ${target}. Available agents: ${[...all, "amp"].join(", ")}.`,
        );
      targets.add(type);
    }
  } else {
    const candidates = new Set(
      options.all
        ? all
        : local
          ? detectProjectAgents(cwd)
          : await detectGlobalAgents(),
    );
    // add-mcp detects ~/.codex even when its writer uses a custom CODEX_HOME.
    if (!local && !options.all && process.env["CODEX_HOME"]) {
      if (existsSync(dirname(agents.codex.configPath))) candidates.add("codex");
      else candidates.delete("codex");
    }
    for (const type of candidates) {
      if (
        (!local || agents[type].localConfigPath) &&
        agents[type].supportedTransports.includes(config.type ?? "stdio")
      )
        targets.add(type);
    }
    amp = !local && (options.all === true || existsSync(ampDir));
    if (!targets.size && !amp)
      throw new Error(
        `No compatible MCP clients detected in ${local ? "project" : "user"} scope. Select --agent NAME or use --all to register every compatible client in this scope.`,
      );
  }
  for (const type of targets) {
    const agent = agents[type];
    if (!agent.supportedTransports.includes(config.type ?? "stdio"))
      throw new Error(
        `${agent.displayName} does not support this MCP transport.`,
      );
    if (local) {
      if (!agent.localConfigPath)
        throw new Error(
          `${agent.displayName} does not support project registration.`,
        );
      const path =
        agent.resolveConfigPath?.(agent, { local, cwd }) ??
        join(cwd, agent.localConfigPath);
      await checkProjectConfig(cwd, path);
    }
  }
  const ampPath = join(ampDir, "settings.json");
  const settings = amp
    ? await ampSettings(ampPath, cliName, config)
    : undefined;
  const installed = [];
  for (const type of targets) {
    const result = upsertServer(type, cliName, config, { local, cwd });
    if (!result.success)
      throw new Error(`${agents[type].displayName}: ${result.error}`);
    installed.push(agents[type].displayName);
  }
  if (settings !== undefined) {
    await mkdir(ampDir, { recursive: true });
    await writeFile(ampPath, settings, { mode: 0o600 });
    installed.push("Amp");
  }
  const command =
    options.command ??
    (config.url ||
      [config.command!, ...(config.args ?? [])]
        .map((word) =>
          word && !/\s|["']/u.test(word) ? word : JSON.stringify(word),
        )
        .join(" "));
  return { command, agents: installed };
}
