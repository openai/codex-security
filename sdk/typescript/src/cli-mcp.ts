import type { AgentType, McpServerConfig } from "add-mcp";
import { SyncMcp } from "incur";
import { lstat, realpath, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
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

function mcpServerConfig(launch: string): McpServerConfig {
  const value = launch.trim();
  if (!value) throw new Error("--command requires a launcher.");
  if (/^https?:\/\//u.test(value)) return { url: value, type: "http" };
  // Preserve add-mcp's handling of literal executable paths, command lines,
  // and bare npm package specifiers.
  if (/^(?:\/|~(?:\/|$)|\.{1,2}\/|[A-Za-z]:[\\/]|\\\\)/u.test(value))
    return { command: value, args: [] };
  const [command, ...args] = value.split(" ");
  return args.length
    ? { command: command!, args }
    : { command: "npx", args: ["-y", value] };
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
          `Project configuration resolves outside ${root}: ${path}`,
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
  command: string,
  requested: string[],
  local: boolean,
): Promise<SyncMcp.register.Result> {
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
  if (requested.length) {
    for (const target of requested) {
      if (target === "amp") continue;
      const key = target.toLowerCase();
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
    const detected = local
      ? detectProjectAgents(cwd)
      : await detectGlobalAgents();
    for (const type of detected.length
      ? detected
      : all.filter((type) => !local || agents[type].localConfigPath))
      targets.add(type);
  }
  const config = mcpServerConfig(command);
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
  const installed = [];
  for (const type of targets) {
    const result = upsertServer(type, cliName, config, { local, cwd });
    if (!result.success)
      throw new Error(`${agents[type].displayName}: ${result.error}`);
    installed.push(agents[type].displayName);
  }
  if (!local && (!requested.length || requested.includes("amp"))) {
    // With Amp as the sole target Incur writes its settings directly.
    const amp = await SyncMcp.register(cliName, { agents: ["amp"], command });
    if (requested.includes("amp") && !amp.agents.length)
      throw new Error(
        "The Amp settings file could not be updated. Check its JSON and retry.",
      );
    installed.push(...amp.agents);
  }
  return { command, agents: installed };
}
