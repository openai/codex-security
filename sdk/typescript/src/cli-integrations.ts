import { Cli, Help, SyncMcp, SyncSkills, z } from "incur";
import { execFile } from "node:child_process";
import { dirname, join } from "node:path";
import { parseArgs, promisify } from "node:util";

const cliName = "codex-security";
const agent = z
  .array(z.string().min(1))
  .optional()
  .describe("Target a specific agent. Repeat to select more agents.");
const noGlobal = z
  .boolean()
  .optional()
  .describe("Install to the current project instead of the user profile.");
const depth = z
  .number()
  .int()
  .nonnegative()
  .optional()
  .describe("Grouping depth for generated skill files (default: 1).");
const groupOptions = {
  "mcp add": z.object({
    agent,
    command: z
      .string()
      .min(1)
      .optional()
      .describe("Override the command agents will run."),
    noGlobal,
  }),
  "mcp doctor": z.object({}),
  "skills add": z.object({ depth, noGlobal }),
  "skills list": z.object({}),
};
const groupDescriptions = {
  mcp: "Register the read-only info tool or check its server startup and catalog.",
  skills:
    "Manage generated CLI command guidance. The Codex Security plugin provides scan and remediation workflows.",
};
const descriptions: Record<keyof typeof groupOptions, string> = {
  "mcp add":
    "Register this CLI’s read-only info tool with an agent. Registers in the user profile by default; Amp supports only user registration.",
  "mcp doctor":
    "Check the current CLI's MCP startup and tool catalog. Connect from your client to test its registered launcher.",
  "skills add":
    "Install generated CLI command guidance in the user profile or current project.",
  "skills list":
    "List generated CLI guidance and whether each skill is installed.",
};
const outputOptions = {
  help: { type: "boolean", short: "h" },
  schema: { type: "boolean" },
  version: { type: "boolean" },
  llms: { type: "boolean" },
  "llms-full": { type: "boolean" },
  json: { type: "boolean" },
  format: { type: "string" },
  "full-output": { type: "boolean" },
  "filter-output": { type: "string" },
  "token-count": { type: "boolean" },
  "token-limit": { type: "string" },
  "token-offset": { type: "string" },
} as const;

/** Incur's built-in installers precede schema and version dispatch and skip option validation. */
export async function serveIntegration(
  argv: string[],
  cli: Cli.Cli,
  description: string,
  defaultMcpCommand: string,
  output: Cli.serve.Options,
): Promise<boolean> {
  if (
    (argv.includes("--llms") || argv.includes("--llms-full")) &&
    !argv.some((arg) => ["--help", "-h", "--version", "--schema"].includes(arg))
  ) {
    // Incur renders manifests from registered commands before it dispatches its
    // built-ins. Register the integration descriptions for this read only.
    for (const group of ["mcp", "skills"] as const) {
      const section = Cli.create(group, {
        description: groupDescriptions[group],
        aliases: group === "skills" ? ["skill"] : [],
      });
      for (const [path, options] of Object.entries(groupOptions)) {
        const [parent, verb] = path.split(" ");
        if (parent === group)
          section.command(verb!, {
            description: descriptions[path as keyof typeof groupOptions],
            options,
            aliases: path === "skills list" ? ["ls"] : [],
            run: () => undefined,
          });
      }
      cli.command(section);
    }
    cli.command("completions", {
      description: "Generate a shell completion script.",
      args: z.object({ shell: z.enum(["bash", "fish", "nushell", "zsh"]) }),
      run: () => undefined,
    });
    await cli.serve(
      argv.filter((arg) => arg !== "--update"),
      output,
    );
    return true;
  }
  if (!argv.some((arg) => arg === "skills" || arg === "skill" || arg === "mcp"))
    return false;
  // Recognize groups in the same position as Incur after removing its output controls.
  const { positionals } = parseArgs({
    args: argv,
    options: outputOptions,
    strict: false,
    allowPositionals: true,
  });
  const [first, second] =
    positionals[0] === cliName ? positionals.slice(1) : positionals;
  const group = first === "skill" ? "skills" : first;
  if (group !== "mcp" && group !== "skills") return false;
  const verb = group === "skills" && second === "ls" ? "list" : second;
  const name = `${group} ${verb}`;
  if (!verb) {
    const { values } = parseArgs({
      args: argv,
      options: outputOptions,
      allowPositionals: true,
    });
    if (values.version && !values.help) await cli.serve(["--version"], output);
    else {
      const commands = Object.entries(descriptions)
        .filter(([path]) => path.startsWith(group + " "))
        .map(([path, description]) => ({
          name: path.slice(group.length + 1),
          description,
        }));
      output.stdout?.(
        Help.formatRoot(`${cliName} ${group}`, {
          description: groupDescriptions[group],
          aliases: group === "skills" ? ["skill"] : [],
          commands,
        }) + "\n",
      );
    }
    return true;
  }
  // Preserve the built-in's suggestions without forwarding unrelated action flags.
  if (!Object.hasOwn(groupOptions, name)) {
    await cli.serve([group, verb, "--help"], output);
    return true;
  }
  const path = name as keyof typeof groupOptions;
  const {
    values,
    positionals: actual,
    tokens,
  } = parseArgs({
    args: argv,
    allowPositionals: true,
    tokens: true,
    options: {
      ...outputOptions,
      ...(verb === "add" ? { "no-global": { type: "boolean" as const } } : {}),
      ...(path === "skills add" ? { depth: { type: "string" as const } } : {}),
      ...(path === "mcp add"
        ? {
            agent: { type: "string" as const, multiple: true },
            command: { type: "string" as const, short: "c" },
          }
        : {}),
    },
  });
  if (actual.length !== (actual[0] === cliName ? 3 : 2))
    throw new Error(`Unexpected positional argument for ${name}.`);
  if (values.help) {
    output.stdout?.(
      Help.formatCommand(`${cliName} ${path}`, {
        description: descriptions[path],
        options: Object.keys(groupOptions[path].shape).length
          ? groupOptions[path]
          : undefined,
        alias: path === "mcp add" ? { command: "c" } : undefined,
        aliases: path === "skills list" ? ["ls"] : undefined,
        hideGlobalOptions: true,
      }) + "\n",
    );
    return true;
  }
  if (values.version) {
    await cli.serve(["--version"], output);
    return true;
  }
  // Let the ordinary formatter validate all output options before invoking a writer.
  const formatArgs = tokens.flatMap((token) =>
    token.kind === "option" &&
    Object.hasOwn(outputOptions, token.name) &&
    !["schema", "llms", "llms-full"].includes(token.name)
      ? [
          `--${token.name}`,
          ...(typeof token.value === "string" ? [token.value] : []),
        ]
      : [],
  );
  if (values.schema) {
    const schema = {
      options: z.toJSONSchema(groupOptions[path], { io: "input" }),
    };
    await Cli.create(`${cliName} ${group}`, { sync: false, update: false })
      .command(verb!, { run: () => schema })
      .serve([verb!, ...formatArgs], output);
    return true;
  }

  const local = groupOptions[path].parse({
    ...(values.agent === undefined ? {} : { agent: values.agent }),
    ...(values.command === undefined ? {} : { command: values.command }),
    ...(values.depth === undefined
      ? {}
      : {
          depth:
            typeof values.depth === "string" && values.depth.trim()
              ? Number(values.depth)
              : NaN,
        }),
    ...(values["no-global"] === undefined
      ? {}
      : { noGlobal: values["no-global"] }),
  });
  if (path === "mcp doctor") {
    await cli.serve([group, verb!, ...formatArgs], output);
    return true;
  }

  const commands = Cli.toCommands.get(cli)!;
  const project = "noGlobal" in local && local.noGlobal === true;
  const targets =
    "agent" in local && local.agent ? [...new Set(local.agent)] : undefined;
  if (path === "mcp add" && project && targets?.includes("amp")) {
    throw new Error(
      "The MCP installer can register Amp only in the user profile. For a project installation, select a project-capable client with --no-global --agent NAME.",
    );
  }
  const defaultProjectInstall =
    path === "mcp add" && project && !targets?.length;
  if (formatArgs.length === 0 && path !== "mcp add") {
    // Preserve the native terminal presentation. Rebuild options from parsed
    // values because the native installer does not understand every equals form.
    const nativeArgs = [group, verb!];
    if (project) nativeArgs.push("--no-global");
    if ("depth" in local && local.depth !== undefined)
      nativeArgs.push("--depth", String(local.depth));
    await cli.serve(nativeArgs, output);
    return true;
  }

  const render = Cli.create(`${cliName} ${group}`, {
    update: false,
    sync: false,
  }).command(verb!, {
    async run() {
      if (path === "skills list")
        return SyncSkills.list(cliName, commands, { description });
      if (path === "skills add") {
        const result = await SyncSkills.sync(cliName, commands, {
          global: !project,
          depth: "depth" in local ? local.depth : undefined,
          description,
        });
        return {
          skills: result.paths,
          ...(values["full-output"] ? { agents: result.agents } : {}),
        };
      }
      const command =
        ("command" in local ? local.command : undefined) ?? defaultMcpCommand;
      const result = defaultProjectInstall
        ? await registerProjectMcp(command)
        : await SyncMcp.register(cliName, {
            agents: targets,
            command,
            global: !project,
          });
      if (targets?.includes("amp") && !result.agents.includes("Amp"))
        throw new Error(
          "The Amp settings file could not be updated. Check its JSON and retry.",
        );

      if (formatArgs.length === 0)
        return [
          `✓ Registered ${cliName} as MCP server`,
          ...(result.agents.length
            ? [`  Agents: ${result.agents.join(", ")}`]
            : []),
        ].join("\n");
      return { name: cliName, ...result };
    },
  });
  await render.serve([verb!, ...formatArgs], output);
  return true;
}

// Incur also writes Amp's home settings after add-mcp finishes selecting
// project clients. Invoke only the project-capable installer in this case.
async function registerProjectMcp(
  command: string,
): Promise<SyncMcp.register.Result> {
  const args = ["add-mcp", command, "--name", cliName, "-y"];
  const userAgent = process.env["npm_config_user_agent"] ?? "";
  const npm = process.env["npm_execpath"];
  const runner = userAgent.startsWith("pnpm/")
    ? "pnpx"
    : userAgent.startsWith("bun/")
      ? "bunx"
      : "npx";
  let executable: string = runner;
  if (runner === "npx" && process.platform === "win32") {
    const npx =
      npm && /[\\/]npm-cli\.js$/iu.test(npm)
        ? join(dirname(npm), "npx-cli.js")
        : join(
            dirname(process.execPath),
            "node_modules",
            "npm",
            "bin",
            "npx-cli.js",
          );
    executable = process.execPath;
    args.unshift(npx);
  } else if (runner === "pnpx" && npm && /\.(?:c?js|mjs)$/iu.test(npm)) {
    executable = process.execPath;
    args.unshift(npm, "dlx");
  }
  const { stdout } = await promisify(execFile)(executable, args, {
    encoding: "utf8",
  });
  const agents = stdout.split("\n").flatMap((line) => {
    const match = /[✓✔]\s*([^:│┃|]+):/u.exec(line);
    return match ? [match[1]!.trim()] : [];
  });
  return { command, agents };
}
