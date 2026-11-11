import { Cli, Completions, Help, SyncSkills, z } from "incur";
import { parseArgs } from "node:util";
import { registerMcp } from "./cli-mcp.js";

const cliName = "codex-security";
export const completionShell = z.enum(["bash", "fish", "nushell", "zsh"]);
const depth = z
  .number()
  .int()
  .nonnegative()
  .optional()
  .describe("Grouping depth for generated skill files (default: 1).");
const noGlobal = z
  .boolean()
  .optional()
  .describe("Install to the current project instead of the user profile.");
const descriptions = {
  skills:
    "Manage generated CLI command guidance. The Codex Security plugin provides scan and remediation workflows.",
  mcp: "Register the read-only info tool or check its server startup and catalog.",
};

// Node's tokenizer rejects surplus positionals and missing values such as
// --command --no-global before an installer can consume the scope switch.
const boolean = { type: "boolean" } as const;
const string = { type: "string" } as const;
const formatOptions = {
  json: boolean,
  format: string,
  "full-output": boolean,
  "filter-output": string,
  "token-count": boolean,
  "token-limit": string,
  "token-offset": string,
};
const outputOptions = {
  ...formatOptions,
  help: { ...boolean, short: "h" },
  schema: boolean,
  version: boolean,
  llms: boolean,
  "llms-full": boolean,
};
const options = {
  ...outputOptions,
  depth: string,
  "no-global": boolean,
  command: { ...string, short: "c" },
  agent: { ...string, multiple: true },
} as const;

function integrationGroups(
  cli: Cli.Cli,
  cliOptions: Cli.create.Options,
  invocation?: { output: Cli.serve.Options; plain: boolean; full?: boolean },
) {
  const { output, plain, full } = invocation ?? {};
  const commands = Cli.toCommands.get(cli)!;
  const config = {
    sync: false,
    update: false,
    version: cliOptions.version,
  } as const;
  const prefix = invocation ? cliName + " " : "";
  async function builtin(args: string[]) {
    let text = "";
    await cli.serve(args, {
      ...output,
      stdout: (chunk) => {
        text += chunk;
      },
    });
    return text.trimEnd();
  }

  const skills = Cli.create(prefix + "skills", {
    ...config,
    description: descriptions.skills,
    aliases: ["skill"],
  })
    .command("add", {
      description:
        "Install generated CLI command guidance in the user profile or current project.",
      options: z.object({ depth, noGlobal }),
      async run({ options: { depth, noGlobal } }) {
        if (plain)
          return builtin([
            "skills",
            "add",
            ...(noGlobal ? ["--no-global"] : []),
            ...(depth === undefined ? [] : ["--depth", String(depth)]),
          ]);
        const result = await SyncSkills.sync(cliName, commands, {
          depth,
          global: !noGlobal,
          description: cliOptions.description,
        });
        return {
          skills: result.paths,
          ...(full ? { agents: result.agents } : {}),
        };
      },
    })
    .command("list", {
      aliases: ["ls"],
      description:
        "List generated CLI guidance for one grouping depth. Use the same depth as skills add to check an installation.",
      options: z.object({ depth }),
      async run({ options: { depth } }) {
        if (plain) {
          cliOptions.sync = { ...(cliOptions.sync || {}), depth };
          return `Skill grouping depth: ${depth ?? 1}\n${await builtin(["skills", "list"])}`;
        }
        return SyncSkills.list(cliName, commands, {
          depth,
          description: cliOptions.description,
        });
      },
    });
  const mcp = Cli.create(prefix + "mcp", {
    ...config,
    description: descriptions.mcp,
  })
    .command("doctor", {
      description:
        "Check the current CLI's MCP startup and tool catalog. Connect from your client to test its registered launcher.",
      run: async () => JSON.parse(await builtin(["mcp", "doctor", "--json"])),
    })
    .command("add", {
      description:
        "Register this CLI’s read-only info tool with an agent. Registers in the user profile by default; Amp supports only user registration.",
      options: z.object({
        agent: z
          .array(z.string().min(1))
          .optional()
          .describe("Target a specific agent. Repeat to select more agents."),
        command: z
          .string()
          .min(1)
          .optional()
          .describe("Override the command agents will run."),
        noGlobal,
      }),
      alias: { command: "c" },
      async run({ options }) {
        const agents = [...new Set(options.agent)];
        if (options.noGlobal && agents.includes("amp"))
          throw new Error(
            "The MCP installer can register Amp only in the user profile. For a project installation, select a project-capable client with --no-global --agent NAME.",
          );
        const launch = options.command ?? cliOptions.mcp!.command!;
        const result = await registerMcp(
          cliName,
          launch,
          agents,
          options.noGlobal === true,
        );
        if (plain)
          return [
            `✓ Registered ${cliName} as MCP server`,
            ...(result.agents.length
              ? [`  Agents: ${result.agents.join(", ")}`]
              : []),
          ].join("\n");
        return { name: cliName, ...result };
      },
    });
  if (!invocation) {
    cli
      .command(skills)
      .command(mcp)
      .command("completions", {
        description: "Generate a shell completion script.",
        args: z.object({ shell: completionShell }),
        run: () => undefined,
      });
    // Incur mounts aliases for leaf commands, but not for a whole group.
    commands.set("skill", { _alias: true, target: "skills" });
  }
  return { skills, mcp };
}

/** Complete shell words without dispatching or validating any command. */
export function completeCli(
  cli: Cli.Cli,
  cliOptions: Cli.create.Options,
  shell: z.infer<typeof completionShell>,
  argv: readonly string[],
) {
  const words = argv[0] === "--" ? argv.slice(1) : [...argv];
  if (words.length === 0)
    return [cliName, ...(cliOptions.aliases ?? [])]
      .map((name) => Completions.register(shell, name))
      .join("\n");
  const index = Number(process.env["_COMPLETE_INDEX"] ?? words.length - 1);
  if (!Number.isSafeInteger(index) || index < 0 || index > words.length)
    return "";
  integrationGroups(cli, cliOptions);
  const candidates = Completions.complete(
    Cli.toCommands.get(cli)!,
    undefined,
    words,
    index,
    {
      schema: z.object({
        format: z.enum(["toon", "json", "yaml", "md", "jsonl"]),
      }),
    },
  );
  return Completions.format(shell, candidates);
}

/** Incur dispatches its built-in writers before schema and version. Serve
 * ordinary command groups so its normal parser and metadata handling run first. */
export async function serveIntegration(
  argv: string[],
  cli: Cli.Cli,
  cliOptions: Cli.create.Options,
  output: Cli.serve.Options,
  command: string | undefined,
  literalArgs: readonly string[],
): Promise<boolean> {
  const manifest =
    (argv.includes("--llms") || argv.includes("--llms-full")) &&
    !argv.some((arg) =>
      ["--help", "-h", "--version", "--schema"].includes(arg),
    );
  const group = command === "skill" ? "skills" : command;
  const integration = group === "mcp" || group === "skills";
  if (!integration && !manifest && group !== "completions") return false;
  if (group === "completions") {
    const [, shell, ...extra] = [
      ...parseArgs({
        args: argv,
        options: outputOptions,
        allowPositionals: true,
      }).positionals,
      ...literalArgs,
    ];
    if (extra.length)
      throw new Error("Unexpected positional argument for completions.");
    if (shell !== undefined && !completionShell.safeParse(shell).success)
      throw new Error(
        `Unknown shell. Supported: ${completionShell.options.join(", ")}.`,
      );
    if (argv.includes("--schema") || argv.includes("--version")) {
      const section = Cli.create(cliName + " completions", {
        version: cliOptions.version,
        update: false,
        sync: false,
        args: z.object({ shell: completionShell }),
        run: () => undefined,
      });
      await section.serve(
        argv.filter((arg) => arg !== group && arg !== shell),
        output,
      );
      return true;
    }
    if (!manifest) {
      await cli.serve([...argv, ...literalArgs], output);
      return true;
    }
  }
  const { tokens, positionals, values } = parseArgs({
    args: argv,
    options,
    allowPositionals: true,
    tokens: true,
    strict: integration,
  });
  const plain = !Object.keys(formatOptions).some((key) =>
    Object.hasOwn(values, key),
  );
  const full = values["full-output"] === true;
  const { skills, mcp } = integrationGroups(
    cli,
    cliOptions,
    manifest ? undefined : { output, plain, full },
  );
  if (integration) {
    const section = group === "mcp" ? mcp : skills;
    const [, verb, ...extra] = positionals;
    if (literalArgs.length || extra.length)
      throw new Error(
        `Unexpected positional argument for ${group}${verb ? " " + verb : ""}.`,
      );
    if (verb && !Cli.toCommands.get(section)!.has(verb))
      throw new Error(
        `Unknown command ${group} ${verb}. Use codex-security ${group} --help.`,
      );
  }
  if (manifest) {
    // Put the mode first so a missing format/filter operand cannot consume it
    // and fall through to a command handler.
    const flag = argv.includes("--llms-full") ? "--llms-full" : "--llms";
    await cli.serve(
      [
        flag,
        ...argv.filter(
          (arg) => !["--llms", "--llms-full", "--update"].includes(arg),
        ),
      ],
      output,
    );
    return true;
  }
  if (!integration) return false;
  const section = group === "mcp" ? mcp : skills;
  const [, verb] = positionals;
  if (!verb && !values.version) {
    const invalid = tokens.find(
      (token) =>
        token.kind === "option" && !Object.hasOwn(outputOptions, token.name),
    );
    if (invalid?.kind === "option")
      throw new Error(`Unknown option for ${group}: ${invalid.rawName}`);
    const children = Array.from(Cli.toCommands.get(section)!).flatMap(
      ([name, entry]) =>
        "description" in entry
          ? [{ name, description: entry.description }]
          : [],
    );
    output.stdout?.(
      Help.formatRoot(`${cliName} ${group}`, {
        aliases: section === skills ? ["skill"] : [],
        description: descriptions[group],
        commands: children,
      }) + "\n",
    );
    return true;
  }
  // The public flag names a scope directly. Incur reserves --no-* for
  // negation; pass its schema's field name after Node tokenizes the CLI flag.
  const args = argv.slice();
  const groupToken = tokens.find((token) => token.kind === "positional")!;
  for (const token of tokens) {
    if (token.kind !== "option") continue;
    if (token.name === "depth" && !token.value?.trim())
      throw new Error("--depth requires a nonnegative integer.");
    if (token.name === "no-global") args[token.index] = "--noGlobal";
  }
  args.splice(groupToken.index, 1);
  await section.serve(args, output);
  return true;
}
