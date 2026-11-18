import { Cli, z } from "incur";
import { resolveConfigPath } from "./config-path.js";
import { CodexSecurityError } from "./errors.js";
import { enclosingGitWorktreeRoot, normalizeRepository } from "./targets.js";
import {
  runLocalStackInvestigation,
  stackInvestigationPrompt,
} from "./dependency-stack-launcher.js";
import { stackInvestigationReportSchema } from "./dependency-stack-assessment.js";
import { executeStackRun, stackRunTools } from "./dependency-stack-run.js";

export interface DependencyAgentRequest {
  prompt: string;
  directory: string;
  signal: AbortSignal;
  model?: string;
  effort?: string;
  codex?: string[];
  config?: string;
  readOnly?: boolean;
}

export interface DependencyCliContext {
  currentDirectory(): string;
  recordsInput: AsyncIterable<Buffer | string>;
  withSignal<T>(run: (signal: AbortSignal) => Promise<T>): Promise<T>;
  runAgent(request: DependencyAgentRequest): Promise<string>;
}

export function createExploitabilityCli(context: DependencyCliContext) {
  const flag = z.string().trim().min(1);
  const group = Cli.create("exploitability", {
    description: "Investigate dependency vulnerabilities in a repository.",
  });
  group.command("check", {
    description:
      "Investigate one CVE against supplied source, sink and stack evidence.",
    alias: { config: "c" },
    destructive: false,
    mcp: false,
    args: z.object({
      subject: flag.describe("The CVE named in the supplied advisory."),
    }),
    options: z.object({
      sources: flag
        .optional()
        .describe("Path to the supplied source endpoint document."),
      sinks: flag
        .optional()
        .describe("Path to the sink endpoints and frozen advisory."),
      stacks: flag
        .optional()
        .describe("Path to the observed stacks and target revision."),
      model: flag.optional().describe("Investigator model."),
      effort: flag.optional().describe("Investigator reasoning effort."),
      config: flag
        .optional()
        .describe("Codex Security project configuration file."),
      codex: z
        .array(flag)
        .default([])
        .describe("Pass a Codex model or provider configuration override."),
    }),
    output: stackInvestigationReportSchema,
    async run({ args, options }) {
      const { sources, sinks, stacks } = options;
      if (sources === undefined || sinks === undefined || stacks === undefined)
        throw new CodexSecurityError(
          "Supply --sources, --sinks and --stacks together for one CVE.",
        );
      if (!/^CVE-\d{4}-\d{4,}$/iu.test(args.subject))
        throw new CodexSecurityError(
          "Captured stack investigations require one CVE ID with its advisory in --sinks.",
        );
      const cwd = context.currentDirectory();
      return context.withSignal(async (signal) => {
        const dir = await normalizeRepository(cwd, signal);
        const repo = await enclosingGitWorktreeRoot(dir, signal, {
          requireIfPresent: true,
        });
        if (!repo)
          throw new CodexSecurityError(
            "A captured stack investigation requires a Git checkout at the target revision.",
          );
        return runLocalStackInvestigation({
          cve: args.subject.toUpperCase(),
          repository: repo,
          signal,
          sourcesPath: resolveConfigPath(cwd, sources),
          sinksPath: resolveConfigPath(cwd, sinks),
          stacksPath: resolveConfigPath(cwd, stacks),
          async investigate(session) {
            await context.runAgent({
              directory: session.directory,
              signal,
              prompt: await stackInvestigationPrompt(session),
              model: options.model,
              effort: options.effort,
              config: options.config,
              codex: options.codex,
            });
            return 0;
          },
        });
      });
    },
  });
  const run = Cli.create("run", {
    description:
      "Read and update a single investigation. Each operation returns JSON.",
  });
  const pathOptions = z.object({
    state: flag.describe("Path to the investigation SQLite file."),
  });
  for (const tool of stackRunTools) {
    const options =
      tool.name === "init"
        ? pathOptions.extend({
            inputs: flag.describe(
              "Directory containing the prepared input packet.",
            ),
            repo: flag.describe("Target Git checkout."),
          })
        : tool.inputSchema
          ? pathOptions.extend({
              jsonStdin: z
                .boolean()
                .describe("Read one JSON document from standard input."),
            })
          : pathOptions;
    run.command(tool.name, {
      description: tool.description,
      format: "json",
      options,
      mcp: false,
      async run({ options: opts }) {
        return context.withSignal(async (signal) => {
          const dir = context.currentDirectory();
          let input: unknown;
          if (tool.inputSchema) {
            if (!("jsonStdin" in opts && opts.jsonStdin))
              throw new CodexSecurityError(
                "Use --json-stdin to provide input for " + tool.name + ".",
              );
            const chunks: Buffer[] = [];
            for await (const data of context.recordsInput)
              chunks.push(Buffer.from(data));
            input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          }
          return executeStackRun(tool.name, {
            state: resolveConfigPath(dir, opts.state),
            signal,
            input,
            ...("inputs" in opts &&
              typeof opts.inputs === "string" && {
                inputs: resolveConfigPath(dir, opts.inputs),
              }),
            ...("repo" in opts &&
              typeof opts.repo === "string" && {
                repo: resolveConfigPath(dir, opts.repo),
              }),
          });
        });
      },
    });
  }
  return group.command(run);
}
