import { Cli, z } from "incur";
import { environmentEntry } from "./auth.js";
import { resolveConfigPath } from "./config-path.js";
import {
  dependencyCheckOutputSchema,
  dependencyPackageCheckOutputSchema,
  dependencyScopedBlockedSchema,
} from "./dependency-reachability.js";
import {
  withDependencyCheckOutput,
  writeDependencyReportFile,
  DependencyInvestigationBlockedError,
} from "./dependency-check-output.js";
import { stackInvestigationReportSchema } from "./dependency-stack-assessment.js";
import { formatSecurityPolicyText } from "./security-policy.js";
import { prepareDependencyReport } from "./dependency-report-model.js";
import {
  summarizeDependencyReport,
  renderPreparedDependencyReportMarkdown,
} from "./dependency-report-text.js";
import { CodexSecurityError } from "./errors.js";
import { readProjectConfig } from "./project-config.js";
import { enclosingGitWorktreeRoot, normalizeRepository } from "./targets.js";
import type { InvestigationToolFactory } from "./dependency-investigation-session.js";
import type { ScanTokenUsage } from "./cost-model.js";
import type {
  DependencyEvidenceRecord,
  DependencyEvidenceFailure,
} from "./dependency-evidence-sources.js";
import { executeStackRun, stackRunTools } from "./dependency-stack-run.js";

export interface DependencyAgentRequest {
  prompt: string;
  directory: string;
  signal: AbortSignal;
  model?: string;
  effort?: string;
  codex?: string[];
  config?: string;
  stackTarget?: string;
  readOnly?: boolean;
  coordinator?: boolean;
  onCoordinatorAnswer?: (answer: string) => Promise<string | undefined>;
  investigationTools?: InvestigationToolFactory;
  onAccessProgram?: (program: string | undefined) => void;
  onUsage?: (usage: ScanTokenUsage) => void;
  onEvidence?: (record: DependencyEvidenceRecord) => void;
  onEvidenceFailure?: (
    call: DependencyEvidenceFailure,
    result?: Record<string, unknown>,
  ) => void;
  onEvidenceStartup?: (
    server: string,
    status: import("./dependency-blocked-evidence.js").DependencyStartupStatus,
    required: boolean,
    error: unknown,
  ) => void;
  abortInvestigation?: (args: unknown, thread: string) => unknown;
  onEvidenceDiagnostic?: (message: string) => void;
}

export interface DependencyCliContext {
  hasOutputFilter?(): boolean;
  htmlReportRequested?(): boolean;
  environment: NodeJS.ProcessEnv;
  stderr: Pick<NodeJS.WritableStream, "write">;
  setExitCode(code: number): void;
  currentDirectory(): string;
  recordsInput: AsyncIterable<Buffer | string>;
  withSignal<T>(run: (signal: AbortSignal) => Promise<T>): Promise<T>;
  runAgent(request: DependencyAgentRequest): Promise<string>;
}

const text = z.string().trim().min(1);
const reportFileOption = text
  .optional()
  .describe(
    "Save the completed JSON report to a new file. With --format html, save HTML here instead (default: exploitability_report_<timestamp>.html in the current directory).",
  );
const blocked = dependencyScopedBlockedSchema
  .pick({ status: true, code: true, reason: true })
  .passthrough();
const advisoryId = { advisoryId: z.string().nullable() };
const blockedPackage = dependencyPackageCheckOutputSchema
  .extend({
    ...blocked.shape,
    checks: z.array(
      z.union([
        dependencyPackageCheckOutputSchema.shape.checks.element,
        dependencyScopedBlockedSchema.safeExtend(advisoryId),
        blocked.extend(advisoryId),
      ]),
    ),
    pendingAdvisories: z.array(z.string().nullable()).optional(),
  })
  .passthrough();

/** HTML is a file, never a document dumped to stdout. All other formats keep
 * --report-file independent of the terminal and preserve the canonical JSON. */
function dependencyReportDestination(
  cwd: string,
  requested: string | undefined,
  context: DependencyCliContext,
) {
  const html = context.htmlReportRequested?.();
  const path =
    requested ??
    (html
      ? `exploitability_report_${new Date().toISOString().replace(/[-:.]/gu, "")}.html`
      : undefined);
  return {
    reportFile: path && resolveConfigPath(cwd, path),
    reportFormat: html ? ("html" as const) : ("json" as const),
  };
}

function presentDependencyResult<T>(
  result: T,
  context: DependencyCliContext,
  format: string,
  options: { summary?: boolean; savedPath?: string } = {},
): T | string {
  if (context.htmlReportRequested?.()) {
    const summary = summarizeDependencyReport(prepareDependencyReport(result));
    // A blocked investigation has no completed artifact to link.
    return options.savedPath
      ? summary + "\n\n" + formatSecurityPolicyText(options.savedPath)
      : summary;
  }
  if (context.hasOutputFilter?.()) return result;
  if (format === "md")
    return formatSecurityPolicyText(
      renderPreparedDependencyReportMarkdown(prepareDependencyReport(result)),
      true,
    ).trimEnd();
  if (options.summary && format === "toon")
    return summarizeDependencyReport(prepareDependencyReport(result));
  return result;
}

function registerDependencyCheck(
  group: ReturnType<typeof Cli.create>,
  context: DependencyCliContext,
) {
  group.command("check", {
    description:
      "Investigate a CVE or package in this checkout, optionally using a supplied stack capture.",
    hint: "Read the summary on stdout, use --format md for the full text or --json for the structured result. --format html saves a browser view and prints its path.",
    alias: { config: "c" },
    destructive: false,
    mcp: false,
    args: z.object({
      subject: text.describe(
        "A CVE ID or an ecosystem-qualified package such as npm:example.",
      ),
    }),
    options: z.object({
      sources: text
        .optional()
        .describe("Path to the supplied source endpoint document."),
      sinks: text
        .optional()
        .describe(
          "Path to the sink endpoints and catalog advisory. The CLI looks up public advisory details unless supplied.",
        ),
      stacks: text
        .optional()
        .describe("Path to the observed stacks and target revision."),
      model: text.optional().describe("Investigator model."),
      effort: text.optional().describe("Investigator reasoning effort."),
      config: text
        .optional()
        .describe("Codex Security project configuration file."),
      codex: z
        .array(text)
        .default([])
        .describe("Pass a Codex model or provider configuration override."),
      vulnDescription: text
        .optional()
        .describe(
          "Investigate a caller-supplied description for a named package.",
        ),
      progressEvents: text
        .optional()
        .describe("Stream investigation progress to a new JSON Lines file."),
      reportFile: reportFileOption,
    }),
    output: z.union([
      ...dependencyCheckOutputSchema.options,
      stackInvestigationReportSchema,
      dependencyScopedBlockedSchema,
      blockedPackage,
      blocked,
      z.string(),
    ]),
    async run({ args, options, format, formatExplicit }) {
      const { sources, sinks, stacks } = options;
      const captured =
        sources !== undefined || sinks !== undefined || stacks !== undefined;
      if (captured && (!sources || !sinks || !stacks))
        throw new CodexSecurityError(
          "Supply --sources, --sinks and --stacks together for one CVE.",
        );
      if (
        captured &&
        (!/^CVE-\d{4}-\d{4,}$/iu.test(args.subject) ||
          options.vulnDescription !== undefined)
      )
        throw new CodexSecurityError(
          "Captured stack investigations require one CVE ID with its advisory in --sinks.",
        );
      const cwd = context.currentDirectory();
      return context
        .withSignal(async (signal) => {
          const dir = await normalizeRepository(cwd, signal);
          const repository = await enclosingGitWorktreeRoot(dir, signal, {
            requireIfPresent: true,
          });
          if (!repository)
            throw new CodexSecurityError(
              "A dependency investigation requires a Git checkout.",
            );
          const selectedConfig =
            options.config ??
            environmentEntry(
              context.environment ?? process.env,
              "CODEX_SECURITY_PROJECT_CONFIG",
            );
          const config =
            selectedConfig === undefined
              ? undefined
              : resolveConfigPath(cwd, selectedConfig);
          const settings = {
            model: options.model,
            effort: options.effort,
            codex: options.codex,
            config,
          };
          const destination = dependencyReportDestination(
            cwd,
            options.reportFile,
            context,
          );
          const display = (line: string) => context.stderr.write(line + "\n");
          const result = await withDependencyCheckOutput(
            {
              subject: args.subject,
              checkout: repository,
              display,
              warn: display,
              signal,
              ...destination,
              progressEvents:
                options.progressEvents &&
                resolveConfigPath(cwd, options.progressEvents),
            },
            async (emit) => {
              const project = config
                ? await readProjectConfig(config, cwd)
                : undefined;
              const check = project?.input.exploitability;
              const scope = check?.scope;
              if (sources && sinks && stacks) {
                const { runLocalStackInvestigation } =
                  await import("./dependency-stack-launcher.js");
                return runLocalStackInvestigation({
                  cve: args.subject.toUpperCase(),
                  callerScope: scope?.instructions,
                  repository,
                  signal,
                  sourcesPath: resolveConfigPath(cwd, sources),
                  sinksPath: resolveConfigPath(cwd, sinks),
                  stacksPath: resolveConfigPath(cwd, stacks),
                  emit,
                  runAgent: (request) =>
                    context.runAgent({ ...request, ...settings }),
                });
              }
              const { runReviewedDependencyCheck } =
                await import("./dependency-reviewed-check.js");
              const reviewed = await runReviewedDependencyCheck(
                {
                  directory: repository,
                  subject: args.subject,
                  vulnDescription: options.vulnDescription,
                  scope: scope?.instructions,
                  excludePaths: scope?.exclude_paths,
                  sources: check?.sources,
                  sinks: check?.sinks,
                  evidenceSources: check?.evidence_sources,
                  onProgress: emit,
                  signal,
                  ...settings,
                },
                { runAgent: context.runAgent },
              );
              return dependencyCheckOutputSchema.parse(reviewed);
            },
          );
          return presentDependencyResult(result, context, format, {
            summary: !formatExplicit,
            savedPath: destination.reportFile,
          });
        })
        .catch((error: unknown) => {
          if (error instanceof DependencyInvestigationBlockedError) {
            context.setExitCode(2);
            return presentDependencyResult(error.outcome, context, format, {
              summary: !formatExplicit,
            });
          }
          throw error;
        });
    },
  });
}

export function createExploitabilityCli(context: DependencyCliContext) {
  const group = Cli.create("exploitability", {
    description: "Investigate dependency vulnerabilities in a repository.",
  });
  registerDependencyCheck(group, context);
  const run = Cli.create("run", {
    description:
      "Read and update a single investigation. Commands return JSON by default.",
  });
  const pathOptions = z.object({
    state: text.describe("Path to the investigation SQLite file."),
  });
  for (const tool of stackRunTools) {
    const options =
      tool.name === "init"
        ? pathOptions.extend({
            inputs: text
              .optional()
              .describe("Directory containing the prepared input packet."),
            repo: text.describe("Target Git checkout."),
            jsonStdin: z
              .boolean()
              .optional()
              .describe(
                "Read optional investigation metadata from standard input.",
              ),
          })
        : tool.name === "finalize"
          ? pathOptions.extend({ reportFile: reportFileOption })
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
      async run({ options: opts, format }) {
        return context.withSignal(async (signal) => {
          const dir = context.currentDirectory();
          let input: unknown;
          if ("jsonStdin" in opts && opts.jsonStdin) {
            const chunks: Buffer[] = [];
            for await (const data of context.recordsInput)
              chunks.push(Buffer.from(data));
            input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          } else if (tool.inputSchema && tool.name !== "init") {
            throw new CodexSecurityError(
              "Use --json-stdin to provide input for " + tool.name + ".",
            );
          }
          const result = await executeStackRun(tool.name, {
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
          if (tool.name === "finalize") {
            const { reportFile: path, reportFormat } =
              dependencyReportDestination(
                dir,
                "reportFile" in opts && typeof opts.reportFile === "string"
                  ? opts.reportFile
                  : undefined,
                context,
              );
            if (path) {
              await writeDependencyReportFile(
                path,
                result,
                signal,
                reportFormat,
              );
              if (reportFormat !== "html")
                context.stderr.write(
                  "Report saved · " + formatSecurityPolicyText(path) + "\n",
                );
            }
            return presentDependencyResult(result, context, format, {
              savedPath: path,
            });
          }
          return result;
        });
      },
    });
  }
  return group.command(run);
}
