import { Cli, z } from "incur";
import { environmentEntry } from "./auth.js";
import { resolveConfigPath } from "./config-path.js";
import { dependencyCheckOutputSchema } from "./dependency-reachability.js";
import { withDependencyCheckOutput } from "./dependency-check-output.js";
import {
  DependencyInvestigationBlockedError,
  runReviewedDependencyCheck,
} from "./dependency-reviewed-check.js";
import type { DependencyCliContext } from "./dependency-stack-cli.js";
import { stackInvestigationReportSchema } from "./dependency-stack-assessment.js";
import {
  runLocalStackInvestigation,
  stackInvestigationPrompt,
} from "./dependency-stack-launcher.js";
import { CodexSecurityError } from "./errors.js";
import { readProjectConfig } from "./project-config.js";
import { enclosingGitWorktreeRoot, normalizeRepository } from "./targets.js";

const text = z.string().trim().min(1);
const checkOutput = z.union([
  stackInvestigationReportSchema,
  ...dependencyCheckOutputSchema.options,
]);

type Result =
  | z.output<typeof dependencyCheckOutputSchema>
  | Awaited<ReturnType<typeof runLocalStackInvestigation>>;
function summarize(report: Result): string {
  if ("verdict" in report)
    return [
      `${report.cve} · ${report.verdict}`,
      ...report.assessments.map(
        (a) => `  ${a.workItemId}: ${a.verdict} — ${a.reason}`,
      ),
    ].join("\n");
  const checks = "checks" in report ? report.checks : [report];
  if (!checks.length && "package" in report)
    return `${report.package.ecosystem}:${report.package.name}: no published advisories found.`;
  return checks
    .map((check) => {
      const title =
        "cve" in check
          ? check.cve
          : (check.advisoryId ?? "Caller-supplied description");
      return [
        title,
        ...check.uses.map(
          (u) =>
            `  ${u.location} · ${u.component}@${u.version ?? "unknown"} · ${u.verdict}: ${u.reason}`,
        ),
        ...check.limitations.map((s) => `  Gap: ${s}`),
      ].join("\n");
    })
    .join("\n\n");
}

export function registerDependencyCheck(
  group: ReturnType<typeof Cli.create>,
  context: DependencyCliContext,
) {
  group.command("check", {
    description:
      "Investigate a CVE or package in this checkout, optionally using a supplied stack capture.",
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
        .describe("Path to the sink endpoints and frozen advisory."),
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
      reportFile: text
        .optional()
        .describe("Save the completed JSON report to a new file."),
    }),
    output: z.union([
      checkOutput,
      z
        .object({
          status: z.literal("blocked"),
          code: z.literal("INVESTIGATION_BLOCKED"),
          reason: text,
        })
        .passthrough(),
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
          const result = await withDependencyCheckOutput(
            {
              subject: args.subject,
              checkout: repository,
              ...("isTTY" in context.stderr &&
                context.stderr.isTTY === true &&
                context.environment["TERM"] !== "dumb" && {
                  display: (line: string) => context.stderr.write(line + "\n"),
                }),
              signal,
              reportFile:
                options.reportFile &&
                resolveConfigPath(cwd, options.reportFile),
              progressEvents:
                options.progressEvents &&
                resolveConfigPath(cwd, options.progressEvents),
              warn: (message) =>
                (context.stderr ?? process.stderr).write(message + "\n"),
            },
            async (emit) => {
              if (sources && sinks && stacks) {
                emit("investigation");
                return runLocalStackInvestigation({
                  cve: args.subject.toUpperCase(),
                  repository,
                  signal,
                  sourcesPath: resolveConfigPath(cwd, sources),
                  sinksPath: resolveConfigPath(cwd, sinks),
                  stacksPath: resolveConfigPath(cwd, stacks),
                  async investigate(session) {
                    await context.runAgent({
                      directory: session.directory,
                      stackTarget: session.repo,
                      signal,
                      prompt: await stackInvestigationPrompt(session),
                      ...settings,
                    });
                    return 0;
                  },
                });
              }
              const project = config
                ? await readProjectConfig(config, cwd)
                : undefined;
              const reviewed = await runReviewedDependencyCheck(
                {
                  directory: repository,
                  subject: args.subject,
                  vulnDescription: options.vulnDescription,
                  scope: project?.input.exploitability?.scope?.instructions,
                  excludePaths:
                    project?.input.exploitability?.scope?.exclude_paths,
                  sources: project?.input.exploitability?.sources,
                  sinks: project?.input.exploitability?.sinks,
                  evidenceSources:
                    project?.input.exploitability?.evidence_sources,
                  onProgress: emit,
                  signal,
                  ...settings,
                },
                { runAgent: context.runAgent },
              );
              return dependencyCheckOutputSchema.parse(reviewed);
            },
          );
          return !formatExplicit && format === "toon"
            ? summarize(result)
            : result;
        })
        .catch((error: unknown) => {
          if (error instanceof DependencyInvestigationBlockedError) {
            context.setExitCode(2);
            return !formatExplicit && format === "toon"
              ? error.message
              : error.outcome;
          }
          throw error;
        });
    },
  });
}
