import { dependencyReviewerSchema } from "./dependency-outcome-schema.js";
import { Cli, z } from "incur";
import { environmentEntry } from "./auth.js";
import { resolveConfigPath } from "./config-path.js";
import {
  dependencyCheckOutputSchema,
  dependencyPackageCheckOutputSchema,
} from "./dependency-reachability.js";
import { dependencyScopedBlockedSchema } from "./dependency-blocked-schema.js";
import {
  withDependencyCheckOutput,
  DependencyInvestigationBlockedError,
} from "./dependency-check-output.js";
import type { DependencyCliContext } from "./dependency-stack-cli.js";
import { stackInvestigationReportSchema } from "./dependency-stack-assessment.js";
import { formatSecurityPolicyText } from "./security-policy.js";
import { prepareDependencyReport } from "./dependency-report-model.js";
import { summarizeDependencyReport } from "./dependency-report-summary.js";
import { renderPreparedDependencyReportMarkdown } from "./dependency-report-markdown.js";
import { CodexSecurityError } from "./errors.js";
import { readProjectConfig } from "./project-config.js";
import { enclosingGitWorktreeRoot, normalizeRepository } from "./targets.js";

const text = z.string().trim().min(1);
export const reportFileOption = text
  .optional()
  .describe(
    "Save the completed JSON report to a new file. With --format html, save HTML here instead (default: exploitability_report_<timestamp>.html in the current directory).",
  );
const blocked = z
  .object({
    status: z.literal("blocked"),
    code: z.literal("INVESTIGATION_BLOCKED"),
    reason: text,
  })
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
export function dependencyReportDestination(
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

export function presentDependencyResult<T>(
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

export function registerDependencyCheck(
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
      reviewer: dependencyReviewerSchema
        .default("enabled")
        .describe(
          "Independent review of individual claims (enabled), host checks only (disabled), or experimental review of configured report outcomes (outcome).",
        ),
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
      if (captured && options.reviewer !== "enabled")
        throw new CodexSecurityError(
          "--reviewer=" +
            options.reviewer +
            " applies to repository investigations. Captured stack investigations require independent review.",
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
          const result = await withDependencyCheckOutput(
            {
              subject: args.subject,
              checkout: repository,
              display: (line) => context.stderr.write(line + "\n"),
              signal,
              ...destination,
              progressEvents:
                options.progressEvents &&
                resolveConfigPath(cwd, options.progressEvents),
              warn: (message) =>
                (context.stderr ?? process.stderr).write(message + "\n"),
            },
            async (emit) => {
              const project = config
                ? await readProjectConfig(config, cwd)
                : undefined;
              const scope = project?.input.exploitability?.scope;
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
                  reviewer: options.reviewer,
                  outcomes: project?.input.exploitability?.outcomes,
                  vulnDescription: options.vulnDescription,
                  scope: scope?.instructions,
                  excludePaths: scope?.exclude_paths,
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
