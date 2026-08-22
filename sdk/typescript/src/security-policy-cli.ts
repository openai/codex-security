import type { CodexSecurity, ScanAuthMode } from "./api.js";
import type { BulkScanPrompt } from "./bulk-scan-discovery.js";
import type { CodexSecurityConfig } from "./config.js";
import { formatUsd } from "./cost.js";
import {
  SecurityPolicyRecoveryError,
  SecurityPolicyVerificationError,
  safeErrorMessage,
} from "./errors.js";
import {
  applySecurityPolicy,
  loadSecurityPolicyDraft,
  formatSecurityPolicyText as display,
  securityPolicyDiff,
  type SecurityPolicyDraft,
  type SecurityPolicyOptions,
  type SecurityPolicyStage,
} from "./security-policy.js";
import { resolvePluginPython } from "./runtime.js";
import { enclosingGitWorktreeRoots } from "./targets.js";

type SignalName = "SIGINT" | "SIGTERM";
type Output = { write(value: string): unknown };
export type PolicyPrompt = Pick<
  BulkScanPrompt,
  "isInteractive" | "input" | "confirm"
>;
export type PolicySecurity = Pick<
  CodexSecurity,
  "generatePolicy" | "preflightPolicy" | "previewPolicy" | "close"
>;

export interface PolicyCommandOptions {
  repository: string;
  config: CodexSecurityConfig;
  generation: SecurityPolicyOptions;
  apply?: string;
  write: boolean;
  headless: boolean;
  dryRun: boolean;
  format: string;
  explicitOutput: boolean;
}

export interface PolicyCommandDependencies {
  createSecurity(config: CodexSecurityConfig): PolicySecurity;
  chooseAuthentication(
    config: CodexSecurityConfig,
    auth: ScanAuthMode | undefined,
    signal: AbortSignal,
  ): Promise<ScanAuthMode | undefined>;
  prompt: PolicyPrompt;
  environment: NodeJS.ProcessEnv;
  errorOutput: Output;
  writePreview(value: string, signal: AbortSignal): Promise<void>;
  now(): number;
  addSignalListener(signal: SignalName, listener: () => void): void;
  removeSignalListener(signal: SignalName, listener: () => void): void;
  forceExit(signal: SignalName): void;
  resolvePython?: typeof resolvePluginPython;
}

const STAGES: Record<SecurityPolicyStage, string> = {
  architecture: "[1/3] Understanding the system and its security boundaries",
  threat_model: "[2/3] Building the source-backed threat model",
  policy: "[3/3] Drafting SECURITY.md",
};

export async function runPolicyCommand(
  options: PolicyCommandOptions,
  dependencies: PolicyCommandDependencies,
): Promise<{
  exitCode: number;
  data?: Record<string, unknown>;
  markdown?: string;
  error?: string;
}> {
  const { errorOutput, prompt } = dependencies;
  const controller = new AbortController();
  const interactive =
    !options.headless &&
    options.format === "toon" &&
    dependencies.environment["CI"] === undefined &&
    prompt.isInteractive();
  const started = dependencies.now();
  let security: PolicySecurity | undefined;
  let outputDir: string | undefined;
  let applyingTarget: string | undefined;
  const write = (message: string): void => {
    try {
      errorOutput.write(`${message}\n`);
    } catch {}
  };
  let firstSignalAt = 0;
  const signalListener = (signal: SignalName) => () => {
    if (controller.signal.aborted) {
      // Match scan's handling of duplicate initial signals from launchers.
      if (
        controller.signal.reason === signal &&
        dependencies.now() - firstSignalAt < 500
      )
        return;
      if (applyingTarget !== undefined)
        write(
          `Policy application is being stopped. Check ${display(applyingTarget)}${outputDir === undefined ? "" : ` and saved artifacts at ${display(outputDir)}`} for recovery files before retrying.`,
        );
      removeSignalListeners();
      dependencies.forceExit(signal);
      return;
    }
    firstSignalAt = dependencies.now();
    controller.abort(signal);
  };
  const interrupt = signalListener("SIGINT");
  const terminate = signalListener("SIGTERM");
  const removeSignalListeners = () => {
    dependencies.removeSignalListener("SIGINT", interrupt);
    dependencies.removeSignalListener("SIGTERM", terminate);
  };
  dependencies.addSignalListener("SIGINT", interrupt);
  dependencies.addSignalListener("SIGTERM", terminate);
  try {
    let draft: SecurityPolicyDraft;
    if (options.apply !== undefined) {
      draft = await loadSecurityPolicyDraft(options.repository, options.apply, {
        path: options.generation.path,
        signal: controller.signal,
      });
      outputDir = draft.outputDir;
    } else {
      const auth =
        interactive && !options.dryRun
          ? await dependencies.chooseAuthentication(
              options.config,
              options.generation.auth,
              controller.signal,
            )
          : options.generation.auth;
      controller.signal.throwIfAborted();
      security = dependencies.createSecurity(options.config);
      if (options.dryRun) {
        const preflight = await security.preflightPolicy(options.repository, {
          ...options.generation,
          signal: controller.signal,
        });
        controller.signal.throwIfAborted();
        return {
          exitCode: 0,
          data: {
            ...preflight,
            dryRun: true,
          },
        };
      }
      draft = await security.generatePolicy(options.repository, {
        ...options.generation,
        auth,
        signal: controller.signal,
        onOutputDirReady: (directory) => {
          outputDir = directory;
          write(`Policy artifacts: ${display(directory)}`);
        },
        onStage: (stage) => write(STAGES[stage]),
        onWarning: (warning) =>
          write(`codex-security: ${display(safeErrorMessage(warning))}`),
        ...(interactive
          ? {
              answerQuestions: async (
                questions: readonly string[],
                signal: AbortSignal,
              ) => {
                write(
                  "A few details could change this policy. Leave an answer blank to keep it unresolved.",
                );
                const answers: string[] = [];
                for (const question of questions) {
                  signal.throwIfAborted();
                  const answer = await prompt.input(
                    display(question),
                    undefined,
                    signal,
                  );
                  if (answer.trim()) answers.push(`${question}\n${answer}`);
                }
                return answers.join("\n\n");
              },
            }
          : {}),
      });
    }
    controller.signal.throwIfAborted();
    const cost = draft.cost;
    let python: string | undefined;
    const diff =
      security === undefined
        ? display(
            await securityPolicyDiff(
              draft,
              async () =>
                (python ??= await (
                  dependencies.resolvePython ?? resolvePluginPython
                )({
                  configuredPath: options.config.pythonPath,
                  environment: dependencies.environment,
                  protectedRoot:
                    (
                      await enclosingGitWorktreeRoots(
                        draft.repository,
                        controller.signal,
                      )
                    ).at(-1) ?? draft.repository,
                  signal: controller.signal,
                })),
              controller.signal,
            ),
            true,
          )
        : await security.previewPolicy(draft, {
            signal: controller.signal,
          });
    const changed = diff.length > 0;
    const humanOutput = options.format === "toon" && !options.explicitOutput;
    if (humanOutput) {
      const preview = [
        `\nPolicy target: ${display(draft.targetPath)}`,
        changed
          ? diff.replace(/\n$/u, "")
          : "SECURITY.md is already up to date.",
        ...(draft.reviewNotes.length === 0
          ? []
          : [
              "\nOwner review:",
              ...draft.reviewNotes.map((note) => `- ${display(note)}`),
            ]),
      ].join("\n");
      if (interactive && !options.write)
        await dependencies.writePreview(`${preview}\n`, controller.signal);
      else write(preview);
    }
    controller.signal.throwIfAborted();
    const approved =
      options.write ||
      (changed &&
        interactive &&
        (await prompt.confirm(
          `Write this policy to ${display(draft.targetPath)}?`,
          false,
          controller.signal,
        )));
    controller.signal.throwIfAborted();
    let status: "draft" | "written" | "unchanged" = changed
      ? "draft"
      : "unchanged";
    let recoveryPath: string | null = null;
    if (approved) {
      applyingTarget = draft.targetPath;
      const applied = await applySecurityPolicy(draft, {
        pythonPath: python ?? options.config.pythonPath,
        pluginPath: options.config.pluginPath,
        environment: dependencies.environment,
        signal: controller.signal,
      });
      recoveryPath = applied.recoveryPath;
      status = applied.status;
      write(
        `${status === "written" ? "Wrote and verified" : "Verified"} ${display(draft.targetPath)}`,
      );
      if (recoveryPath !== null)
        write(`Previous policy kept at ${display(recoveryPath)}`);
    } else if (humanOutput) {
      write(`\nDraft: ${display(draft.draftPath)}`);
      write(`Threat model: ${display(draft.threatModelPath)}`);
      if (changed)
        write(
          "No repository files changed. Review the draft, then run policy with --apply <artifact-directory> --write.",
        );
    }
    if (options.apply === undefined) {
      const seconds = Math.max(0, (dependencies.now() - started) / 1000);
      write(
        `Policy generation finished in ${seconds.toFixed(1)}s${cost === null ? "" : ` (${formatUsd(cost.estimatedUsd)} estimated)`}.`,
      );
    }
    return {
      exitCode: 0,
      markdown: draft.content,
      data: {
        status,
        repository: draft.repository,
        scope: draft.scope,
        targetPath: draft.targetPath,
        ...(recoveryPath === null ? {} : { recoveryPath }),
        outputDir: draft.outputDir,
        draftPath: draft.draftPath,
        specificationPath: draft.specificationPath,
        threatModelPath: draft.threatModelPath,
        customPlugin: draft.customPlugin,
        reviewNotes: draft.reviewNotes,
        cost,
      },
    };
  } catch (error) {
    const written = error instanceof SecurityPolicyVerificationError;
    const recovery = error instanceof SecurityPolicyRecoveryError;
    const signal =
      (written || recovery ? undefined : controller.signal.reason) ??
      (error instanceof Error && error.name === "ExitPromptError"
        ? "SIGINT"
        : undefined);
    const exitCode = signal === "SIGINT" ? 130 : signal === "SIGTERM" ? 143 : 2;
    const message =
      signal === "SIGINT"
        ? "Policy generation canceled by Ctrl-C."
        : signal === "SIGTERM"
          ? "Policy generation terminated by SIGTERM."
          : display(safeErrorMessage(error));
    write(`codex-security: ${message}`);
    if (outputDir !== undefined)
      write(`Saved artifacts: ${display(outputDir)}`);
    return {
      exitCode,
      error: message,
      ...(written || recovery
        ? {
            data: {
              status: written ? "written_unverified" : "recovery_required",
              targetPath: error.targetPath,
              ...(error.recoveryPath === undefined
                ? {}
                : { recoveryPath: error.recoveryPath }),
              ...(outputDir === undefined ? {} : { outputDir }),
            },
          }
        : {}),
    };
  } finally {
    removeSignalListeners();
    try {
      await security?.close();
    } catch (error) {
      write(
        `codex-security: Could not clean up the policy runtime: ${display(safeErrorMessage(error))}`,
      );
    }
  }
}

export function policyDisplayData(
  data: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  const displayValue = (value: unknown): unknown => {
    if (typeof value === "string") return display(value);
    if (Array.isArray(value)) return value.map(displayValue);
    if (value !== null && typeof value === "object")
      return Object.fromEntries(
        Object.entries(value).map(([key, item]) => [key, displayValue(item)]),
      );
    return value;
  };
  return data === undefined
    ? undefined
    : (displayValue(data) as Record<string, unknown>);
}
