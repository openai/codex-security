import { randomUUID } from "node:crypto";
import { cp, mkdir, readFile, rm } from "node:fs/promises";
import { join, relative } from "node:path";
import { Codex } from "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js";
import * as sdk from "../../sdk/typescript/dist/api.js";
import { deepScanOptions } from "../../sdk/typescript/dist/deep-config.js";
import { createProfileCodex } from "../../sdk/typescript/dist/provider-profile.js";
import {
  codexExecutableReadPaths,
  resolveCodexCommand,
} from "../../sdk/typescript/dist/runtime.js";
import type { CodexSecurity as Client } from "../../sdk/typescript/src/api.js";
import type { PreparedStandardEval } from "./fixtures.mts";
import { gradeResult, type Result } from "./grade.mts";
import {
  hashText,
  StateCleanupError,
  type RunReport,
  type Variant,
} from "./experiment.mts";

const { CodexSecurity, scanAuthentication } =
  sdk as unknown as typeof import("../../sdk/typescript/src/api.js");
type Dependencies = NonNullable<ConstructorParameters<typeof CodexSecurity>[1]>;

export async function snapshotCodexExecutable(environment: NodeJS.ProcessEnv) {
  const command = resolveCodexCommand(environment).command;
  const paths = await codexExecutableReadPaths(command);
  return {
    command,
    files: await Promise.all(
      paths.map(async (path) => ({
        path,
        sha256: hashText(await readFile(path)),
      })),
    ),
  };
}

export function preflightStandardEval(
  environment: NodeJS.ProcessEnv,
  budgetMinutes: number,
) {
  if (scanAuthentication(environment).method !== "api_key") {
    throw new Error(
      "The Standard time-budget eval requires OPENAI_API_KEY or CODEX_API_KEY. Saved logins are not supported by this developer eval.",
    );
  }
  deepScanOptions({ mode: "standard", maxTimeMinutes: budgetMinutes });
}

export interface StandardRunOptions {
  model: string;
  pair: number;
  variant: Variant;
  maxTimeMinutes?: number;
  signal?: AbortSignal;
  observation: { prompt?: string; usage?: unknown };
}

export type StandardRunner = (
  prepared: PreparedStandardEval,
  options: StandardRunOptions,
) => Promise<{ report: RunReport; semanticResult: Result }>;

export function createStandardRunner({
  stateRoot,
  outputRoot,
  environment = process.env,
  createClient = (config, dependencies) =>
    new CodexSecurity(config, dependencies, { surface: "sdk" }),
  createCodex = ({ nativeProfile, ...settings }) =>
    nativeProfile === undefined
      ? new Codex(settings)
      : createProfileCodex(settings, nativeProfile),
}: {
  stateRoot: string;
  outputRoot: string;
  environment?: NodeJS.ProcessEnv;
  createClient?: (
    config: ConstructorParameters<typeof CodexSecurity>[0],
    dependencies: Dependencies,
  ) => Pick<Client, "run" | "close">;
  createCodex?: Dependencies["createCodex"];
}): StandardRunner {
  return async (prepared, options) => {
    const stateDirectory = join(stateRoot, randomUUID());
    const scanDirectory = join(stateDirectory, "scan");
    const archiveDirectory = join(
      outputRoot,
      `pair-${options.pair}-${options.variant}`,
      "scan",
    );
    await mkdir(scanDirectory, { recursive: true, mode: 0o700 });
    const client = createClient(
      {
        pluginPath: prepared.runtime,
        codexOverrides: {
          model: options.model,
          model_reasoning_effort: "xhigh",
        },
      },
      {
        environment: {
          ...environment,
          CODEX_SECURITY_STATE_DIR: stateDirectory,
        },
        createCodex: async (settings) => {
          const codex = await createCodex(settings);
          return {
            startThread: (threadOptions) => {
              const thread = codex.startThread(threadOptions);
              return {
                get id() {
                  return thread.id;
                },
                runStreamed: (prompt, turnOptions) => {
                  options.observation.prompt ??= prompt;
                  return thread.runStreamed(prompt, turnOptions);
                },
              };
            },
          };
        },
      },
    );
    let failure: unknown;
    try {
      const result = await client.run(prepared.repo, {
        mode: "standard",
        maxTimeMinutes: options.maxTimeMinutes,
        signal: options.signal,
        onUsage: (usage) => {
          options.observation.usage = usage;
        },
        outputDir: scanDirectory,
      });
      options.observation.usage =
        result.turnResult.usage ?? options.observation.usage;
      const semanticResult = {
        findings: result.findings.findings,
        coverage: result.coverage,
        threatModel: result.threatModel,
      };
      return {
        semanticResult,
        report: {
          ...gradeResult(semanticResult, prepared.fixture),
          scanId: result.manifest.scan.id,
          scanDir: archiveDirectory,
          reportPath: join(
            archiveDirectory,
            relative(result.scanDir, result.reportPath),
          ),
        },
      };
    } catch (error) {
      failure = error;
      throw error;
    } finally {
      const failures: unknown[] = failure === undefined ? [] : [failure];
      try {
        await client.close();
      } catch (error) {
        failures.push(error);
      }
      try {
        await cp(scanDirectory, archiveDirectory, { recursive: true });
      } catch (error) {
        failures.push(error);
      }
      try {
        await rm(stateDirectory, { recursive: true, force: true });
      } catch (error) {
        failures.push(error);
        throw new StateCleanupError(failures, failures.map(String).join("\n"));
      }
      if (failures.length > 1)
        throw new AggregateError(failures, failures.map(String).join("\n"));
      if (failures.length === 1 && failure === undefined) throw failures[0];
    }
  };
}
