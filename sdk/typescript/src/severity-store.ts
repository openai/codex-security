import { stat } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import {
  severityClassificationSchema,
  type SeverityAssessment,
  type SeverityClassification,
  type SeverityClassificationCheckpoint,
  type SeverityClassificationProgress,
} from "./classify-severity.js";
import type { JsonObject } from "./config.js";
import { CodexSecurityError } from "./errors.js";
import {
  bundledPluginRoot,
  canonicalizeModelSafePath,
  codexSecurityStateDirectory,
  requireOutputOutsideRepository,
  resolvePluginPython,
  runWorkbench,
  type WorkbenchCommandOptions,
} from "./runtime.js";

/** @internal */
export class SeverityStore {
  private options?: Promise<WorkbenchCommandOptions>;
  readonly runId = randomUUID();

  constructor(
    private readonly environment: NodeJS.ProcessEnv,
    private readonly scanDirectory: string,
    private readonly signal?: AbortSignal,
  ) {}

  async isRegisteredScan(scanId: string): Promise<boolean> {
    const response = await this.run(["severity-classification"], {
      action: "source",
      scanId,
      scanDirectory: this.scanDirectory,
    });
    return response["registeredScan"] === true;
  }

  checkpoint(
    scanId: string,
    findingIds: string[],
    reprocess: boolean,
    savedProgress: (progress: SeverityClassificationProgress) => {
      progress: SeverityClassificationProgress;
      registeredScan: boolean;
    },
  ): SeverityClassificationCheckpoint {
    return {
      load: async (result) => {
        const response = await this.run(["severity-classification"], {
          action: "begin",
          scanId,
          findingIds,
          assessedAt: result.assessedAt,
          rubricSha256: result.rubricSha256,
          knowledgeBaseSha256: result.knowledgeBaseSha256,
        });
        return reprocess
          ? []
          : matchingAssessments(
              response["assessments"] as JsonObject[],
              result,
            );
      },
      save: async (finding, assessment, result, progress) => {
        await this.run(
          ["severity-classification"],
          {
            action: "save",
            finding,
            assessment: {
              ...assessment,
              rubricSha256: result.rubricSha256,
              knowledgeBaseSha256: result.knowledgeBaseSha256,
            },
            scanId,
            runId: this.runId,
            ...savedProgress(progress),
          },
          true,
        );
      },
    };
  }

  async progress(
    scanId: string,
    progress: SeverityClassificationProgress,
    registeredScan: boolean,
  ): Promise<void> {
    await this.run(
      ["severity-classification"],
      {
        action: "progress",
        scanId,
        runId: this.runId,
        progress,
        registeredScan,
      },
      true,
    );
  }

  async read(scanId: string): Promise<SeverityClassification | undefined> {
    try {
      await stat(
        join(
          codexSecurityStateDirectory(this.environment),
          "workbench.sqlite3",
        ),
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
    const saved = await this.run([
      "read-severity-classification",
      "--scan-id",
      scanId,
    ]);
    if (saved["scanId"] === undefined) return undefined;
    const result: SeverityClassification = {
      schemaVersion: 1,
      assessedAt: saved["assessedAt"] as string,
      rubricSha256: saved["rubricSha256"] as string | null,
      knowledgeBaseSha256: saved["knowledgeBaseSha256"] as string | null,
      assessments: [],
    };
    result.assessments = matchingAssessments(
      saved["assessments"] as JsonObject[],
      result,
    );
    const findingIds = saved["findingIds"] as string[];
    if (result.assessments.length !== findingIds.length) {
      throw new CodexSecurityError(
        "Severity classification is incomplete or its inputs changed. Rerun classify-severity before publishing.",
      );
    }
    return result;
  }

  private async run(args: string[], input?: object, finishWrite = false) {
    const options = await (this.options ??= this.resolveOptions());
    return runWorkbench(
      finishWrite ? { ...options, signal: undefined } : options,
      args,
      input === undefined ? undefined : JSON.stringify(input),
    );
  }

  private async resolveOptions(): Promise<WorkbenchCommandOptions> {
    const environment = {
      ...this.environment,
      CODEX_SECURITY_STATE_DIR: codexSecurityStateDirectory(this.environment),
    };
    requireOutputOutsideRepository(
      this.scanDirectory,
      await canonicalizeModelSafePath(environment.CODEX_SECURITY_STATE_DIR),
      "runtime",
    );
    const [python, pluginRoot] = await Promise.all([
      resolvePluginPython({
        environment,
        protectedRoot: this.scanDirectory,
        signal: this.signal,
      }),
      bundledPluginRoot(),
    ]);
    return {
      python,
      pluginRoot,
      environment,
      signal: this.signal,
      failureMessage: "Could not access severity assessments",
    };
  }
}

function matchingAssessments(
  stored: JsonObject[],
  result: SeverityClassification,
): SeverityAssessment[] {
  return severityClassificationSchema.parse({
    ...result,
    assessments: stored
      .filter(
        (row) =>
          row["rubricSha256"] === result.rubricSha256 &&
          row["knowledgeBaseSha256"] === result.knowledgeBaseSha256,
      )
      .map(
        ({
          assessedAt: _assessedAt,
          rubricSha256: _rubric,
          knowledgeBaseSha256: _knowledge,
          ...assessment
        }) => assessment,
      ),
  }).assessments;
}
