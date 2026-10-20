import { stat } from "node:fs/promises";
import { join } from "node:path";
import {
  severityClassificationSchema,
  type SeverityClassification,
  type SeverityClassificationCheckpoint,
} from "./classify-severity.js";
import type { JsonObject } from "./config.js";
import { gitProtectionRoots } from "./targets.js";
import { CodexSecurityError } from "./errors.js";
import {
  canonicalizeModelSafePath,
  bundledPluginRoot,
  codexSecurityStateDirectory,
  workbenchEnvironment,
  requireOutputOutsideRepository,
  runWorkbench,
  type WorkbenchCommandOptions,
} from "./runtime.js";

/** @internal */
export class SeverityStore {
  private options?: Promise<Omit<WorkbenchCommandOptions, "python">>;

  constructor(
    private readonly environment: NodeJS.ProcessEnv,
    private readonly scanDirectory: string,
    private readonly signal?: AbortSignal,
    private readonly protectedRoots: readonly string[] = [],
  ) {}

  checkpoint(
    scanId: string,
    findingIds: string[],
    reprocess: boolean,
  ): SeverityClassificationCheckpoint {
    return {
      load: async (result) => {
        const response = await this.run("severity-classification", {
          action: "begin",
          scanId,
          findingIds,
          assessedAt: result.assessedAt,
          classificationRuns: result.classificationRuns,
          rubricSha256: result.rubricSha256,
          knowledgeBaseSha256: result.knowledgeBaseSha256,
        });
        return reprocess
          ? []
          : matchingClassification(
              response["assessments"] as JsonObject[],
              result,
            ).assessments;
      },
      save: async (finding, assessment, result) => {
        await this.run("severity-classification", {
          action: "save",
          scanId,
          finding,
          assessment: {
            ...assessment,
            classificationRuns: result.classificationRuns,
            rubricSha256: result.rubricSha256,
            knowledgeBaseSha256: result.knowledgeBaseSha256,
          },
        });
      },
    };
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
    const saved = await this.run("read-severity-classification", { scanId });
    if (saved["scanId"] === undefined) return undefined;
    const result = matchingClassification(
      saved["assessments"] as JsonObject[],
      {
        schemaVersion: 1,
        assessedAt: saved["assessedAt"] as string,
        classificationRuns: (saved["classificationRuns"] ?? undefined) as
          number | undefined,
        rubricSha256: saved["rubricSha256"] as string | null,
        knowledgeBaseSha256: saved["knowledgeBaseSha256"] as string | null,
      },
    );
    const findingIds = saved["findingIds"] as string[];
    if (result.assessments.length !== findingIds.length) {
      throw new CodexSecurityError(
        "Severity classification is incomplete or its inputs changed. Rerun classify-severity before publishing.",
      );
    }
    return result;
  }

  private async run(command: string, input: object) {
    return runWorkbench(
      await (this.options ??= this.resolveOptions()),
      [command],
      JSON.stringify(input),
    );
  }

  private async resolveOptions(): Promise<
    Omit<WorkbenchCommandOptions, "python">
  > {
    const environment = workbenchEnvironment(this.environment);
    requireOutputOutsideRepository(
      this.scanDirectory,
      await canonicalizeModelSafePath(environment.CODEX_SECURITY_STATE_DIR),
      "runtime",
    );
    return {
      pluginRoot: await bundledPluginRoot(),
      environment,
      protectedRoot: [
        this.scanDirectory,
        ...this.protectedRoots,
        ...(await gitProtectionRoots(process.cwd(), this.signal)),
        ...(await gitProtectionRoots(this.scanDirectory, this.signal)),
      ],
      signal: this.signal,
      failureMessage: "Could not access severity assessments",
    };
  }
}

function matchingClassification(
  stored: JsonObject[],
  result: Omit<SeverityClassification, "assessments">,
): SeverityClassification {
  return severityClassificationSchema.parse({
    ...result,
    assessments: stored
      .filter(
        (row) =>
          (row["classificationRuns"] ?? undefined) ===
            result.classificationRuns &&
          row["rubricSha256"] === result.rubricSha256 &&
          row["knowledgeBaseSha256"] === result.knowledgeBaseSha256,
      )
      .map(
        ({
          assessedAt: _assessedAt,
          classificationRuns: _runs,
          rubricSha256: _rubric,
          knowledgeBaseSha256: _knowledge,
          ...assessment
        }) => assessment,
      ),
  });
}
