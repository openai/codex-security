import { createHash } from "node:crypto";
import { isAbsolute, relative, sep } from "node:path";
import type { JsonObject } from "./config.js";
import { CodexSecurityError, safeErrorMessage } from "./errors.js";
import type { FindingSearchScope } from "./finding-retrieval.js";
import {
  bundledPluginRoot,
  canonicalizeModelSafePath,
  codexSecurityStateDirectory,
  resolvePluginPython,
  runWorkbench,
  type WorkbenchCommandOptions,
} from "./runtime.js";

export type WorkflowStage = "scan" | "publish" | "dedupe";
export interface WorkflowBinding {
  repositoryPath?: string;
  scanRequestDigest?: string;
  scanId?: string;
  scanDir?: string;
  artifactDigest?: string;
  destination?: string;
  scope?: FindingSearchScope;
}
export interface WorkflowState extends WorkflowBinding {
  id: string;
  stages: Record<
    WorkflowStage,
    {
      status: "pending" | "running" | "failed" | "completed";
      result?: unknown;
      error?: string;
      pendingWrite?: { groups: string[][] };
    }
  >;
}

export function workflowDigest(value: unknown): string {
  const json = JSON.stringify(value, (_key, item: unknown) =>
    item !== null && typeof item === "object" && !Array.isArray(item)
      ? Object.fromEntries(
          Object.entries(item).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        )
      : item,
  );
  return createHash("sha256").update(json).digest("hex");
}

export function workflowDestination(url: string): string {
  const route = "v1/bulk/findings";
  const destination = new URL(route, url.endsWith("/") ? url : `${url}/`);
  destination.username = "";
  destination.password = "";
  return destination.href.slice(0, -route.length);
}

/** State lives in the workbench database, never in sealed scan artifacts. */
export class FindingWorkflow {
  private options?: Promise<WorkbenchCommandOptions>;

  constructor(
    readonly id: string,
    private readonly environment: NodeJS.ProcessEnv = process.env,
    private readonly workbench: typeof runWorkbench = runWorkbench,
    private readonly pythonPath?: string,
  ) {
    if (!id.trim())
      throw new CodexSecurityError("workflowId must be a nonempty string.");
  }

  async protectArtifacts(scanDir: string): Promise<void> {
    const path = relative(
      await canonicalizeModelSafePath(scanDir),
      await canonicalizeModelSafePath(
        codexSecurityStateDirectory(this.environment),
      ),
    );
    if (
      path === "" ||
      (!isAbsolute(path) && path !== ".." && !path.startsWith(`..${sep}`))
    ) {
      throw new CodexSecurityError(
        "Workflow state must be outside the sealed scan artifacts.",
      );
    }
  }

  async get(): Promise<WorkflowState | null> {
    return (await this.command({ action: "get" })) as WorkflowState | null;
  }

  async bind(binding: WorkflowBinding): Promise<WorkflowState> {
    return (await this.command({ action: "bind", binding }))!;
  }

  async begin(stage: WorkflowStage): Promise<WorkflowState> {
    return (await this.command({ action: "begin", stage }))!;
  }

  async complete(
    stage: WorkflowStage,
    result: unknown,
  ): Promise<WorkflowState> {
    return (await this.command({ action: "complete", stage, result }))!;
  }

  async fail(stage: WorkflowStage, error: unknown): Promise<void> {
    await this.command({
      action: "fail",
      stage,
      error: safeErrorMessage(error),
    }).catch(() => undefined);
  }

  async run<T>(stage: WorkflowStage, operation: () => Promise<T>): Promise<T> {
    const state = await this.begin(stage);
    if (state.stages[stage].status === "completed")
      return state.stages[stage].result as T;
    try {
      const result = await operation();
      await this.complete(stage, result);
      return result;
    } catch (error) {
      await this.fail(stage, error);
      throw error;
    }
  }

  async registeredScan(scanId: string): Promise<JsonObject> {
    const context = await this.call(["get-scan", "--scan-id", scanId]);
    return context["scan"] as JsonObject;
  }

  async sourceSnapshot(repository: string): Promise<JsonObject> {
    return (await this.request({ action: "source", repository }))[
      "source"
    ] as JsonObject;
  }

  async getReview(key: string): Promise<unknown> {
    return (await this.request({ action: "get-review", key }))["review"];
  }

  async saveReview(
    key: string,
    binding: object,
    result: unknown,
  ): Promise<void> {
    await this.request({ action: "save-review", key, binding, result });
  }

  async prepareDedupe(
    result: unknown,
    pendingWrite: { groups: string[][] },
  ): Promise<void> {
    await this.command({
      action: "prepare-dedupe",
      stage: "dedupe",
      result,
      pendingWrite,
    });
  }

  private async command(payload: object): Promise<WorkflowState | null> {
    const result = await this.request(payload);
    return result["workflow"] as unknown as WorkflowState | null;
  }

  private async request(payload: object): Promise<JsonObject> {
    return await this.call(
      ["finding-workflow"],
      JSON.stringify({ id: this.id, ...payload }),
    );
  }

  private async call(
    args: readonly string[],
    input?: string,
  ): Promise<JsonObject> {
    this.options ??= (async () => ({
      pluginRoot: await bundledPluginRoot(),
      python: await resolvePluginPython({
        environment: this.environment,
        configuredPath: this.pythonPath,
      }),
      environment: {
        ...this.environment,
        CODEX_SECURITY_STATE_DIR: codexSecurityStateDirectory(this.environment),
      },
      failureMessage: "Could not save or resume the findings workflow",
    }))();
    return await this.workbench(await this.options, args, input);
  }
}
