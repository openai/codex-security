import type { JsonObject } from "../config.js";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { CodexSecurityError } from "../errors.js";
import type { FindingSearchScope } from "../finding-retrieval.js";
import { FindingWorkflow, workflowDigest } from "../finding-workflow.js";
import { CODEX_EXECUTABLE_VERSION } from "../version.js";
import {
  codexSecurityCredentialHome,
  expandHome,
  resolveCodexCommand,
} from "../runtime.js";
import type { CodexReview, CodexReviewRunner } from "./codex-review.js";
import {
  reviewSubmissionInstructions,
  sourceReviewInstructions,
} from "./deduplication-prompts.js";

// Increment when validation or review execution changes without a prompt/schema change.
const REVIEW_CONTRACT_VERSION = 1;

export async function reviewSettingsDigest(
  environment: NodeJS.ProcessEnv,
): Promise<string> {
  const homes = new Set([
    expandHome(
      environment["CODEX_HOME"] ?? join(homedir(), ".codex"),
      environment,
    ),
    codexSecurityCredentialHome(environment),
  ]);
  const configs = await Promise.all(
    [...homes].map(async (home) => {
      try {
        return await readFile(join(home, "config.toml"), "utf8");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw error;
      }
    }),
  );
  return workflowDigest({
    configs,
    command: resolveCodexCommand(environment),
    baseUrl: environment["OPENAI_BASE_URL"],
  });
}

export class CheckpointedReviewRunner {
  constructor(
    private readonly workflow: FindingWorkflow,
    private readonly runner: Pick<CodexReviewRunner, "run">,
    private readonly source: JsonObject,
    private readonly scope: FindingSearchScope,
    private readonly settingsDigest?: string,
  ) {}

  async assertSourceUnchanged(): Promise<void> {
    const current = await this.workflow.sourceSnapshot(
      this.source["repository"] as string,
    );
    if (workflowDigest(current) !== workflowDigest(this.source))
      throw new CodexSecurityError(
        "Source changed during deduplication. Restart the workflow to review the changed inputs.",
      );
  }

  async run<T>(review: CodexReview<T>): Promise<T> {
    const binding = {
      version: REVIEW_CONTRACT_VERSION,
      codexVersion: CODEX_EXECUTABLE_VERSION,
      source: this.source,
      scope: this.scope,
      model: review.model,
      effort: review.effort,
      settingsDigest: this.settingsDigest,
      promptDigest: workflowDigest([
        reviewSubmissionInstructions,
        sourceReviewInstructions,
        review.prompt,
      ]),
      contractDigest: workflowDigest(review.schema),
    };
    const key = workflowDigest(binding);
    const saved = await this.workflow.getReview(key);
    if (saved !== null) return review.validate(saved);
    const result = review.validate(await this.runner.run(review));
    await this.assertSourceUnchanged();
    await this.workflow.saveReview(key, binding, result);
    return result;
  }
}
