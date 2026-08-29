import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import {
  FindingWorkflow,
  workflowDestination,
} from "../src/finding-workflow.js";
import type { CodexReview } from "../src/deduplication/codex-review.js";
import {
  CheckpointedReviewRunner,
  reviewSettingsDigest,
} from "../src/deduplication/checkpointed-review.js";
import type { DuplicateDecision } from "../src/deduplication/deduplication-reviewer.js";
import {
  checkpointWorkbench,
  scriptedWorkbench,
} from "./support/workbench-fakes.js";
import { workflowFixture } from "./support/workflow-fixture.js";

const distinct: DuplicateDecision = {
  decision: "DISTINCT",
  rationale: "Independent corrections are required.",
};

test.each([
  "finding",
  "source",
  "scope",
  "model",
  "effort",
  "prompt",
  "contract",
  "configuration",
])("does not reuse a checkpoint for changed %s inputs", async (changed) => {
  await using fixture = await workflowFixture();
  const { environment, repository, document } = fixture;
  const store = checkpointWorkbench(`changed-${changed}`, {
    repository,
    revision: "synthetic-revision",
    refsDigest: "synthetic-refs",
    content: "synthetic-content",
  });
  const workflow = new FindingWorkflow(
    `changed-${changed}`,
    environment,
    store.run,
  );
  let calls = 0;
  const runner = {
    async run<T>(review: CodexReview<T>): Promise<T> {
      calls++;
      return review.validate(distinct);
    },
  };
  const review: CodexReview<DuplicateDecision> = {
    model: "gpt-5.6-sol",
    effort: "ultra",
    prompt: JSON.stringify(document.findings),
    schema: { type: "object" },
    validate: () => distinct,
  };
  const source = await workflow.sourceSnapshot(repository);
  const scope = { repositoryId: "synthetic-repository" };
  const initial = new CheckpointedReviewRunner(
    workflow,
    runner,
    source,
    scope,
    await reviewSettingsDigest(environment),
  );
  await initial.run(review);
  await initial.run(review);
  expect(calls).toBe(1);
  if (changed === "source")
    store.source = { ...store.source, content: "changed-content" };
  if (changed === "configuration") {
    await mkdir(environment.CODEX_HOME);
    await writeFile(
      join(environment.CODEX_HOME, "config.toml"),
      'model_reasoning_summary = "none"\n',
    );
  }
  const next = { ...review };
  if (changed === "finding")
    next.prompt = JSON.stringify([
      { ...document.findings[0], title: "Changed original" },
    ]);
  if (changed === "model") next.model = "gpt-5.6-luna";
  if (changed === "effort") next.effort = "high";
  if (changed === "prompt") next.prompt += "Changed review contract";
  if (changed === "contract")
    next.schema = { type: "object", required: ["decision"] };
  const resumed = new CheckpointedReviewRunner(
    new FindingWorkflow(workflow.id, environment, store.run),
    runner,
    await workflow.sourceSnapshot(repository),
    changed === "scope" ? { allRepositories: true } : scope,
    await reviewSettingsDigest(environment),
  );
  await resumed.run(next);
  expect(calls).toBe(2);
});

test("does not checkpoint a review when source changes during its execution", async () => {
  await using fixture = await workflowFixture();
  const { environment, repository, document } = fixture;
  const store = checkpointWorkbench("source-drift", {
    repository,
    revision: "synthetic-revision",
    refsDigest: "synthetic-refs",
    content: "synthetic-content",
  });
  const workflow = new FindingWorkflow("source-drift", environment, store.run);
  const source = await workflow.sourceSnapshot(repository);
  const runner = new CheckpointedReviewRunner(
    workflow,
    {
      async run<T>(review: CodexReview<T>): Promise<T> {
        store.source = { ...store.source, content: "changed-during-review" };
        return review.validate(distinct);
      },
    },
    source,
    { allRepositories: true },
  );
  const review: CodexReview<DuplicateDecision> = {
    model: "gpt-5.6-sol",
    effort: "ultra",
    prompt: JSON.stringify(document.findings),
    schema: {},
    validate: () => distinct,
  };
  await expect(runner.run(review)).rejects.toThrow(
    "Source changed during deduplication",
  );
  expect(store.saved).toHaveLength(0);
  store.source = source;
  let calls = 0;
  await new CheckpointedReviewRunner(
    workflow,
    {
      async run<T>(review: CodexReview<T>): Promise<T> {
        calls++;
        return review.validate(distinct);
      },
    },
    source,
    { allRepositories: true },
  ).run(review);
  expect(calls).toBe(1);
});

test("returns a completed stage's saved result without running the operation", async () => {
  await using fixture = await workflowFixture();
  const result = { duplicateGroups: [] };
  const workbench = scriptedWorkbench([
    {
      request: { id: "completed", action: "begin", stage: "dedupe" },
      response: {
        workflow: { stages: { dedupe: { status: "completed", result } } },
      },
    },
  ]);
  const workflow = new FindingWorkflow(
    "completed",
    fixture.environment,
    workbench.run,
  );
  expect(
    await workflow.run<typeof result>("dedupe", async () => {
      throw new Error("Completed work must not run again");
    }),
  ).toEqual(result);
  workbench.assertDone();
});

test("preserves the operation error when recording a failed stage also fails", async () => {
  await using fixture = await workflowFixture();
  const failure = new Error("Synthetic publication failure");
  const workbench = scriptedWorkbench([
    {
      request: { id: "failed", action: "begin", stage: "publish" },
      response: { workflow: { stages: { publish: { status: "running" } } } },
    },
    {
      request: {
        id: "failed",
        action: "fail",
        stage: "publish",
        error: failure.message,
      },
      error: new Error("Synthetic unavailable persistence"),
    },
  ]);
  const workflow = new FindingWorkflow(
    "failed",
    fixture.environment,
    workbench.run,
  );
  await expect(
    workflow.run("publish", async () => {
      throw failure;
    }),
  ).rejects.toBe(failure);
  workbench.assertDone();
});

test("checks failure-recording requests even when the caller handles persistence errors", async () => {
  await using fixture = await workflowFixture();
  const workbench = scriptedWorkbench([
    {
      request: {
        id: "handled-failure",
        action: "fail",
        stage: "publish",
        error: "Synthetic expected failure",
      },
    },
  ]);
  const workflow = new FindingWorkflow(
    "handled-failure",
    fixture.environment,
    workbench.run,
  );
  await workflow.fail("publish", new Error("Synthetic different failure"));
  expect(() => workbench.assertDone()).toThrow("Synthetic expected failure");
});

test("rejects unexpected workbench commands after their errors are caught", async () => {
  const workbench = scriptedWorkbench([]);
  await expect(
    workbench.run(
      { environment: {}, pluginRoot: "unused", python: "unused" },
      ["unexpected-command"],
      "{}",
    ),
  ).rejects.toThrow();
  expect(() => workbench.assertDone()).toThrow();
});

test("normalizes a workflow destination without storing URL credentials", () => {
  expect(workflowDestination("http://synthetic:password@synthetic.test")).toBe(
    "http://synthetic.test/",
  );
});
