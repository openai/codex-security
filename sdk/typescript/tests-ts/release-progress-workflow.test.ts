import { expect, test } from "bun:test";
import { renderProgress } from "../../../.github/scripts/release-progress.mjs";
import { workflow } from "./support/workflow.js";

const progress = workflow("release-progress");
const identifyJob = progress.jobs["identify"]!;

const sha = "a".repeat(40);
const releasePull = {
  title: "chore(release): 99.1.2",
  merged_at: "2026-01-01T00:00:00Z",
  base: { ref: "main" },
};
const ciRun = {
  id: 101,
  path: ".github/workflows/node-ci.yml",
  event: "push",
  head_branch: "main",
  head_sha: sha,
};

function identify(
  run: Record<string, unknown>,
  pages: Array<Array<typeof releasePull>> = [[releasePull]],
  manual = false,
) {
  const output: string[] = [];
  const calls: string[][] = [];
  const execute = new Function(
    "require",
    "process",
    identifyJob.steps![0]!.run!,
  );
  execute(
    (name: string) => {
      if (name === "node:fs")
        return {
          readFileSync: () =>
            JSON.stringify(manual ? {} : { workflow_run: run }),
          appendFileSync: (_path: string, value: string) => output.push(value),
        };
      expect(name).toBe("node:child_process");
      return {
        execFileSync: (command: string, args: string[]) => {
          expect(command).toBe("gh");
          calls.push(args);
          if (args[1] === "repos/example/security-tool/actions/runs/101")
            return JSON.stringify(run);
          expect(args).toEqual([
            "api",
            `repos/example/security-tool/commits/${sha}/pulls?per_page=100`,
            "--paginate",
            "--slurp",
          ]);
          return JSON.stringify(pages);
        },
      };
    },
    {
      env: {
        GITHUB_REPOSITORY: "example/security-tool",
        GITHUB_EVENT_PATH: "event.json",
        GITHUB_OUTPUT: "outputs",
        RELEASE_RUN_ID: "101",
      },
    },
  );
  return { output: output.join(""), calls };
}

test("release verification reports a failed Darwin signer when publication is skipped", () => {
  const release = workflow("node-release");
  const jobName = release.jobs["sign-darwin"]?.name ?? "sign-darwin";
  const progress = renderProgress(
    { "node-release": { status: "completed", conclusion: "failure" } },
    {
      "node-release": [
        { name: "native / bundle", status: "completed", conclusion: "success" },
        {
          name: `${jobName} / sign`,
          status: "completed",
          conclusion: "failure",
        },
        { name: "verify", status: "completed", conclusion: "skipped" },
        {
          name: "Publish npm and container images",
          status: "completed",
          conclusion: "skipped",
        },
      ],
    },
    false,
  );
  expect(progress).toContain("| Release verification | Failed |");
});

test("main CI completions report independently of cutting a release", () => {
  expect(progress.on).toHaveProperty("workflow_call");
  expect(progress.on["workflow_run"]).toEqual({
    workflows: ["node-release", "node-github-release"],
    types: ["in_progress", "completed"],
  });
  const cut = workflow("node-release-cut");
  const cutJob = cut.jobs["cut"]!;
  const report = cut.jobs["progress"]!;
  expect(cut.on).toEqual({
    workflow_run: {
      workflows: ["node-ci"],
      types: ["completed"],
      branches: ["main"],
    },
    workflow_dispatch: null,
  });
  const verifiedSha = "${{ github.event.workflow_run.head_sha || github.sha }}";
  expect(cutJob.env!["RELEASE_SHA"]).toBe(verifiedSha);
  expect(
    cutJob.steps!.find(({ uses }) => uses?.startsWith("actions/checkout@"))
      ?.with?.["ref"],
  ).toBe(verifiedSha);
  expect(report.uses).toBe("./.github/workflows/release-progress.yml");
  expect(cutJob).not.toHaveProperty("needs");
  expect(report).not.toHaveProperty("needs");
  expect(cutJob).toHaveProperty("concurrency", {
    group: "node-release-cut",
    queue: "max",
  });
  const selected = new Function("github", `return (${report.if})`);
  const context = {
    repository: "openai/codex-security",
    event_name: "workflow_run",
    event: { workflow_run: ciRun },
  };
  for (const conclusion of ["success", "failure", "cancelled"]) {
    expect(
      selected({
        ...context,
        event: { workflow_run: { ...ciRun, conclusion } },
      }),
    ).toBe(true);
  }
  expect(selected({ ...context, event_name: "workflow_dispatch" })).toBe(false);
  expect(
    selected({
      ...context,
      event: { workflow_run: { ...ciRun, event: "pull_request" } },
    }),
  ).toBe(false);
});

test("ordinary CI commits do not reach release checkout or reporting", () => {
  for (const pull of [
    { ...releasePull, title: "fix: improve reporting" },
    { ...releasePull, title: "chore(release): improve automation" },
    { ...releasePull, title: "chore(release): 99.1.2-beta.1" },
    { ...releasePull, merged_at: "" },
    { ...releasePull, base: { ref: "maintenance" } },
  ]) {
    expect(identify(ciRun, [[pull]]).output).toBe("");
  }
  expect(identify(ciRun, [[]]).output).toBe("");
  expect(identifyJob.steps!.every((step) => !step.uses)).toBe(true);
  expect(identifyJob.permissions).toEqual({
    actions: "read",
    contents: "read",
    "pull-requests": "read",
  });
});

test("release identification uses merged PRs across pages, not commit titles", () => {
  for (const title of [
    "chore(release): 99.1.2",
    "chore(release)!: 99.1.2",
    "release!: 99.1.2",
    "release(npm): 99.1.2",
  ]) {
    expect(
      identify({ ...ciRun, display_title: "A custom merge title" }, [
        [],
        [{ ...releasePull, title }],
      ]).output,
    ).toBe("version=99.1.2\n");
  }
  expect(identify({ ...ciRun, event: "pull_request" }).calls).toEqual([]);
  expect(identify({ ...ciRun, head_branch: "feature" }).calls).toEqual([]);
});

test("release stages share a version key without requiring a version-bump commit", () => {
  for (const run of [
    {
      ...ciRun,
      path: ".github/workflows/node-release.yml@npm-v99.1.2",
      head_branch: "npm-v99.1.2",
    },
    {
      ...ciRun,
      path: ".github/workflows/node-github-release.yml@main",
      event: "workflow_dispatch",
      display_title: "Publish npm-v99.1.2",
    },
  ]) {
    expect(identify(run).output).toBe("version=99.1.2\n");
    expect(identify(run).calls).toEqual([]);
    expect(identify(run, [], true).output).toBe("version=99.1.2\n");
    expect(identify({ ...run, event: "pull_request" }).output).toBe("");
  }
  expect(
    identify({ ...ciRun, path: ".github/workflows/other.yml" }).output,
  ).toBe("");
});

function refreshGroup(
  id: number,
  action: string,
  name: string,
  inputs: Record<string, unknown> = {},
) {
  return progress.concurrency!.group.replace(
    /\$\{\{(.*?)\}\}/gu,
    (_, expression) =>
      String(
        new Function(
          "github",
          "inputs",
          `return ${expression.replaceAll("inputs.run-id", 'inputs["run-id"]')}`,
        )(
          { run_id: id, event: { action, workflow_run: { id: 101, name } } },
          inputs,
        ),
      ),
  );
}

test("same-run refreshes coalesce without blocking observers or other stages", () => {
  const refresh = refreshGroup(201, "completed", "node-release");
  expect(refreshGroup(202, "", "", { "run-id": "101" })).toBe(refresh);
  expect(refreshGroup(203, "in_progress", "node-release")).not.toBe(refresh);
  expect(refreshGroup(204, "", "", { "run-id": "101", watch: true })).not.toBe(
    refresh,
  );
  expect(refreshGroup(205, "", "", { "run-id": "102" })).not.toBe(refresh);
  expect(progress.jobs["report"]!.concurrency).toEqual({
    group:
      "release-progress-${{ github.repository }}-${{ needs.identify.outputs.version }}",
    queue: "max",
  });
});
