import { createTemporaryDirectoriesSync } from "./support/temporary-directories.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { parse } from "yaml";
import { runWorkflowScript } from "./support/workflow-script.js";

interface Step {
  id?: string;
  uses?: string;
  if?: string;
  run?: string;
  env?: Record<string, string>;
  with?: Record<string, unknown>;
}

const workflow = parse(
  readFileSync(
    new URL(
      "../../../examples/github-actions/codex-security.yml",
      import.meta.url,
    ),
    "utf8",
  ),
) as {
  on: Record<string, unknown>;
  jobs: {
    scan: {
      if: string;
      env: Record<string, string>;
      steps: Step[];
    };
  };
};
const job = workflow.jobs.scan;
const scan = job.steps.find((step) => step.id === "scan")!;
const sarif = job.steps.find((step) => step.id === "sarif")!;
const temporaryDirectories = createTemporaryDirectoriesSync();

afterEach(temporaryDirectories.cleanup);

function runStep(step: Step, overrides: Record<string, string> = {}) {
  const directory = temporaryDirectories.create("codex actions example ");
  // Git Bash accepts forward-slash drive paths on Windows.
  const root = directory.replaceAll("\\", "/");
  const result = runWorkflowScript(
    directory,
    step.run,
    {
      RUNNER_TEMP: root,
      GITHUB_WORKSPACE: `${root}/repository with spaces`,
      GITHUB_OUTPUT: `${root}/outputs`,
      EVENT_NAME: "workflow_dispatch",
      BASE_SHA: "",
      FAIL_ON_SEVERITY: "",
      ...overrides,
    },
    ["-e", "-o", "pipefail"],
    "$RUNNER_TEMP/arguments",
  );
  const args = readFileSync(join(directory, "arguments"), "utf8")
    .split("\0")
    .slice(0, -1);
  return { ...result, directory, root, args };
}

test("scans PR changes at the default merge checkout with literal arguments", () => {
  const base = "a".repeat(40);
  const result = runStep(scan, {
    EVENT_NAME: "pull_request",
    BASE_SHA: base,
  });
  expect(result.status).toBe(0);
  expect(result.args.slice(0, 2)).toEqual([
    "scan",
    `${result.root}/repository with spaces`,
  ]);
  expect(result.args.slice(-2)).toEqual(["--diff", base]);
  const checkout = job.steps.find((step) =>
    step.uses?.startsWith("actions/checkout@"),
  )!;
  expect(checkout.with?.["fetch-depth"]).toBe(0);
  expect(checkout.with?.["persist-credentials"]).toBe(false);
  expect(checkout.with?.["ref"]).toBeUndefined();
});

for (const event of ["workflow_dispatch", "schedule"]) {
  test(`${event} scans the full repository without a severity gate by default`, () => {
    const result = runStep(scan, { EVENT_NAME: event });
    expect(result.status).toBe(0);
    expect(result.args).not.toContain("--diff");
    expect(result.args).not.toContain("--fail-on-severity");
    expect(job.env["FAIL_ON_SEVERITY"]).toBe("");
  });
}

for (const status of [0, 1, 2, 130]) {
  test(`preserves scan exit ${status} and writes its result for later steps`, () => {
    const result = runStep(scan, {
      MOCK_EXIT_CODE: String(status),
      FAIL_ON_SEVERITY: "high",
    });
    expect(result.status).toBe(status);
    expect(result.args.slice(-2)).toEqual(["--fail-on-severity", "high"]);
    expect(readFileSync(join(result.directory, "outputs"), "utf8")).toBe(
      `exit-code=${status}\n`,
    );
    expect(
      JSON.parse(
        readFileSync(
          join(result.directory, "codex-security-result.json"),
          "utf8",
        ),
      ),
    ).toEqual({ mock: true });
  });
}

test("exports the completed scan with source-root fingerprints outside the checkout", () => {
  const result = runStep(sarif);
  expect(result.status).toBe(0);
  expect(result.args).toEqual([
    "export",
    `${result.root}/codex-security-scan`,
    "--export-format",
    "sarif",
    "--source-root",
    `${result.root}/repository with spaces`,
    "--output",
    `${result.root}/codex-security.sarif`,
  ]);
  expect(sarif.if).toBe(
    "${{ !cancelled() && (steps.scan.outputs.exit-code == '0' || steps.scan.outputs.exit-code == '1') }}",
  );
  const upload = job.steps.find((step) =>
    step.uses?.startsWith("github/codeql-action/upload-sarif@"),
  )!;
  expect(upload.if).toBe(
    "${{ !cancelled() && steps.sarif.outcome == 'success' }}",
  );
});

test("keeps credentials scoped and skips untrusted PR workflows", () => {
  expect(workflow.on).toHaveProperty("pull_request");
  expect(workflow.on).not.toHaveProperty("pull_request_target");
  expect(job.if).toContain(
    "github.event.pull_request.head.repo.full_name == github.repository",
  );
  expect(job.if).toContain("github.actor != 'dependabot[bot]'");
  const aws = job.steps.find((step) => step.id === "aws")!;
  expect(aws.with?.["output-env-credentials"]).toBe(false);
  expect(aws.with?.["output-credentials"]).toBe(true);
  expect(scan.env).toHaveProperty("AWS_SESSION_TOKEN");
  for (const step of job.steps) {
    expect(step.env ?? {}).not.toHaveProperty("GH_TOKEN");
    expect(step.env ?? {}).not.toHaveProperty("GITHUB_TOKEN");
    if (step.uses) expect(step.uses).toMatch(/@[a-f0-9]{40}$/);
  }
});
