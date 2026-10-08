import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { bashCommand } from "./support/shell.js";

type Step = { name?: string; uses?: string; run?: string; if?: string };
type Job = {
  uses?: string;
  needs?: string | string[];
  if?: string;
  steps?: Step[];
  strategy?: { matrix: { include: Array<{ architecture: string }> } };
};

function workflow(name: string) {
  return Bun.YAML.parse(
    readFileSync(
      new URL(`../../../.github/workflows/${name}.yml`, import.meta.url),
      "utf8",
    ),
  ) as { on: Record<string, unknown>; jobs: Record<string, Job> };
}

const ci = workflow("node-ci");
const bash = bashCommand();

test("shares one native build and container matrix in automatic CI", () => {
  const container = workflow("container-ci");
  const validation = workflow("container-validate");
  expect(Object.keys(container.on)).toEqual(["workflow_dispatch"]);
  expect(
    Object.values(ci.jobs).filter(
      (job) => job.uses === "./.github/workflows/native-artifacts.yml",
    ),
  ).toHaveLength(1);
  expect(
    Object.values(ci.jobs).filter((job) =>
      job.uses?.startsWith("./.github/workflows/container-"),
    ),
  ).toEqual([ci.jobs["container-validate"]!]);
  expect(ci.jobs["container-validate"]).toMatchObject({
    needs: ["validate-title", "native"],
    uses: "./.github/workflows/container-validate.yml",
  });
  expect(container.jobs["container"]).toMatchObject({
    needs: "native",
    uses: "./.github/workflows/container-validate.yml",
  });
  expect(
    validation.jobs["validate"]?.strategy?.matrix.include.map(
      ({ architecture }) => architecture,
    ),
  ).toEqual(["amd64", "arm64"]);
  const steps = validation.jobs["validate"]!.steps!;
  for (const name of [
    "Verify customer build excludes secrets and scan data",
    "Reject interactive repository discovery",
    "Verify hardened Codex command sandbox",
    "Verify host-scoped Git credentials",
    "Verify findings API and persistent storage through consumer Compose",
  ]) {
    expect(steps.filter((step) => step.name === name)).toHaveLength(1);
  }
});

test("keeps container validation available to forks and publication upstream-only", () => {
  const container = workflow("container-ci");
  const validation = workflow("container-validate");
  const release = workflow("container-release");
  expect(container.jobs["native"]).not.toHaveProperty("if");
  expect(container.jobs["container"]).not.toHaveProperty("if");
  expect(validation.jobs["validate"]).not.toHaveProperty("if");
  for (const name of ["native", "validate", "authorize"]) {
    expect(release.jobs[name]?.if).toBe(
      "github.repository == 'openai/codex-security'",
    );
  }
  expect(release.jobs["publish-platform"]?.needs).toBe("authorize");
});

test.each([
  ["push", false, "README.md", true],
  ["pull_request", true, "README.md", true],
  ["pull_request", false, "README.md", false],
  ["pull_request", false, "Dockerfile", true],
  ["pull_request", false, ".github/workflows/container-ci.yml", true],
  ["pull_request", false, ".github/workflows/container-validate.yml", true],
  ["pull_request", false, ".github/workflows/container-release.yml", true],
  ["pull_request", false, ".github/workflows/native-windows.yml", true],
  ["pull_request", false, ".github/workflows/node-ci.yml", true],
  ["pull_request", false, ".github/actions/setup-tools/action.yml", true],
  ["pull_request", false, "sdk/typescript/src/index.ts", true],
  [
    "pull_request",
    false,
    "plugins/codex-security/skills/example/SKILL.md",
    true,
  ],
] as const)(
  "selects container validation for %s / retarget=%p / %s",
  (eventName, baseChanged, path, selected) => {
    const directory = mkdtempSync(join(tmpdir(), "container-ci-scope-"));
    const output = join(directory, "outputs");
    const script = ci.jobs["validate-title"]!.steps!.find(
      (step) => step.name === "Select additional checks",
    )!.run!;
    try {
      const result = spawnSync(
        bash,
        ["-c", `git() { printf '%s\\0' "$CHANGED_PATH"; }\n${script}`],
        {
          env: {
            ...process.env,
            EVENT_NAME: eventName,
            BASE_CHANGED: String(baseChanged),
            CHANGED_PATH: path,
            GITHUB_OUTPUT: output,
          },
        },
      );
      expect(result.status).toBe(0);
      const outputs = Object.fromEntries(
        readFileSync(output, "utf8")
          .trim()
          .split("\n")
          .map((line) => line.split("=")),
      );
      expect(outputs["container-validate"]).toBe(String(selected));
      if (path === ".github/actions/setup-tools/action.yml") {
        expect(outputs["test-quality"]).toBe("true");
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  },
);

test("required CI rejects failed, cancelled, or skipped selected container checks", () => {
  const gate = ci.jobs["required-test"]!;
  expect(gate.needs).toContain("container-validate");
  expect(gate.if).toBe("always()");
  const step = gate.steps!.find(
    (step) => step.name === "Require selected container coverage",
  )!;
  expect(step.run).toBe("exit 1");
  for (const selected of ["true", "false"]) {
    for (const result of ["success", "failure", "cancelled", "skipped"]) {
      const condition = step
        .if!.replaceAll(
          "needs.validate-title.outputs.container-validate",
          `'${selected}'`,
        )
        .replaceAll("needs.container-validate.result", `'${result}'`);
      const evaluation = spawnSync(bash, ["-c", `[[ ${condition} ]]`]);
      expect(evaluation.status, `${selected}/${result}`).toBe(
        selected === "true" && result !== "success" ? 0 : 1,
      );
    }
  }
});
