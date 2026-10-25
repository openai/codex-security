import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";

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
const { selectChecks } = (await import(
  new URL("../../../.github/scripts/select-ci-checks.mjs", import.meta.url).href
)) as {
  selectChecks(
    paths: string[],
    options: { event: string; baseChanged: boolean },
  ): Record<string, string>;
};

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
    needs: ["classify-changes", "native", "static-checks"],
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
  for (const name of ["source", "validate", "authorize"]) {
    expect(release.jobs[name]?.if).toBe(
      "github.repository == 'openai/codex-security'",
    );
  }
  expect(release.jobs["native"]?.if).toBe(
    "github.repository == 'openai/codex-security' && needs.source.outputs.existing-digest == ''",
  );
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
  ["pull_request", false, "sdk/typescript/scripts/run-ci-tests.mts", true],
  [
    "pull_request",
    false,
    "plugins/codex-security/skills/example/SKILL.md",
    true,
  ],
] as const)(
  "selects container validation for %s / retarget=%p / %s",
  (eventName, baseChanged, path, selected) => {
    const outputs = selectChecks([path], { event: eventName, baseChanged });
    expect(outputs["container-validate"]).toBe(String(selected));
  },
);

test("the final CI gate executes selected container failures and permits unselected checks", () => {
  const gate = ci.jobs["ci"]!;
  expect(gate.needs).toContain("container-validate");
  expect(gate.if).toContain("always()");
  const step = gate.steps!.find(
    (step) => step.name === "Require selected checks",
  )!;
  const [command, script] = step.run!.split(" ");
  expect(command).toBe("node");
  for (const selected of [true, false]) {
    const outputs = selectChecks([selected ? "Dockerfile" : "README.md"], {
      event: "pull_request",
      baseChanged: false,
    });
    const needs = Object.fromEntries(
      (gate.needs as string[]).map((name) => [name, { result: "success" }]),
    );
    const classified = {
      ...needs,
      "classify-changes": { result: "success", outputs },
      "action-ci": { result: "success", outputs: { passed: "true" } },
    };
    for (const result of ["success", "failure", "cancelled", "skipped"]) {
      const execution = spawnSync(
        command!,
        [fileURLToPath(new URL(`../../../${script}`, import.meta.url))],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            CI_RESULTS: JSON.stringify({
              ...classified,
              "container-validate": { result },
            }),
          },
        },
      );
      expect(execution.status, execution.stderr).toBe(
        selected && result !== "success" ? 1 : 0,
      );
      if (selected && result !== "success")
        expect(execution.stderr).toContain("container-validate");
    }
  }
});
