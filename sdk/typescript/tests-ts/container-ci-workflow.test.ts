import { readFileSync } from "node:fs";
import { expect, test } from "bun:test";

type Job = {
  uses?: string;
  needs?: string | string[];
  if?: string;
  steps?: Array<{ name?: string }>;
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
    if: "needs.classify-changes.outputs.container-required == 'true'",
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
