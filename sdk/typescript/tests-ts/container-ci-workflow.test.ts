import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createTemporaryDirectoriesSync } from "./support/temporary-directories.js";
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
  const release = workflow("container-publish");
  expect(container.jobs["native"]).not.toHaveProperty("if");
  expect(container.jobs["container"]).not.toHaveProperty("if");
  expect(validation.jobs["validate"]).not.toHaveProperty("if");
  expect(Object.keys(release.on)).toEqual(["workflow_call"]);
  expect(release.jobs["source"]?.if).toBe(
    "github.workflow_ref == 'openai/codex-security/.github/workflows/node-github-release.yml@refs/heads/main'",
  );
  expect(release.jobs["authorize"]?.needs).toContain("source");
  expect(release.jobs["manifest"]?.needs).toContain("authorize");
});

test("stages the verified scanner archive and retains its locked dependencies", () => {
  const directories = createTemporaryDirectoriesSync();
  try {
    const root = directories.create("release image inputs ");
    const archive = join(root, "release.tgz");
    const runtimeLock = join(root, "runtime-lock.json");
    const bytes = Buffer.from("verified npm archive");
    const integrity =
      "sha512-" + createHash("sha512").update(bytes).digest("base64");
    const scanner = {
      version: "1.2.3",
      resolved: "https://registry.npmjs.org/scanner.tgz",
      integrity,
    };
    const packages = {
      "": { dependencies: { "@openai/codex-security": "1.2.3" } },
      "node_modules/@openai/codex-security": scanner,
      "node_modules/dependency": { version: "3.2.1", integrity: "unchanged" },
    };
    writeFileSync(archive, bytes);
    writeFileSync(
      runtimeLock,
      JSON.stringify({ lockfileVersion: 3, packages }),
    );
    const prepare = () =>
      execFileSync(
        process.execPath,
        [
          fileURLToPath(
            new URL(
              "../../../docker/prepare-release-package.mjs",
              import.meta.url,
            ),
          ),
          archive,
          runtimeLock,
          root,
        ],
        { stdio: "pipe" },
      );
    prepare();
    expect(readFileSync(join(root, "scanner.tgz"))).toEqual(bytes);
    expect(
      JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"))
        .packages,
    ).toEqual({
      ...packages,
      "node_modules/@openai/codex-security": {
        ...scanner,
        resolved: "file:scanner.tgz",
      },
    });
    writeFileSync(archive, "changed scanner bytes");
    expect(prepare).toThrow(
      "Scanner archive differs from the release runtime lock",
    );
  } finally {
    directories.cleanup();
  }
});
