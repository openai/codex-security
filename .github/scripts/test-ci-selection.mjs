import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { selectChecks } from "./select-ci-checks.mjs";
import { failedChecks } from "./check-ci-results.mjs";

const select = (paths, options = {}) =>
  selectChecks(paths, { event: "pull_request", ...options });

test("only ordinary documentation can skip source qualification", () => {
  assert.equal(
    select(["README.md", "docs/bedrock.md"])["source-required"],
    "false",
  );
  for (const path of [
    "plugins/codex-security/skills/security-scan/SKILL.md",
    "plugins/codex-security/references/core-scan.md",
    "plugins/codex-security/schemas/finding.schema.json",
    "sdk/typescript/src/api.ts",
    "new-runtime/file",
    "AGENTS.md",
  ]) {
    assert.equal(select(["README.md", path])["source-required"], "true", path);
  }
  assert.equal(select([])["source-required"], "true");
  assert.equal(
    select(["README.md"], { baseChanged: true })["source-required"],
    "true",
  );
});

test("packaged SDK documentation keeps package validation selected", () => {
  const manifest = JSON.parse(
    readFileSync(
      new URL("../../sdk/typescript/package.json", import.meta.url),
      "utf8",
    ),
  );
  for (const file of manifest.files.filter((file) => file.endsWith(".md"))) {
    const path = `sdk/typescript/${file}`;
    const selected = select([path]);
    assert.equal(selected["source-required"], "true", path);
    assert.equal(selected["container-validate"], "true", path);
  }
  // The --no-renames diff reports the old path when a required doc is renamed.
  const renamed = select([
    "sdk/typescript/docs/hosted-scans.md",
    "docs/hosted-scans.md",
  ]);
  assert.equal(renamed["source-required"], "true");
  assert.equal(
    select(["README.md", "sdk/typescript/README.md"])["source-required"],
    "true",
  );
});

test("release helper changes select their release-progress regression checks", () => {
  assert.equal(
    select(["sdk/typescript/scripts/release-pr.mjs"])["workflow-quality"],
    "true",
  );
});

test("regular PRs retain supported Node minimums, current Action runtime and native Python coverage", () => {
  const selected = select(["sdk/typescript/src/cost.ts"]);
  assert.deepEqual(JSON.parse(selected["compatibility-matrix"]).include, [
    { os: "ubuntu-latest", node: "22.13.0" },
    { os: "ubuntu-latest", node: "24.0.0" },
    { os: "ubuntu-latest", node: "24" },
    { os: "ubuntu-latest", node: "26.0.0" },
    { os: "macos-latest", node: "22.13.0" },
  ]);
  assert.deepEqual(JSON.parse(selected["windows-node-matrix"]).node, [
    "22.13.0",
  ]);
  assert.deepEqual(
    JSON.parse(selected["python-matrix"]).include.map(({ os, python }) => [
      os,
      python,
    ]),
    [
      ["ubuntu-latest", "3.12"],
      ["macos-latest", "3.12"],
      ["windows-latest", "3.12"],
    ],
  );
});

test("runtime and Python build inputs expand the corresponding version matrix", () => {
  for (const path of [
    "package.json",
    "sdk/typescript/pnpm-lock.yaml",
    "plugins/codex-security/native/src/lib.rs",
    "sdk/typescript/scripts/build-plugin.mjs",
    ".github/workflows/node-ci.yml",
  ]) {
    const selected = select([path]);
    assert.equal(
      JSON.parse(selected["compatibility-matrix"]).include.length,
      6,
      path,
    );
    assert.equal(
      JSON.parse(selected["windows-node-matrix"]).node.length,
      2,
      path,
    );
  }
  for (const path of [
    "plugins/codex-security/scripts/workbench_db.py",
    "plugins/codex-security/tests/test_database.py",
    "plugins/codex-security/requirements-test.txt",
    "plugins/codex-security/pyproject.toml",
    "plugins/codex-security/schemas/finding.schema.json",
    ".github/actions/setup-tools/action.yml",
  ]) {
    assert.equal(
      JSON.parse(select([path])["python-matrix"]).include.length,
      5,
      path,
    );
  }
});

test("main, scheduled, manual and retargeted qualification use full matrices", () => {
  for (const options of [
    { event: "push" },
    { event: "schedule" },
    { event: "workflow_dispatch" },
    { baseChanged: true },
  ]) {
    const selected = select(["README.md"], options);
    assert.equal(selected["source-required"], "true");
    assert.equal(
      JSON.parse(selected["compatibility-matrix"]).include.length,
      6,
    );
    assert.equal(JSON.parse(selected["windows-node-matrix"]).node.length, 2);
    assert.equal(JSON.parse(selected["python-matrix"]).include.length, 5);
  }
});

test("the final gate rejects every missing or unsuccessful selected check", () => {
  const outputs = select([".github/workflows/node-ci.yml"]);
  const needs = Object.fromEntries(
    [
      "static-checks",
      "native",
      "package",
      "test",
      "compatibility",
      "mcp",
      "plugin-host",
      "plugin-source",
      "windows-test",
      "windows-verify",
      "workflow-quality",
      "container-validate",
    ].map((name) => [name, { result: "success" }]),
  );
  needs["classify-changes"] = { result: "success", outputs };
  assert.deepEqual(failedChecks(needs), []);
  for (const name of Object.keys(needs)) {
    for (const result of ["failure", "cancelled", "skipped", undefined]) {
      assert.deepEqual(
        failedChecks({ ...needs, [name]: { ...needs[name], result } }),
        [name],
      );
    }
  }
});

test("documentation requires static checks and explicit selection, without skipped source failures", () => {
  const outputs = select(["README.md"]);
  const needs = {
    "classify-changes": { result: "success", outputs },
    "static-checks": { result: "success" },
  };
  assert.deepEqual(failedChecks(needs), []);
  assert.deepEqual(
    failedChecks({ ...needs, "static-checks": { result: "failure" } }),
    ["static-checks"],
  );
  for (const key of [
    "source-required",
    "workflow-quality",
    "container-validate",
  ]) {
    assert.deepEqual(
      failedChecks({
        ...needs,
        "classify-changes": {
          result: "success",
          outputs: { ...outputs, [key]: undefined },
        },
      }),
      [`${key} classification`],
    );
  }
});
