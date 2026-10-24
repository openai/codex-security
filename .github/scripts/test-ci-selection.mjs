import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { selectChecks } from "./select-ci-checks.mjs";
import { failedChecks } from "./check-ci-results.mjs";

const select = (paths, options = {}) =>
  selectChecks(paths, { event: "pull_request", ...options });

const regularSource = {
  "source-required": "true",
  "workflow-quality": "false",
  "container-validate": "true",
  "compatibility-matrix": JSON.stringify({
    include: [
      { os: "ubuntu-latest", node: "22.13.0" },
      { os: "ubuntu-latest", node: "24.0.0" },
      { os: "ubuntu-latest", node: "24" },
      { os: "ubuntu-latest", node: "26.0.0" },
      { os: "macos-latest", node: "22.13.0" },
    ],
  }),
  "python-matrix": JSON.stringify({
    include: [
      { os: "ubuntu-latest", python: "3.12", markers: "" },
      {
        os: "macos-latest",
        python: "3.12",
        markers: "cross_platform or native_macos",
      },
      {
        os: "windows-latest",
        python: "3.12",
        markers: "cross_platform or native_windows",
      },
    ],
  }),
  "windows-node-matrix": JSON.stringify({ node: ["22.13.0"] }),
};
const fullQualification = {
  "source-required": "true",
  "workflow-quality": "true",
  "container-validate": "true",
  "compatibility-matrix": JSON.stringify({
    include: [
      { os: "ubuntu-latest", node: "22.13.0" },
      { os: "ubuntu-latest", node: "24.0.0" },
      { os: "ubuntu-latest", node: "24" },
      { os: "ubuntu-latest", node: "26.0.0" },
      { os: "ubuntu-latest", node: "26" },
      { os: "macos-latest", node: "22.13.0" },
    ],
  }),
  "python-matrix": JSON.stringify({
    include: [
      { os: "ubuntu-latest", python: "3.10", markers: "" },
      { os: "ubuntu-latest", python: "3.12", markers: "" },
      { os: "ubuntu-latest", python: "3.14", markers: "" },
      {
        os: "macos-latest",
        python: "3.12",
        markers: "cross_platform or native_macos",
      },
      {
        os: "windows-latest",
        python: "3.12",
        markers: "cross_platform or native_windows",
      },
    ],
  }),
  "windows-node-matrix": JSON.stringify({ node: ["22.13.0", "24"] }),
};

test("only ordinary documentation can skip source qualification", () => {
  assert.deepEqual(select(["README.md", "docs/bedrock.md"]), {
    ...regularSource,
    "source-required": "false",
    "container-validate": "false",
  });
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
    assert.deepEqual(selected, fullQualification, path);
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

test("release recovery documentation keeps its SDK contract selected", () => {
  for (const paths of [["RELEASING.md"], ["README.md", "RELEASING.md"]]) {
    const outputs = select(paths);
    assert.deepEqual(outputs, fullQualification);
    // release-automation.test.ts validates the documented recovery marker.
    const missing = failedChecks({
      "classify-changes": { result: "success", outputs },
      "static-checks": { result: "success" },
    });
    assert.ok(missing.includes("test"));
  }
});

test("release helper changes select their release-progress regression checks", () => {
  assert.equal(
    select(["sdk/typescript/scripts/release-pr.mjs"])["workflow-quality"],
    "true",
  );
});

test("ordinary TypeScript source and tests retain the reduced version matrices", () => {
  for (const path of [
    "sdk/typescript/src/cost.ts",
    "sdk/typescript/tests-ts/skeleton.test.ts",
    "sdk/typescript/tests-ts/support/test-subprocess.ts",
    "plugins/codex-security/mcp-app/src/stdio-transport.ts",
    "plugins/codex-security/mcp-app/tests/test_deep_scan_executor.ts",
    "plugins/codex-security/mcp-app/tests/support/fixture.ts",
  ]) {
    assert.deepEqual(select([path]), regularSource, path);
    assert.deepEqual(select(["README.md", path]), regularSource, path);
  }
});

test("unknown paths and dependency configuration receive full qualification", () => {
  for (const paths of [
    ["new-runtime/file"],
    ["sdk/typescript/src/new-runtime.json"],
    ["sdk/typescript/src/runtime.mjs"],
    ["sdk/typescript/tests-ts/runtime.mts"],
    ["sdk/typescript/src-extra/runtime.ts"],
    ["plugins/codex-security/mcp-app/src/runtime.yaml"],
    ["plugins/codex-security/mcp-app/main.ts"],
    ["other/sdk/typescript/src/runtime.ts"],
    [".npmrc"],
    ["sdk/typescript/.npmrc"],
    ["plugins/codex-security/mcp-app/src/.npmrc"],
    ["pnpm-workspace.yaml"],
    ["sdk/typescript/pnpm-workspace.yaml"],
    ["plugins/codex-security/mcp-app/pnpm-workspace.yaml"],
    ["evals/triage-finding/pnpm-workspace.yaml"],
    ["README.md", "new-runtime/file"],
    ["sdk/typescript/src/cost.ts", "new-runtime/file"],
    // --no-renames reports both sides when source becomes an unknown input.
    ["sdk/typescript/src/runtime.ts", "new-runtime/runtime.ts"],
    ["sdk/typescript/src/runtime.ts", "sdk/typescript/.npmrc"],
  ]) {
    assert.deepEqual(select(paths), fullQualification, paths.join(", "));
  }
});

test("tooling and non-TypeScript product inputs receive full qualification", () => {
  for (const path of [
    "package.json",
    "sdk/typescript/pnpm-lock.yaml",
    "sdk/typescript/bunfig.toml",
    "sdk/typescript/tsconfig.json",
    "plugins/codex-security/native/src/lib.rs",
    "sdk/typescript/scripts/build-plugin.mjs",
    ".github/workflows/node-ci.yml",
    "plugins/codex-security/scripts/workbench_db.py",
    "plugins/codex-security/tests/test_database.py",
    "plugins/codex-security/requirements-test.txt",
    "plugins/codex-security/pyproject.toml",
    "plugins/codex-security/schemas/finding.schema.json",
    "plugins/codex-security/skills/security-scan/SKILL.md",
    ".github/actions/setup-tools/action.yml",
  ]) {
    assert.deepEqual(select([path]), fullQualification, path);
  }
});

test("main, scheduled, manual, empty and retargeted changes receive full qualification", () => {
  for (const options of [
    { event: "push" },
    { event: "schedule" },
    { event: "workflow_dispatch" },
    { baseChanged: true },
  ]) {
    assert.deepEqual(select(["README.md"], options), fullQualification);
  }
  assert.deepEqual(select([]), fullQualification);
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
