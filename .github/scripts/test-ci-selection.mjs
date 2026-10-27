import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { selectChecks } from "./select-ci-checks.mjs";
import { failedChecks } from "./check-ci-results.mjs";

const select = (paths, options = {}) =>
  selectChecks(paths, { event: "pull_request", ...options });

const ubuntuNode24Install = JSON.stringify({
  include: [{ os: "ubuntu-latest", node: "24" }],
});

const regularSource = {
  "source-required": "true",
  "container-required": "true",
  "plugin-tests-required": "true",
  "package-required": "true",
  "action-ci": "false",
  "eval-contracts": "true",
  "workflow-quality": "false",
  "compatibility-matrix": JSON.stringify({
    include: [
      { os: "ubuntu-latest", node: "22.13.0" },
      { os: "ubuntu-latest", node: "24.0.0" },
      { os: "ubuntu-latest", node: "24" },
      { os: "ubuntu-latest", node: "26.0.0" },
      { os: "macos-latest", node: "22.13.0" },
      { os: "windows-latest", node: "22.13.0" },
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
};
const fullQualification = {
  ...regularSource,
  "action-ci": "true",
  "workflow-quality": "true",
  "compatibility-matrix": JSON.stringify({
    include: [
      { os: "ubuntu-latest", node: "22.13.0" },
      { os: "ubuntu-latest", node: "24.0.0" },
      { os: "ubuntu-latest", node: "24" },
      { os: "ubuntu-latest", node: "26.0.0" },
      { os: "ubuntu-latest", node: "26" },
      { os: "macos-latest", node: "22.13.0" },
      { os: "windows-latest", node: "22.13.0" },
      { os: "windows-latest", node: "24" },
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
};

const docs = {
  ...regularSource,
  "source-required": "false",
  "container-required": "false",
  "plugin-tests-required": "false",
  "package-required": "false",
  "eval-contracts": "false",
};

test("the Docker context excludes both test trees skipped by container CI", () => {
  const ignore = ["Dockerfile.dockerignore", ".dockerignore"]
    .map((file) => new URL(`../../${file}`, import.meta.url))
    .find((file) => fs.existsSync(file));
  const rules = fs.readFileSync(ignore, "utf8");
  assert.match(rules, /^plugins\/codex-security\/tests\r?$/m);
  assert.match(rules, /^sdk\/typescript\/tests-ts\r?$/m);
  assert.doesNotMatch(rules, /^\s*!/m);
});

test("only edits to existing direct pytest modules skip independent jobs", (t) => {
  const cwd = fs.mkdtempSync(resolve(tmpdir(), "ci-pytest-"));
  t.after(() => fs.rmSync(cwd, { recursive: true, force: true }));
  const files = join(cwd, "plugins/codex-security/tests");
  const output = join(cwd, "output");
  const script = join(import.meta.dirname, "select-ci-checks.mjs");
  const env = {
    ...process.env,
    EVENT_NAME: "pull_request",
    BASE_CHANGED: "false",
    GITHUB_OUTPUT: output,
  };
  // A Git hook may export its own repository and index into this process.
  for (const name of Object.keys(env))
    if (/^GIT_/iu.test(name)) delete env[name];
  env.GIT_CONFIG_GLOBAL = join(cwd, "empty.gitconfig");
  env.GIT_CONFIG_NOSYSTEM = "1";
  const git = (...args) => execFileSync("git", args, { cwd, env });
  git("init", "-q");
  git("config", "user.name", "CI Fixture");
  git("config", "user.email", "fixture@example.com");
  fs.mkdirSync(files, { recursive: true });
  let revision = 0;
  function commit(...names) {
    for (const name of names)
      fs.writeFileSync(join(files, name), String(revision++));
    git("add", "--force", "plugins");
    git("commit", "-qm", "fixture");
  }
  commit("test_2fa.py", "conftest.py");
  const reduced = {
    ...fullQualification,
    "compatibility-matrix": JSON.stringify({
      include: JSON.parse(
        fullQualification["compatibility-matrix"],
      ).include.filter(({ os }) => os !== "windows-latest"),
    }),
    "source-required": "false",
    "container-required": "false",
    "action-ci": "false",
    "eval-contracts": "false",
  };
  for (const [names, expected] of [
    [["test_2fa.py"], reduced],
    [["test_2fa.py", "test_added.py"], fullQualification],
    [["test_2fa.py", "conftest.py"], fullQualification],
  ]) {
    commit(...names);
    fs.writeFileSync(output, "");
    execFileSync(process.execPath, [script], { cwd, env });
    const lines = fs.readFileSync(output, "utf8").trim().split("\n");
    assert.deepEqual(
      Object.fromEntries(lines.map((line) => line.split("="))),
      expected,
    );
  }
});

test("ordinary documentation selects static checks", () => {
  assert.deepEqual(select(["README.md", "docs/bedrock.md"]), docs);
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

test("the Action README also requires Action documentation and release contracts", () => {
  const expected = { ...docs, "action-ci": "true" };
  assert.deepEqual(select(["github-action/README.md"]), expected);
  assert.deepEqual(select(["docs/ci.md", "github-action/README.md"]), expected);
  assert.deepEqual(
    select(["sdk/typescript/src/cost.ts", "github-action/README.md"]),
    { ...regularSource, "action-ci": "true" },
  );
  assert.deepEqual(
    failedChecks({
      "classify-changes": { result: "success", outputs: expected },
      "static-checks": { result: "success" },
    }),
    ["action-ci"],
  );
});

test("Action-only changes require Action CI and integration against the built package", () => {
  const expected = {
    ...docs,
    "package-required": "true",
    "action-ci": "true",
    "compatibility-matrix": ubuntuNode24Install,
  };
  for (const paths of [
    ["action.yml", "github-action/README.md"],
    ["github-action/src/results.ts", "github-action/dist/index.cjs"],
    ["github-action/dist/post.cjs"],
    ["github-action/package.json", "github-action/package-lock.json"],
    [
      "github-action/runtime/package.json",
      "github-action/runtime/package-lock.json",
    ],
    [
      "github-action/tests/release.test.mjs",
      "github-action/scripts/release.mjs",
    ],
  ]) {
    assert.deepEqual(select(paths), expected, paths.join(", "));
  }
  const needs = {
    "classify-changes": { result: "success", outputs: expected },
    "static-checks": { result: "success" },
    "action-ci": { result: "success", outputs: { passed: "true" } },
  };
  assert.deepEqual(failedChecks(needs), ["native", "package", "compatibility"]);
  for (const name of ["native", "package", "compatibility"])
    needs[name] = { result: "success" };
  assert.deepEqual(failedChecks(needs), []);
  for (const action of [
    { result: "failure", outputs: { passed: "true" } },
    { result: "success", outputs: { passed: "false" } },
    { result: "success" },
  ]) {
    assert.deepEqual(failedChecks({ ...needs, "action-ci": action }), [
      "action-ci",
    ]);
  }
  assert.deepEqual(select(["sdk/typescript/src/git-remote.ts"]), {
    ...regularSource,
    "action-ci": "true",
  });
});

test("Standard and triage eval changes require all deterministic eval contracts", () => {
  const expected = { ...docs, "eval-contracts": "true" };
  for (const paths of [
    [
      "evals/standard-time-budget/fixtures.mts",
      "evals/standard-time-budget/test_production.mts",
    ],
    [
      "evals/standard-time-budget/experiment.json",
      "evals/standard-time-budget/README.md",
    ],
    [
      "evals/triage-finding/package.json",
      "evals/triage-finding/pnpm-lock.yaml",
    ],
    [
      "evals/triage-finding/assertions/output.mts",
      "evals/triage-finding/scripts/test-triage-io.mts",
    ],
  ]) {
    assert.deepEqual(select(paths), expected, paths.join(", "));
  }
  const needs = {
    "classify-changes": { result: "success", outputs: expected },
    "static-checks": { result: "success" },
    "eval-contracts": { result: "skipped" },
  };
  assert.deepEqual(failedChecks(needs), ["eval-contracts"]);
  assert.deepEqual(
    failedChecks({ ...needs, "eval-contracts": { result: "success" } }),
    [],
  );
});

test("packaged guides keep the archive and installed-package gates", () => {
  const expected = {
    ...docs,
    "package-required": "true",
    "compatibility-matrix": ubuntuNode24Install,
  };
  for (const paths of [
    ["sdk/typescript/README.md"],
    ["RELEASING.md", "sdk/typescript/docs/cli.md"],
    // --no-renames includes the old required path even when the new path is ordinary docs.
    ["sdk/typescript/docs/hosted-scans.md", "docs/hosted-scans.md"],
  ]) {
    assert.deepEqual(select(paths), expected, paths.join(", "));
  }
  assert.deepEqual(
    failedChecks({
      "classify-changes": { result: "success", outputs: expected },
      "static-checks": { result: "success" },
    }),
    ["native", "package", "compatibility"],
  );
});

test("release guide changes select the static route", () => {
  assert.deepEqual(select(["RELEASING.md"]), docs);
  assert.deepEqual(select(["README.md", "RELEASING.md"]), docs);
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
    "sdk/typescript/src/index.ts",
    "sdk/typescript/tests-ts/support/test-subprocess.ts",
    "plugins/codex-security/mcp-app/src/stdio-transport.ts",
    "plugins/codex-security/mcp-app/tests/test_deep_scan_executor.ts",
    "plugins/codex-security/mcp-app/tests/support/fixture.ts",
  ]) {
    assert.deepEqual(select([path]), regularSource, path);
    for (const guide of ["README.md", "sdk/typescript/docs/cli.md"]) {
      assert.deepEqual(select([guide, path]), regularSource, path);
    }
  }
});

test("SDK test-only PRs skip independent suites and retain any changed eval input", () => {
  const paths = [
    "sdk/typescript/tests-ts/skeleton.test.ts",
    "sdk/typescript/tests-ts/windows-machine-policy.test.ts",
  ];
  const sdk = {
    ...regularSource,
    "container-required": "false",
    "plugin-tests-required": "false",
    "compatibility-matrix": ubuntuNode24Install,
  };
  assert.deepEqual(select(paths), { ...sdk, "eval-contracts": "false" });
  assert.deepEqual(
    select([...paths, "sdk/typescript/tests-ts/codex-dependency-pins.test.ts"]),
    sdk,
  );
  for (const other of [
    "README.md",
    "sdk/typescript/tests-ts/support/test-subprocess.ts",
    "sdk/typescript/src/api.ts",
  ]) {
    assert.deepEqual(select([...paths, other]), regularSource, other);
  }
  for (const options of [
    { event: "push" },
    { event: "schedule" },
    { event: "workflow_dispatch" },
    { baseChanged: true },
  ]) {
    assert.deepEqual(select(paths, options), fullQualification);
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
    ["sdk/typescript/docs/unlisted.md"],
    ["RELEASING.md", "sdk/typescript/src/api.ts"],
    ["sdk/typescript/docs/cli.md", "sdk/typescript/docs/unlisted.md"],
    ["plugins/codex-security/mcp-app/src/.npmrc"],
    ["pnpm-workspace.yaml"],
    ["sdk/typescript/pnpm-workspace.yaml"],
    ["plugins/codex-security/mcp-app/pnpm-workspace.yaml"],
    ["evals/triage-finding/pnpm-workspace.yaml"],
    ["evals/standard-time-budget/fixtures.mts", "sdk/typescript/src/cost.ts"],
    ["evals/triage-finding/fixtures/repo/package.json"],
    [
      "evals/triage-finding/pnpm-lock.yaml",
      "github-action/runtime/package-lock.json",
    ],
    ["github-action/src/main.ts", "sdk/typescript/src/git-remote.ts"],
    ["github-action/src/main.ts", "github-action/src/nested/unknown.ts"],
    ["github-action/tsconfig.json"],
    ["github-action/package.json", "github-action/.npmrc"],
    ["plugins/codex-security/examples/completed-scan/findings.jsonl"],
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
    "Dockerfile",
    ".github/workflows/container-ci.yml",
    ".github/workflows/container-validate.yml",
    ".github/workflows/container-release.yml",
    ".github/workflows/native-windows.yml",
    "sdk/typescript/scripts/run-ci-tests.mts",
    "plugins/codex-security/skills/example/SKILL.md",
    "package.json",
    "sdk/typescript/pnpm-lock.yaml",
    "sdk/typescript/bunfig.toml",
    "sdk/typescript/tsconfig.json",
    "plugins/codex-security/native/src/lib.rs",
    "sdk/typescript/scripts/build-plugin.mjs",
    ".github/workflows/node-ci.yml",
    ".github/workflows/action-ci.yml",
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

function successfulFullRun() {
  const outputs = select([".github/workflows/node-ci.yml"]);
  const needs = Object.fromEntries(
    [
      "static-checks",
      "action-ci",
      "eval-contracts",
      "native",
      "package",
      "test",
      "compatibility",
      "mcp",
      "plugin-host",
      "plugin-source",
      "windows-test",
      "workflow-quality",
      "container-validate",
    ].map((name) => [name, { result: "success" }]),
  );
  needs["action-ci"].outputs = { passed: "true" };
  needs["classify-changes"] = { result: "success", outputs };
  return needs;
}

test("the final gate rejects every missing or unsuccessful selected check", () => {
  const needs = successfulFullRun();
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

test("the final gate distinguishes a failed check from a skipped dependent job", () => {
  const run = (needs) =>
    spawnSync(process.execPath, ["check-ci-results.mjs"], {
      cwd: new URL(".", import.meta.url),
      env: { ...process.env, CI_RESULTS: JSON.stringify(needs) },
      encoding: "utf8",
    });
  const needs = successfulFullRun();
  for (const selected of [true, false]) {
    const outputs = select(
      [
        selected
          ? "Dockerfile"
          : "plugins/codex-security/tests/test_workbench.py",
      ],
      { modifiedOnly: true },
    );
    for (const result of ["success", "failure", "cancelled", "skipped"]) {
      const verdict = run({
        ...needs,
        "classify-changes": { result: "success", outputs },
        "container-validate": { result },
      });
      const failed = selected && result !== "success";
      assert.equal(verdict.status, failed ? 1 : 0, verdict.stderr);
      if (failed) {
        assert.ok(
          verdict.stderr.includes(`container-validate (${result})`),
          verdict.stderr,
        );
      } else {
        assert.equal(
          verdict.stdout.trim(),
          "All selected required CI checks passed.",
        );
      }
    }
  }

  needs["static-checks"].result = "failure";
  needs["container-validate"].result = "skipped";
  const failed = run(needs);
  assert.equal(failed.status, 1, failed.stderr);
  assert.match(
    failed.stderr,
    /^Required CI checks did not pass: static-checks \(failure\), container-validate \(skipped\)$/m,
  );
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
    "container-required",
    "plugin-tests-required",
    "package-required",
    "action-ci",
    "eval-contracts",
    "workflow-quality",
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

test("only an authenticated, successful classifier can propagate a source result", () => {
  const classification = {
    result: "success",
    outputs: { "source-run": "123" },
  };
  assert.deepEqual(failedChecks({ "classify-changes": classification }), []);
  for (const result of ["failure", "cancelled", "skipped"]) {
    assert.deepEqual(
      failedChecks({ "classify-changes": { ...classification, result } }),
      ["classify-changes"],
    );
  }
});
