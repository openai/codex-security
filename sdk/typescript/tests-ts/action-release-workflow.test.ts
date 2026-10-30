import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { createTemporaryDirectoriesSync } from "./support/temporary-directories.js";
import { runWorkflowScript } from "./support/workflow-script.js";

type Step = {
  name: string;
  id?: string;
  run?: string;
  uses?: string;
  with?: Record<string, string | boolean>;
  if?: string;
  "continue-on-error"?: boolean;
};
type Job = {
  steps: Step[];
  env?: Record<string, string>;
  permissions?: Record<string, string>;
  needs?: string[];
  outputs?: Record<string, string>;
};
const workflow = Bun.YAML.parse(
  readFileSync(
    new URL(
      "../../../.github/workflows/node-github-release.yml",
      import.meta.url,
    ),
    "utf8",
  ),
) as { jobs: Record<string, Job> };

function step(job: string, name: string) {
  const value = workflow.jobs[job]?.steps.find((step) => step.name === name);
  if (!value) throw new Error(`Missing workflow step: ${job}/${name}`);
  return value;
}

function script(job: string, name: string) {
  const value = step(job, name);
  if (!value.run) throw new Error(`Missing workflow script: ${job}/${name}`);
  return value.run;
}

const reuse = script(
  "action",
  "Reuse an existing immutable Action distribution",
);
const detect = script("release", "Detect Action release source");
const detectContainer = script("release", "Detect container release source");
const complete = script("complete", "Require completed release channels");
const summarize = script("complete", "Summarize release channels");
const publish = script("action", "Publish immutable Action tag and metadata");
const directories = createTemporaryDirectoriesSync();
const version = "99.1.2";
const packageName = "@openai/codex-security";
const integrity = "sha512-synthetic-verified-integrity";

afterEach(directories.cleanup);

function fixture(includeAction = true) {
  const directory = directories.create("action release workflow ");
  const repository = join(directory, "release-source");
  const output = join(directory, "outputs");
  const npmMarker = join(directory, "npm-ran");
  mkdirSync(repository);
  writeFileSync(npmMarker, "");
  const helper = join(
    directory,
    "automation/github-action/scripts/release.mjs",
  );
  mkdirSync(dirname(helper), { recursive: true });
  copyFileSync(
    new URL("../../../github-action/scripts/release.mjs", import.meta.url),
    helper,
  );
  function git(...args: string[]) {
    return execFileSync(
      "git",
      [
        "-c",
        "user.name=Release Test",
        "-c",
        "user.email=release@example.invalid",
        "-c",
        "commit.gpgsign=false",
        ...args,
      ],
      { cwd: repository, encoding: "utf8", stdio: "pipe" },
    ).trim();
  }
  function write(path: string, value: string) {
    const destination = join(repository, path);
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, value);
  }
  function writeJson(path: string, value: unknown) {
    write(path, `${JSON.stringify(value)}\n`);
  }
  function updateJson(
    path: string,
    update: (value: Record<string, unknown>) => Record<string, unknown>,
  ) {
    writeJson(
      path,
      update(JSON.parse(readFileSync(join(repository, path), "utf8"))),
    );
  }
  function commit(message: string) {
    git("add", "--all");
    git("commit", "-m", message);
    return git("rev-parse", "HEAD");
  }
  function run(script: string, environment: Record<string, string> = {}) {
    writeFileSync(output, "");
    const result = runWorkflowScript(
      repository,
      script,
      {
        GITHUB_OUTPUT: output.replaceAll("\\", "/"),
        RELEASE_VERSION: version,
        RELEASE_SHA: source,
        CLI_INTEGRITY: integrity,
        GITHUB_WORKSPACE: directory.replaceAll("\\", "/"),
        RUNNER_TEMP: directory.replaceAll("\\", "/"),
        NPM_MARKER: npmMarker.replaceAll("\\", "/"),
        ...environment,
      },
      ["-e", "-o", "pipefail"],
    );
    return { ...result, output: readFileSync(output, "utf8") };
  }
  git("init");
  write("README.md", "Synthetic CLI source\n");
  writeJson("sdk/typescript/package.json", { name: packageName, version });
  const actionPackage = {
    name: "example-action",
    version: "99.1.1",
    scripts: { build: "node scripts/build.mjs" },
    dependencies: { "example-build": "1.2.3" },
  };
  if (includeAction) {
    write("action.yml", "name: Synthetic Action\n");
    writeJson("github-action/package.json", actionPackage);
    writeJson("github-action/package-lock.json", {
      version: actionPackage.version,
      lockfileVersion: 3,
      packages: {
        "": actionPackage,
        "node_modules/example-build": { version: "1.2.3" },
      },
    });
    writeJson("github-action/runtime/package.json", {
      private: true,
      dependencies: { [packageName]: "99.1.1" },
    });
  }
  const source = commit("Create release source");
  function distribution(change?: () => void) {
    writeJson("github-action/package.json", { ...actionPackage, version });
    writeJson("github-action/package-lock.json", {
      version,
      lockfileVersion: 3,
      packages: {
        "": { ...actionPackage, version },
        "node_modules/example-build": { version: "1.2.3" },
      },
    });
    writeJson("github-action/runtime/package.json", {
      private: true,
      dependencies: { [packageName]: version },
    });
    writeJson("github-action/runtime/package-lock.json", {
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { [packageName]: version } },
        [`node_modules/${packageName}`]: { version, integrity },
      },
    });
    for (const path of [
      "github-action/dist/index.cjs",
      "github-action/dist/post.cjs",
    ]) {
      write(path, "Synthetic generated release content\n");
    }
    change?.();
    const sha = commit("Package Action release");
    git("tag", "action-v99.1.2", sha);
    git("checkout", "--detach", source);
    return sha;
  }
  return {
    directory,
    repository,
    git,
    write,
    updateJson,
    commit,
    run,
    source,
    distribution,
    npmMarker,
  };
}

test("runs CLI verification read-only and passes only its identified runtime lock to publication", () => {
  const verification = workflow.jobs["action-verify"]!;
  const publication = workflow.jobs["action"]!;
  expect(verification.permissions).toEqual({ contents: "read" });
  expect(publication.permissions).toEqual({ contents: "write" });
  expect(publication.needs).toContain("action-verify");
  expect(step("action", "Checkout verified CLI source").with).toMatchObject({
    ref: "${{ needs.release.outputs.sha }}",
    path: "release-source",
    "persist-credentials": false,
  });
  const artifacts = verification.steps.filter((step) =>
    step.uses?.startsWith("actions/upload-artifact@"),
  );
  expect(artifacts).toHaveLength(1);
  expect(artifacts[0]?.with?.["path"]).toBe(
    "release-source/github-action/runtime/package-lock.json",
  );
  expect(verification.outputs?.["runtime-lock-artifact"]).toBe(
    `\${{ steps.${artifacts[0]!.id}.outputs.artifact-id }}`,
  );
  expect(
    step("action", "Download verified CLI runtime lock").with,
  ).toMatchObject({
    "artifact-ids": "${{ needs.action-verify.outputs.runtime-lock-artifact }}",
  });
  const verificationCommands = script(
    "action-verify",
    "Validate the packaged Action",
  )
    .trim()
    .split("\n");
  expect(verificationCommands.at(-1)).toBe("npm run check-dist");
  expect(
    script("action", "Check Action distribution before publication").trim(),
  ).toBe("npm run check-dist");
  const actionPackage = JSON.parse(
    readFileSync(
      new URL("../../../github-action/package.json", import.meta.url),
      "utf8",
    ),
  ) as { scripts: Record<string, string> };
  expect(actionPackage.scripts["check-dist"]).toBeString();
  const publicationCommands = publication.steps
    .map((step) => step.run ?? "")
    .join("\n");
  expect(publicationCommands).not.toMatch(
    /test:cli|scripts\/linux-smoke\.mjs|npm ci --prefix runtime/u,
  );
});

test("stages the verified runtime lock without copying verification workspace source or bundles", () => {
  const release = fixture();
  release.write(".gitattributes", "* text eol=lf\n");
  const version = "99.1.2";
  const packageName = "@openai/codex-security";
  const integrity = "sha512-synthetic-verified-integrity";
  const writeJson = (path: string, value: unknown) =>
    release.write(path, `${JSON.stringify(value)}\n`);
  writeJson("sdk/typescript/package.json", { name: packageName, version });
  writeJson("github-action/package.json", {
    name: "example-action",
    version: "99.1.1",
  });
  writeJson("github-action/package-lock.json", {
    version: "99.1.1",
    packages: { "": { version: "99.1.1" } },
  });
  writeJson("github-action/runtime/package.json", {
    dependencies: { [packageName]: "99.1.1" },
  });
  const source = "reviewed Action source\n";
  const bundle = "reviewed Action bundle\n";
  release.write("github-action/src/index.ts", source);
  release.write("github-action/dist/index.cjs", bundle);
  release.write("github-action/dist/post.cjs", bundle);
  const sourceCommit = release.commit("Prepare reviewed Action source");
  const verification = join(release.directory, "verification");
  const publication = join(release.directory, "publication");
  mkdirSync(verification);
  mkdirSync(publication);
  for (const workspace of [verification, publication]) {
    release.git(
      "clone",
      "--local",
      release.repository,
      join(workspace, "release-source"),
    );
  }
  const verifiedAction = join(verification, "release-source", "github-action");
  for (const path of [
    "src/index.ts",
    "dist/index.cjs",
    "dist/post.cjs",
    "package.json",
  ]) {
    writeFileSync(
      join(verifiedAction, path),
      "modified by runtime verification\n",
    );
  }
  const runtimeLock = `${JSON.stringify({
    packages: {
      "": { dependencies: { [packageName]: version } },
      [`node_modules/${packageName}`]: { version, integrity },
    },
  })}\n`;
  const artifactPath = step("action-verify", "Save verified CLI runtime lock")
    .with?.["path"];
  if (typeof artifactPath !== "string")
    throw new Error("Missing runtime lock artifact path");
  writeFileSync(join(verification, artifactPath), runtimeLock);
  const runner = join(publication, "runner");
  const download = join(runner, "action-runtime-lock");
  mkdirSync(download, { recursive: true });
  copyFileSync(
    join(verification, artifactPath),
    join(download, basename(artifactPath)),
  );
  const helper = join(
    publication,
    "automation",
    "github-action",
    "scripts",
    "release.mjs",
  );
  mkdirSync(dirname(helper), { recursive: true });
  copyFileSync(
    new URL("../../../github-action/scripts/release.mjs", import.meta.url),
    helper,
  );
  const result = runWorkflowScript(
    publication,
    script("action", "Stage verified CLI runtime lock"),
    {
      RELEASE_VERSION: version,
      RELEASE_SHA: sourceCommit,
      CLI_INTEGRITY: integrity,
      RUNNER_TEMP: runner.replaceAll("\\", "/"),
      GITHUB_WORKSPACE: publication.replaceAll("\\", "/"),
    },
    ["-e", "-o", "pipefail"],
  );
  expect(result.status, result.stderr).toBe(0);
  const publishedAction = join(publication, "release-source", "github-action");
  expect(readFileSync(join(publishedAction, "src/index.ts"), "utf8")).toBe(
    source,
  );
  for (const path of ["dist/index.cjs", "dist/post.cjs"]) {
    expect(readFileSync(join(publishedAction, path), "utf8")).toBe(bundle);
  }
  expect(
    JSON.parse(readFileSync(join(publishedAction, "package.json"), "utf8")),
  ).toEqual({
    name: "example-action",
    version,
  });
  expect(
    readFileSync(join(publishedAction, "runtime/package-lock.json"), "utf8"),
  ).toBe(runtimeLock);
});

test.each([0, 42])(
  "gates runtime verification through Socket with an empty cache (exit %j)",
  (firewallExit) => {
    const verification = workflow.jobs["action-verify"]!;
    const install = step(
      "action-verify",
      "Install Action and CLI dependencies",
    );
    const validate = step("action-verify", "Validate the packaged Action");
    const upload = step("action-verify", "Save verified CLI runtime lock");
    expect(verification.steps.indexOf(install)).toBeLessThan(
      verification.steps.indexOf(validate),
    );
    expect(verification.steps.indexOf(validate)).toBeLessThan(
      verification.steps.indexOf(upload),
    );
    expect(install["continue-on-error"]).toBeUndefined();
    expect(validate.if).toBeUndefined();
    expect(upload.if).toBeUndefined();

    const directory = directories.create("action runtime firewall ");
    const runner = join(directory, "runner");
    const existingCache = join(runner, "existing-cache");
    mkdirSync(existingCache, { recursive: true });
    writeFileSync(join(existingCache, "cached-package"), "cached bytes");
    mkdirSync(join(directory, "runtime"));
    const lockPath = join(directory, "runtime", "package-lock.json");
    const runtimeLock = `${JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "node_modules/example-runtime": {
          version: "1.2.3",
          resolved:
            "https://registry.npmjs.org/example-runtime/-/example-runtime-1.2.3.tgz",
          integrity: "sha512-synthetic-integrity",
        },
      },
    })}\n`;
    writeFileSync(lockPath, runtimeLock);
    const events = join(directory, "events");
    const argumentsPath = join(directory, "sfw-arguments");
    const result = runWorkflowScript(
      directory,
      `npm() { printf 'npm %s\\n' "$*" >> "$EVENTS"; }
node() { printf 'node %s\\n' "$*" >> "$EVENTS"; }
sfw() {
  printf '%s\\0' "$@" > "$SFW_ARGUMENTS"
  local argument cache
  for argument in "$@"; do
    case "$argument" in --cache=*) cache="\${argument#--cache=}" ;; esac
  done
  [[ -d "$cache" && -z "$(ls -A "$cache")" ]] || return 91
  touch "$cache/downloaded-package"
  printf 'sfw\\n' >> "$EVENTS"
  return "$FIREWALL_EXIT"
}
${install.run}
${validate.run}`,
      {
        RUNNER_TEMP: runner.replaceAll("\\", "/"),
        npm_config_cache: existingCache.replaceAll("\\", "/"),
        EVENTS: events.replaceAll("\\", "/"),
        SFW_ARGUMENTS: argumentsPath.replaceAll("\\", "/"),
        FIREWALL_EXIT: String(firewallExit),
      },
      ["-e", "-o", "pipefail"],
    );
    expect(result.status, result.stderr).toBe(firewallExit);
    const args = readFileSync(argumentsPath, "utf8").split("\0").slice(0, -1);
    expect(args.slice(0, 4)).toEqual(["npm", "ci", "--prefix", "runtime"]);
    expect(args).toContain("--registry=https://registry.npmjs.org/");
    expect(args).toContain("--ignore-scripts");
    expect(readFileSync(lockPath, "utf8")).toBe(runtimeLock);
    expect(readdirSync(runner)).toEqual(["existing-cache"]);
    const commands = readFileSync(events, "utf8");
    expect(commands).toContain("sfw\n");
    if (firewallExit === 0) {
      expect(commands).toContain("npm run test:cli\n");
      expect(commands).toContain("node scripts/linux-smoke.mjs\n");
    } else {
      expect(commands).not.toContain("npm run");
      expect(commands).not.toContain("node ");
    }
  },
);

function reuseAndInstall(job: string) {
  const steps = workflow.jobs[job]!.steps;
  const reuse = step(job, "Reuse an existing immutable Action distribution");
  const install = step(
    job,
    job === "action"
      ? "Install Action build dependencies"
      : "Install Action and CLI dependencies",
  );
  expect(steps.indexOf(reuse)).toBeLessThan(steps.indexOf(install));
  return `npm() { printf 'npm\\n' >> "$NPM_MARKER"; }
sfw() { "$@"; }
${reuse.run}
cd "$GITHUB_WORKSPACE/release-source/github-action"
${install.run}`;
}

const changedDistributions: Array<{
  name: string;
  path: string;
  update: (value: Record<string, unknown>) => Record<string, unknown>;
  error: string;
}> = [
  {
    name: "Action scripts",
    path: "package.json",
    update: (value) => ({ ...value, scripts: { build: "node changed.mjs" } }),
    error: "must preserve the reviewed release source",
  },
  {
    name: "Action dependencies",
    path: "package.json",
    update: (value) => ({
      ...value,
      dependencies: { "example-build": "9.9.9" },
    }),
    error: "must preserve the reviewed release source",
  },
  {
    name: "Action lock dependencies",
    path: "package-lock.json",
    update: (value) => ({
      ...value,
      packages: {
        ...(value["packages"] as Record<string, unknown>),
        "node_modules/example-build": { version: "9.9.9" },
      },
    }),
    error: "must preserve the reviewed release source",
  },
  {
    name: "runtime scripts",
    path: "runtime/package.json",
    update: (value) => ({ ...value, scripts: { prepare: "node changed.mjs" } }),
    error: "must preserve the reviewed release source",
  },
  {
    name: "CLI version",
    path: "runtime/package.json",
    update: (value) => ({
      ...value,
      dependencies: { [packageName]: "99.1.3" },
    }),
    error: "Action and CLI release versions must agree",
  },
  {
    name: "CLI integrity",
    path: "runtime/package-lock.json",
    update: (value) => ({
      ...value,
      packages: {
        ...(value["packages"] as Record<string, unknown>),
        [`node_modules/${packageName}`]: {
          version,
          integrity: "sha512-different",
        },
      },
    }),
    error: "Action must install the verified npm release",
  },
];

const releaseJobs = ["action-verify", "action"];

test.each(releaseJobs)(
  "%s reuses the exact CLI release before installing dependencies",
  (job) => {
    const release = fixture();
    const distribution = release.distribution();
    const result = release.run(reuseAndInstall(job));
    expect(result.status, result.stderr).toBe(0);
    expect(result.output).toBe("existing=true\n");
    expect(readFileSync(release.npmMarker, "utf8")).toContain("npm\n");
    expect(release.git("rev-parse", "HEAD")).toBe(distribution);
  },
);

test.each(changedDistributions)(
  "both jobs reject changed $name before installing dependencies",
  ({ path, update, error }) => {
    const release = fixture();
    release.distribution(() =>
      release.updateJson(`github-action/${path}`, update),
    );
    for (const job of releaseJobs) {
      release.git("checkout", "--detach", release.source);
      const result = release.run(reuseAndInstall(job));
      expect(result.status, job).not.toBe(0);
      expect(result.stderr, job).toContain(error);
      expect(result.output, job).toBe("");
      expect(readFileSync(release.npmMarker, "utf8"), job).toBe("");
    }
  },
);

test("leaves the CLI source ready for first Action publication", () => {
  const release = fixture();
  const result = release.run(reuse);
  expect(result.status).toBe(0);
  expect(result.output).toBe("");
  expect(release.git("rev-parse", "HEAD")).toBe(release.source);
});

test("rejects an Action distribution derived from a different source commit", () => {
  const release = fixture();
  release.write("README.md", "Another CLI source commit\n");
  release.commit("Advance source");
  release.distribution();
  const result = release.run(reuse);
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("exact CLI source");
  expect(result.output).toBe("");
  expect(release.git("rev-parse", "HEAD")).toBe(release.source);
});

test("rejects unrelated source edits in an existing Action distribution", () => {
  const release = fixture();
  release.distribution(() =>
    release.write("github-action/src/index.ts", "Unrelated source change\n"),
  );
  const result = release.run(reuse);
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("outside release packaging");
  expect(result.output).toBe("");
  expect(release.git("rev-parse", "HEAD")).toBe(release.source);
});

test("detects Action support from the release commit during historical recovery", () => {
  const release = fixture(false);
  release.write("action.yml", "name: Synthetic Action\n");
  const newerSource = release.commit("Add Action after earlier CLI release");
  const historical = release.run(detect);
  expect(historical.status).toBe(0);
  expect(historical.output).toBe("");
  const current = release.run(detect, { RELEASE_SHA: newerSource });
  expect(current.status).toBe(0);
  expect(current.output).toBe("present=true\n");
});

type PublishedRelease = {
  isDraft: boolean;
  assets: Record<string, string>;
};

const actionAssets = {
  "action-release-manifest.json": "verified manifest\n",
  "action-sbom.cdx.json": "verified SBOM\n",
};

function publicationFixture(existingRelease: PublishedRelease | null) {
  const release = fixture();
  const distribution = release.distribution();
  release.git("checkout", "--detach", distribution);
  const runner = join(release.directory, "runner");
  const state = join(release.directory, "release.json");
  const calls = join(release.directory, "calls.jsonl");
  const github = join(release.directory, "github.cjs");
  mkdirSync(runner);
  writeFileSync(state, JSON.stringify(existingRelease));
  writeFileSync(calls, "");
  release.write(
    "github-action/build/release-manifest.json",
    actionAssets["action-release-manifest.json"],
  );
  release.write(
    "github-action/build/sbom.cdx.json",
    actionAssets["action-sbom.cdx.json"],
  );
  writeFileSync(
    github,
    `const assert = require("node:assert/strict");
const { appendFileSync, readFileSync, writeFileSync } = require("node:fs");
const { basename, join } = require("node:path");
const [program, ...args] = process.argv.slice(2);
if (program === "jq") {
  const value = JSON.parse(readFileSync(0, "utf8"));
  assert.equal(args[0], "-r");
  if (args[1] === ".isDraft") console.log(value.isDraft);
  else if (args[1] === ".assets[].name") {
    for (const asset of value.assets) console.log(asset.name);
  } else throw new Error("Unexpected jq filter: " + args[1]);
  process.exit(0);
}
appendFileSync(process.env.GITHUB_CALLS, JSON.stringify(args) + "\\n");
assert.equal(args[0], "release");
assert.equal(args[2], "action-v99.1.2");
const option = (name) => args[args.indexOf(name) + 1];
assert.equal(option("--repo"), "example/security-tool");
let state = JSON.parse(readFileSync(process.env.RELEASE_STATE, "utf8"));
switch (args[1]) {
  case "view":
    if (state === null) process.exit(1);
    assert.equal(option("--json"), "isDraft,assets");
    console.log(JSON.stringify({
      isDraft: state.isDraft,
      assets: Object.keys(state.assets).map((name) => ({ name })),
    }));
    break;
  case "download": {
    const asset = option("--pattern");
    assert.ok(Object.hasOwn(state.assets, asset));
    writeFileSync(join(option("--dir"), asset), state.assets[asset]);
    break;
  }
  case "create": {
    assert.equal(state, null, "Cannot replace an existing release");
    assert.ok(args.includes("--verify-tag"));
    assert.ok(args.includes("--latest=false"));
    assert.equal(option("--title"), "Codex Security GitHub Action 99.1.2");
    const assets = args.slice(3, args.indexOf("--repo"));
    assert.deepEqual(assets.map((asset) => basename(asset)).sort(), [
      "action-release-manifest.json", "action-sbom.cdx.json",
    ]);
    state = {
      isDraft: false,
      assets: Object.fromEntries(assets.map((asset) => [basename(asset), readFileSync(asset, "utf8")])),
      notes: readFileSync(option("--notes-file"), "utf8"),
    };
    break;
  }
  case "upload": {
    assert.equal(state.isDraft, true, "Published release assets are immutable");
    const path = args.at(-1);
    const asset = basename(path);
    assert.ok(!Object.hasOwn(state.assets, asset), "Cannot replace existing metadata");
    state.assets[asset] = readFileSync(path, "utf8");
    break;
  }
  case "edit":
    assert.equal(state.isDraft, true, "Published releases are immutable");
    assert.ok(args.includes("--draft=false"));
    assert.ok(args.includes("--latest=false"));
    assert.deepEqual(Object.keys(state.assets).sort(), [
      "action-release-manifest.json", "action-sbom.cdx.json",
    ]);
    state.isDraft = false;
    break;
  default: throw new Error("Unexpected release command: " + args[1]);
}
writeFileSync(process.env.RELEASE_STATE, JSON.stringify(state));
`,
  );
  const fakeGitHub = `gh() { node "$GITHUB_FIXTURE" gh "$@"; }
jq() { node "$GITHUB_FIXTURE" jq "$@"; }
`;
  return {
    distribution,
    state() {
      return JSON.parse(readFileSync(state, "utf8")) as PublishedRelease & {
        notes?: string;
      };
    },
    commands() {
      return readFileSync(calls, "utf8")
        .trim()
        .split("\n")
        .map((line) => (JSON.parse(line) as string[])[1]);
    },
    run() {
      return release.run(`${fakeGitHub}${publish}`, {
        EXISTING: "true",
        RUNNER_TEMP: runner.replaceAll("\\", "/"),
        GITHUB_FIXTURE: github.replaceAll("\\", "/"),
        GITHUB_CALLS: calls.replaceAll("\\", "/"),
        RELEASE_STATE: state.replaceAll("\\", "/"),
        GITHUB_REPOSITORY: "example/security-tool",
        GITHUB_SERVER_URL: "https://github.com",
        GITHUB_STEP_SUMMARY: join(release.directory, "summary.md").replaceAll(
          "\\",
          "/",
        ),
      });
    },
  };
}

test("recovers an existing Action tag by creating its companion release with both metadata assets", () => {
  const publication = publicationFixture(null);
  const result = publication.run();
  expect(result.status, result.stderr).toBe(0);
  expect(publication.commands()).toEqual(["view", "create"]);
  const published = publication.state();
  expect(published).toMatchObject({
    isDraft: false,
    assets: actionAssets,
  });
  expect(published.notes).toContain(
    "https://github.com/example/security-tool/releases/tag/npm-v99.1.2",
  );
  expect(published.notes).toContain(
    `uses: example/security-tool@${publication.distribution}`,
  );

  const retry = publication.run();
  expect(retry.status, retry.stderr).toBe(0);
  expect(publication.state()).toEqual(published);
  expect(publication.commands()).toEqual([
    "view",
    "create",
    "view",
    "download",
    "download",
  ]);
});

const draftAssetSets: Record<string, string>[] = [
  {},
  {
    "action-release-manifest.json":
      actionAssets["action-release-manifest.json"],
  },
  actionAssets,
];

test.each(draftAssetSets)(
  "completes an existing Action release draft before publishing it: %j",
  (assets) => {
    const publication = publicationFixture({ isDraft: true, assets });
    const result = publication.run();
    expect(result.status, result.stderr).toBe(0);
    expect(publication.state()).toEqual({
      isDraft: false,
      assets: actionAssets,
    });
    expect(publication.commands()).toEqual([
      "view",
      Object.hasOwn(assets, "action-release-manifest.json")
        ? "download"
        : "upload",
      Object.hasOwn(assets, "action-sbom.cdx.json") ? "download" : "upload",
      "edit",
    ]);
  },
);

test.each(
  [false, true].flatMap((isDraft) =>
    Object.keys(actionAssets).map((asset) => ({ isDraft, asset })),
  ),
)(
  "rejects mismatched $asset without replacing it (draft=$isDraft)",
  ({ isDraft, asset }) => {
    const assets = {
      ...actionAssets,
      [asset]: "different published metadata\n",
    };
    const publication = publicationFixture({ isDraft, assets });
    const result = publication.run();
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("Published Action metadata differs");
    expect(publication.commands()).toEqual(
      asset === "action-release-manifest.json"
        ? ["view", "download"]
        : ["view", "download", "download"],
    );
    expect(publication.state()).toEqual({ isDraft, assets });
  },
);

test.each(Object.keys(actionAssets))(
  "rejects published metadata missing %s without attempting an immutable upload",
  (missing) => {
    const assets = Object.fromEntries(
      Object.entries(actionAssets).filter(([asset]) => asset !== missing),
    );
    const publication = publicationFixture({ isDraft: false, assets });
    const result = publication.run();
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "Published Action release is missing metadata",
    );
    expect(publication.commands()).toEqual(
      missing === "action-release-manifest.json"
        ? ["view"]
        : ["view", "download"],
    );
    expect(publication.state()).toEqual({ isDraft: false, assets });
  },
);

const successfulChannels = {
  RELEASE_RESULT: "success",
  INSTALL_RESULT: "success",
  ACTION_RESULT: "success",
  HAS_ACTION: "true",
  CONTAINER_RESULT: "success",
  HAS_CONTAINER: "true",
};

const failedRelease = {
  RELEASE_RESULT: "failure",
  INSTALL_RESULT: "skipped",
  ACTION_RESULT: "skipped",
  HAS_ACTION: "",
};

const channelCases: Array<[Record<string, string>, boolean]> = [
  [{}, true],
  [{ RELEASE_RESULT: "failure" }, false],
  [failedRelease, false],
  [{ ...failedRelease, CONTAINER_RESULT: "skipped", HAS_CONTAINER: "" }, false],
  [{ INSTALL_RESULT: "failure" }, false],
  [{ INSTALL_RESULT: "failure", ACTION_RESULT: "skipped" }, false],
  [{ INSTALL_RESULT: "cancelled" }, false],
  [
    { INSTALL_RESULT: "cancelled", ACTION_RESULT: "skipped", HAS_ACTION: "" },
    false,
  ],
  [{ ACTION_RESULT: "failure" }, false],
  [{ ACTION_RESULT: "skipped" }, false],
  [{ ACTION_RESULT: "skipped", HAS_ACTION: "" }, true],
  [{ CONTAINER_RESULT: "failure" }, false],
  [{ CONTAINER_RESULT: "cancelled" }, false],
  [{ CONTAINER_RESULT: "skipped" }, false],
  [{ HAS_WOLFI: "true", DEBIAN_DIGEST: "debian-digest" }, false],
  [{ HAS_WOLFI: "true", WOLFI_DIGEST: "wolfi-digest" }, false],
  [
    {
      HAS_WOLFI: "true",
      DEBIAN_DIGEST: "debian-digest",
      WOLFI_DIGEST: "wolfi-digest",
    },
    true,
  ],
  [{ CONTAINER_RESULT: "skipped", HAS_CONTAINER: "" }, true],
];

test.each(channelCases)(
  "checks release channel requirements with %j",
  (overrides, succeeds) => {
    const result = runWorkflowScript(
      tmpdir(),
      complete,
      { ...successfulChannels, ...overrides },
      ["-e", "-o", "pipefail"],
    );
    expect(result.status === 0).toBe(succeeds);
  },
);

test("detects container support from the release commit, not the automation checkout", () => {
  const release = fixture();
  release.write(".github/workflows/wolfi-build.yml", "name: Wolfi\n");
  const withoutContainer = release.commit("Add Wolfi workflow");
  expect(
    release.run(detectContainer, { RELEASE_SHA: withoutContainer }).output,
  ).toBe("");
  release.write("Dockerfile", "FROM scratch\n");
  const containerSource = release.commit("Add container");
  expect(release.run(detectContainer).output).toBe("");
  expect(
    release.run(detectContainer, { RELEASE_SHA: containerSource }).output,
  ).toBe("present=true\nwolfi=true\n");
});

test.each([
  ["0.1.26", false],
  ["0.4.0", false],
  ["0.5.0", true],
  ["0.10.0", true],
  ["1.0.0", true],
] as const)(
  "preserves historical recovery before coordinated containers: %s",
  (version, included) => {
    const release = fixture();
    release.write("Dockerfile", "FROM scratch\n");
    release.updateJson("sdk/typescript/package.json", (value) => ({
      ...value,
      version,
    }));
    const source = release.commit("Add container source");
    expect(
      release.run(detectContainer, {
        RELEASE_SHA: source,
        RELEASE_VERSION: version,
      }).output,
    ).toBe(included ? "present=true\n" : "");
  },
);

test.each(["success", "failure", "cancelled", "skipped"])(
  "reports the coordinated container result: %s",
  (containerResult) => {
    const directory = directories.create("release summary ");
    const summary = join(directory, "summary.md");
    const result = runWorkflowScript(
      directory,
      summarize,
      {
        ...successfulChannels,
        RELEASE_VERSION: version,
        GITHUB_STEP_SUMMARY: summary.replaceAll("\\", "/"),
        GITHUB_SERVER_URL: "https://github.com",
        GITHUB_REPOSITORY: "example/project",
        CONTAINER_RESULT: containerResult,
        RELEASE_SHA: "a".repeat(40),
        DEBIAN_DIGEST:
          containerResult === "success" ? `sha256:${"a".repeat(64)}` : "",
        WOLFI_DIGEST:
          containerResult === "success" ? `sha256:${"b".repeat(64)}` : "",
      },
      ["-e", "-o", "pipefail"],
    );
    expect(result.status, result.stderr).toBe(0);
    const text = readFileSync(summary, "utf8");
    if (containerResult === "success") {
      for (const digit of ["a", "b"]) {
        const ref = `ghcr.io/example/project@sha256:${digit.repeat(64)}`;
        expect(text).toContain(`docker pull ${ref}`);
        expect(text).toContain(
          `gh attestation verify oci://${ref} --repo example/project`,
        );
      }
    }
    const rows = text
      .split("\n")
      .filter((line) => line.startsWith("|"))
      .map((line) => line.split("|").map((cell) => cell.trim()));
    expect(rows.find((row) => row[1] === "Container image")?.[2]).toBe(
      containerResult,
    );
    expect(
      step("complete", "Summarize release channels")["continue-on-error"],
    ).toBe(true);
    expect(workflow.jobs["complete"]?.env?.["CONTAINER_RESULT"]).toBe(
      "${{ needs.container.result }}",
    );
  },
);
