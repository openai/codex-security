import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
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
const complete = script("complete", "Require completed release channels");
const publish = script("action", "Publish immutable Action tag and metadata");
const directories: string[] = [];
const version = "99.1.2";
const packageName = "@openai/codex-security";
const integrity = "sha512-synthetic-verified-integrity";

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function fixture(includeAction = true) {
  const directory = mkdtempSync(join(tmpdir(), "action release workflow "));
  directories.push(directory);
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

    const directory = mkdtempSync(join(tmpdir(), "action runtime firewall "));
    directories.push(directory);
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

for (const job of ["action-verify", "action"]) {
  test(`${job} reuses the exact CLI release before installing dependencies`, () => {
    const release = fixture();
    const distribution = release.distribution();
    const result = release.run(reuseAndInstall(job));
    expect(result.status, result.stderr).toBe(0);
    expect(result.output).toBe("existing=true\n");
    expect(readFileSync(release.npmMarker, "utf8")).toContain("npm\n");
    expect(release.git("rev-parse", "HEAD")).toBe(distribution);
  });

  test.each(changedDistributions)(
    `${job} rejects changed $name before installing dependencies`,
    ({ path, update, error }) => {
      const release = fixture();
      release.distribution(() =>
        release.updateJson(`github-action/${path}`, update),
      );
      const result = release.run(reuseAndInstall(job));
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(error);
      expect(result.output).toBe("");
      expect(readFileSync(release.npmMarker, "utf8")).toBe("");
    },
  );
}

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

function publicationFixture(existingManifest: string) {
  const release = fixture();
  const runner = join(release.directory, "runner");
  const remote = join(release.directory, "published assets");
  const uploads = join(release.directory, "uploads");
  mkdirSync(runner);
  mkdirSync(remote);
  writeFileSync(uploads, "");
  release.write(
    "github-action/build/release-manifest.json",
    "verified manifest\n",
  );
  release.write("github-action/build/sbom.cdx.json", "verified SBOM\n");
  writeFileSync(join(remote, "action-release-manifest.json"), existingManifest);
  const fakeGitHub = `gh() {
  case "$1 $2" in
    'release view')
      for asset in "$REMOTE_ASSETS/"*; do basename "$asset"; done
      ;;
    'release download')
      local asset destination
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --pattern) asset="$2"; shift ;;
          --dir) destination="$2"; shift ;;
        esac
        shift
      done
      cp "$REMOTE_ASSETS/$asset" "$destination/$asset"
      ;;
    'release upload')
      local asset="$(basename "\${!#}")"
      cp "\${!#}" "$REMOTE_ASSETS/$asset"
      printf '%s\\n' "$asset" >> "$UPLOADS"
      ;;
    *) return 1 ;;
  esac
}
`;
  return {
    remote,
    uploads,
    run() {
      return release.run(`${fakeGitHub}${publish}`, {
        EXISTING: "true",
        RUNNER_TEMP: runner.replaceAll("\\", "/"),
        REMOTE_ASSETS: remote.replaceAll("\\", "/"),
        UPLOADS: uploads.replaceAll("\\", "/"),
        GITHUB_REPOSITORY: "example/security-tool",
        GITHUB_STEP_SUMMARY: join(release.directory, "summary.md").replaceAll(
          "\\",
          "/",
        ),
      });
    },
  };
}

test("completes partial Action metadata publication and reuses matching assets", () => {
  const publication = publicationFixture("verified manifest\n");
  expect(publication.run().status).toBe(0);
  expect(readFileSync(publication.uploads, "utf8")).toBe(
    "action-sbom.cdx.json\n",
  );
  expect(
    readFileSync(join(publication.remote, "action-sbom.cdx.json"), "utf8"),
  ).toBe("verified SBOM\n");
  expect(publication.run().status).toBe(0);
  expect(readFileSync(publication.uploads, "utf8")).toBe(
    "action-sbom.cdx.json\n",
  );
});

test("rejects mismatched published Action metadata without replacing it", () => {
  const publication = publicationFixture("different published manifest\n");
  const result = publication.run();
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("Published Action metadata differs");
  expect(readFileSync(publication.uploads, "utf8")).toBe("");
  expect(
    readFileSync(
      join(publication.remote, "action-release-manifest.json"),
      "utf8",
    ),
  ).toBe("different published manifest\n");
});

test.each([
  ["success", "success", "success", "true", true],
  ["success", "success", "skipped", "", true],
  ["failure", "skipped", "skipped", "", false],
  ["success", "failure", "skipped", "true", false],
  ["success", "success", "failure", "true", false],
  ["success", "success", "skipped", "true", false],
  ["success", "cancelled", "skipped", "", false],
] as const)(
  "requires completed release channels: release=%s install=%s action=%s present=%s",
  (releaseResult, installResult, actionResult, hasAction, succeeds) => {
    const release = fixture();
    const result = release.run(complete, {
      RELEASE_RESULT: releaseResult,
      INSTALL_RESULT: installResult,
      ACTION_RESULT: actionResult,
      HAS_ACTION: hasAction,
    });
    expect(result.status === 0).toBe(succeeds);
  },
);
