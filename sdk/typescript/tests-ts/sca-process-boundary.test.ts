import { spawnSync } from "node:child_process";
import { chmod, mkdir, rm, writeFile } from "node:fs/promises";
import { delimiter, join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { dependencyRepositoryDirty } from "../src/sca.js";
import { git } from "./git-fixture.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const { create: temporaryDirectory, cleanup } =
  createTemporaryDirectories(true);
afterEach(cleanup);

const scannerModule = pathToFileURL(
  join(import.meta.dir, "../src/sca-osv.ts"),
).href;

function runScript(script: string, args: string[], env = process.env) {
  const child = spawnSync(process.execPath, ["-e", script, ...args], {
    encoding: "utf8",
    env,
  });
  expect(child.stderr).toBe("");
  expect(child.status).toBe(0);
  return JSON.parse(child.stdout);
}

async function fixture() {
  const root = await temporaryDirectory("sca-process-boundary-");
  const checkout = join(root, "checkout");
  const project = join(checkout, "project");
  const repositoryTools = join(checkout, "bin");
  const trustedTools = join(root, "tools");
  const output = join(root, "output");
  await Promise.all([
    mkdir(join(checkout, ".git"), { recursive: true }),
    mkdir(join(project, ".git"), { recursive: true }),
    mkdir(repositoryTools, { recursive: true }),
    mkdir(trustedTools),
    mkdir(output),
  ]);
  const suffix = process.platform === "win32" ? ".exe" : "";
  for (const directory of [repositoryTools, trustedTools]) {
    for (const name of ["git", "osv-scanner"]) {
      const executable = join(directory, `${name}${suffix}`);
      // Inert executable candidates: the isolated child records requests and never runs them.
      await writeFile(executable, "synthetic executable selection fixture\n");
      await chmod(executable, 0o700);
    }
  }
  await writeFile(
    join(project, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 3,
      packages: { "node_modules/synthetic-lib": { version: "1.0.0" } },
    }),
  );
  return { checkout, project, repositoryTools, trustedTools, output, suffix };
}

type Observation = {
  executable: string;
  argv: string[];
  environment: Record<string, string>;
};

async function observe(operation: "status" | "inventory" | "scan") {
  const paths = await fixture();
  const environment = {
    PATH: [paths.repositoryTools, paths.trustedTools].join(delimiter),
    SCA_SYNTHETIC_SETTING: "selected",
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "http.extraHeader",
    GIT_CONFIG_VALUE_0: "Authorization: synthetic-test-only",
    GIT_TRACE: "synthetic-trace",
    git_config_value_1: "synthetic-case-variant",
  };
  // Persistent ESM mocks are restricted to this subprocess. Observe ordinary
  // child requests, without executing repository binaries or configuring hooks.
  const script = `
    import { mock } from "bun:test";
    import * as childProcess from "node:child_process";
    const paths = JSON.parse(process.argv[1]);
    const environment = JSON.parse(process.argv[2]);
    const operation = process.argv[3];
    const observations = [];
    mock.module("node:child_process", () => ({
      ...childProcess,
      execFile(executable, argv, options, callback) {
        if (argv.includes("status") || argv.includes("ls-files")) {
          observations.push({ executable, argv, environment: options.env });
        }
        const stdout = argv.includes("--show-toplevel")
          ? paths.project + "\\n"
          : argv.includes("ls-files")
            ? (argv.includes("-t") ? "H package-lock.json\\0" : "")
            : "";
        callback(null, { stdout, stderr: "" });
      },
    }));
    const { dependencyRepositoryDirty } = await import(process.argv[4]);
    const { discoverScaInputs, runOsvScan } = await import(process.argv[5]);
    let result;
    if (operation === "status") {
      result = await dependencyRepositoryDirty(paths.project, environment, new AbortController().signal);
    } else if (operation === "inventory") {
      result = await discoverScaInputs(paths.project, environment);
    } else {
      result = await runOsvScan({ repositoryPath: paths.project, outputDir: paths.output, environment }, {
        runProcess: async (executable, argv, options) => {
          observations.push({ executable, argv, environment: options.environment });
          return argv[0] === "--version"
            ? { stdout: "osv-scanner version: 2.6.0", stderr: "", exitCode: 0 }
            : { stdout: JSON.stringify({ results: [{ source: { path: "package-lock.json" }, packages: [{ package: { name: "synthetic-lib", version: "1.0.0", ecosystem: "npm" } }] }] }), stderr: "", exitCode: 0 };
        },
      });
    }
    console.log(JSON.stringify({ result, observations, environment }));
  `;
  const observed = runScript(script, [
    JSON.stringify(paths),
    JSON.stringify(environment),
    operation,
    pathToFileURL(join(import.meta.dir, "../src/sca.ts")).href,
    scannerModule,
  ]) as {
    result: unknown;
    observations: Observation[];
    environment: typeof environment;
  };
  expect(observed.environment).toEqual(environment);
  return { ...paths, ...observed };
}

test("SCA dirty reporting follows the selected Git subtree", async () => {
  const root = await temporaryDirectory("sca-dirty-subtree-");
  const project = join(root, "project");
  const sibling = join(root, "sibling");
  await Promise.all([mkdir(project), mkdir(sibling)]);
  for (const directory of [project, sibling])
    await writeFile(join(directory, "tracked.txt"), "original\n");
  git(root, "init", "--quiet");
  git(root, "add", ".");
  git(
    root,
    "-c",
    "commit.gpgsign=false",
    "commit",
    "--quiet",
    "-m",
    "Synthetic fixture",
  );
  const signal = new AbortController().signal;
  const dirty = (path: string) =>
    dependencyRepositoryDirty(path, process.env, signal);
  expect(await dirty(project)).toBe(false);
  await writeFile(join(sibling, "tracked.txt"), "changed sibling\n");
  expect(await dirty(project)).toBe(false);
  await writeFile(join(sibling, "untracked.txt"), "untracked sibling\n");
  expect(await dirty(project)).toBe(false);
  expect(await dirty(root)).toBe(true);
  await writeFile(join(project, "tracked.txt"), "changed selected file\n");
  expect(await dirty(project)).toBe(true);
  await writeFile(join(project, "tracked.txt"), "original\n");
  await writeFile(join(project, "untracked.txt"), "untracked selected file\n");
  expect(await dirty(project)).toBe(true);
});

test.each(["status", "inventory"] as const)(
  "SCA %s Git requests protect the enclosing checkout and isolate selected configuration",
  async (operation) => {
    const observed = await observe(operation);
    const command = observed.observations.find((item) =>
      item.argv.includes(operation === "status" ? "status" : "ls-files"),
    );
    expect(command).toBeDefined();
    expect(command!.executable).toBe(
      join(observed.trustedTools, `git${observed.suffix}`),
    );
    expect(command!.argv.slice(0, 4)).toEqual([
      "-c",
      "core.fsmonitor=false",
      "-C",
      observed.project,
    ]);
    expect(command!.environment).toEqual({
      PATH: observed.trustedTools,
      SCA_SYNTHETIC_SETTING: "selected",
      GIT_ALLOW_PROTOCOL: "",
    });
    if (operation === "status") expect(observed.result).toBe(false);
    else
      expect(observed.result).toMatchObject({
        inputs: [{ path: "package-lock.json", status: "scanned" }],
      });
  },
);

test("SCA scanner requests use the enclosing checkout trust boundary and selected environment", async () => {
  const observed = await observe("scan");
  const commands = observed.observations.filter(
    (item) => !item.argv.includes("ls-files"),
  );
  expect(commands).toHaveLength(2);
  for (const command of commands) {
    expect(command.executable).toBe(
      join(observed.trustedTools, `osv-scanner${observed.suffix}`),
    );
    expect(command.environment["PATH"]).toBe(observed.trustedTools);
    expect(command.environment["SCA_SYNTHETIC_SETTING"]).toBe("selected");
  }
  expect(observed.result).toMatchObject({
    status: "completed",
    coverage: { status: "complete" },
  });
});

test.each(["missing-git", "broken-metadata", "standalone"] as const)(
  "inventory distinguishes failed Git discovery from standalone directories: %s",
  async (scenario) => {
    const root = await temporaryDirectory("sca-git-discovery-");
    const repository = join(root, "repository");
    await mkdir(join(repository, "ignored"), { recursive: true });
    await writeFile(join(repository, ".gitignore"), "ignored/\n");
    await writeFile(
      join(repository, "ignored", "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "node_modules/synthetic-lib": { version: "1.0.0" } },
      }),
    );
    if (scenario !== "standalone") {
      git(repository, "init", "--quiet");
      if (scenario === "broken-metadata")
        await rm(join(repository, ".git", "HEAD"));
    }
    const environment = { ...process.env };
    if (scenario !== "broken-metadata") {
      for (const name of Object.keys(environment))
        if (name.toUpperCase() === "PATH") delete environment[name];
      environment["PATH"] = "";
    }
    // Isolate PATH changes while exercising actual Git metadata and discovery.
    const script = `
      const [repository, output, module] = process.argv.slice(1);
      const { discoverScaInputs, runOsvScan } = await import(module);
      let discovery;
      try {
        discovery = await discoverScaInputs(repository);
      } catch (error) {
        discovery = { error: error.message };
      }
      let scannerCalls = 0;
      const result = await runOsvScan({ repositoryPath: repository, outputDir: output }, {
        executable: process.execPath,
        runProcess: async (_executable, argv) => {
          scannerCalls++;
          return argv[0] === "--version"
            ? { stdout: "osv-scanner version: 2.6.0", stderr: "", exitCode: 0 }
            : { stdout: JSON.stringify({ results: [{ source: { path: argv.at(-1) }, packages: [{ package: { name: "synthetic-lib", version: "1.0.0", ecosystem: "npm" } }] }] }), stderr: "", exitCode: 0 };
        },
      });
      console.log(JSON.stringify({ discovery, result, scannerCalls }));
    `;
    const { discovery, result, scannerCalls } = runScript(
      script,
      [repository, join(root, "output"), scannerModule],
      environment,
    );
    if (scenario === "standalone") {
      expect(discovery.inputs).toMatchObject([
        { path: "ignored/package-lock.json", status: "scanned" },
      ]);
      expect(result).toMatchObject({
        status: "completed",
        coverage: { status: "complete" },
      });
      expect(scannerCalls).toBe(2);
    } else {
      expect(discovery.error).toContain(
        "Could not determine the Git worktree root",
      );
      expect(result).toMatchObject({
        status: "failed",
        coverage: { status: "failed", inputs: [] },
        scanner: { invocations: [] },
      });
      expect(result.diagnostics.join("\n")).toContain(
        "Could not determine the Git worktree root",
      );
      expect(scannerCalls).toBe(0);
    }
  },
);

test.each([true, false])(
  "scoped Git inventory matches indexed prefixes by filesystem identity, same directory: %p",
  async (sameDirectory) => {
    const root = await temporaryDirectory("sca-git-scope-");
    const repository = join(root, "repository");
    const selected = join(repository, "SRC");
    const indexed = join(repository, "src");
    await mkdir(selected, { recursive: true });
    await writeFile(join(repository, ".gitignore"), "*\n");
    await writeFile(
      join(selected, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 3, packages: {} }),
    );
    git(repository, "init", "--quiet");
    const oid = git(
      repository,
      "hash-object",
      "-w",
      "--",
      join(selected, "package-lock.json"),
    );
    git(
      repository,
      "update-index",
      "--add",
      "--cacheinfo",
      "100644",
      oid,
      "src/package-lock.json",
    );
    // Model the filesystem identity lookup at the portable boundary. The Git index
    // and ignored working-tree lockfile are real; no application code is executed.
    // The second case represents distinct case-sensitive directories.
    const other = join(root, "distinct-directory");
    await mkdir(other);
    const script = `
    import { mock } from "bun:test";
    import * as filesystem from "node:fs/promises";
    const [selected, indexed, other, sameDirectory, module] = process.argv.slice(1);
    const nativeStat = filesystem.stat;
    mock.module("node:fs/promises", () => ({
      ...filesystem,
      stat(path, options) {
        return nativeStat(path === indexed ? (sameDirectory === "true" ? selected : other) : path, options);
      },
    }));
    const { discoverScaInputs } = await import(module);
    const result = await discoverScaInputs(selected);
    console.log(JSON.stringify(result));
  `;
    const result = runScript(script, [
      selected,
      indexed,
      other,
      String(sameDirectory),
      scannerModule,
    ]);
    expect(
      result.inputs.map((input: { path: string; status: string }) => [
        input.path,
        input.status,
      ]),
    ).toEqual(sameDirectory ? [["package-lock.json", "scanned"]] : []);
    expect(result.diagnostics).toEqual([]);
  },
);
