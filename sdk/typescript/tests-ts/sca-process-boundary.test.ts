import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { dependencyRepositoryDirty } from "../src/sca.js";

const temporaryDirectories: string[] = [];
afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "sca-process-boundary-")),
  );
  temporaryDirectories.push(root);
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
  const child = spawnSync(
    process.execPath,
    [
      "-e",
      script,
      JSON.stringify(paths),
      JSON.stringify(environment),
      operation,
      pathToFileURL(join(import.meta.dir, "../src/sca.ts")).href,
      pathToFileURL(join(import.meta.dir, "../src/sca-osv.ts")).href,
    ],
    { encoding: "utf8" },
  );
  expect(child.stderr).toBe("");
  expect(child.status).toBe(0);
  const observed = JSON.parse(child.stdout) as {
    result: unknown;
    observations: Observation[];
    environment: typeof environment;
  };
  expect(observed.environment).toEqual(environment);
  return { ...paths, ...observed };
}

test("SCA dirty reporting follows the selected Git subtree", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "sca-dirty-subtree-")),
  );
  temporaryDirectories.push(root);
  const project = join(root, "project");
  const sibling = join(root, "sibling");
  await Promise.all([mkdir(project), mkdir(sibling)]);
  for (const directory of [project, sibling])
    await writeFile(join(directory, "tracked.txt"), "original\n");
  const git = (...args: string[]) => {
    const child = spawnSync("git", ["-C", root, ...args], {
      encoding: "utf8",
    });
    expect(child.status, child.stderr).toBe(0);
  };
  git("init", "--quiet");
  git("add", ".");
  git(
    "-c",
    "user.name=Synthetic Fixture",
    "-c",
    "user.email=fixture@example.invalid",
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
