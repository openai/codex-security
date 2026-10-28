import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import * as filesystem from "node:fs/promises";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import {
  discoverScaInputs,
  normalizeOsvOutput,
  osvErrorDiagnostics,
  runOsvProcess,
  runOsvScan,
  type OsvProcessOptions,
  type OsvProcessResult,
  type OsvScanResult,
} from "../src/sca-osv.js";
import type { ScaInput } from "../src/sca-types.js";
import type { DependencyScanProgress } from "../src/sca-progress.js";
import { dependencyScanResult, saveDependencyScan } from "../src/sca.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const execFile = promisify(execFileCallback);
const temporaryDirectories: string[] = [];
afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});
async function setup() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "sca-osv-")));
  temporaryDirectories.push(root);
  const repository = join(root, "repository with spaces");
  const output = join(root, "output");
  await Promise.all([mkdir(repository), mkdir(output)]);
  return { root, repository, output };
}
const npmLock = (version = 3) =>
  JSON.stringify({
    name: "synthetic-app",
    lockfileVersion: version,
    packages: {
      "": { name: "synthetic-app", version: "1.0.0" },
      "node_modules/synthetic-lib": { version: "1.2.0" },
    },
  });
function input(path = "package-lock.json"): ScaInput {
  return {
    path,
    format: "npm",
    status: "scanned",
    reason: null,
    sha256: "abc",
  };
}
function advisory(id: string, aliases: string[] = []) {
  return {
    id,
    aliases,
    modified: "2026-01-01T00:00:00Z",
    affected: [
      {
        package: { name: "synthetic-lib", ecosystem: "npm" },
        ranges: [
          { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.3.0" }] },
        ],
      },
    ],
  };
}
function rawOutput(source: string, vulnerabilities: unknown[] = []) {
  return {
    results: [
      {
        source: { path: source, type: "lockfile" },
        packages: [
          {
            package: {
              name: "synthetic-lib",
              version: "1.2.0",
              ecosystem: "npm",
            },
            dependency_groups: ["dev"],
            vulnerabilities,
          },
        ],
      },
    ],
  };
}
async function scanFixture(
  out: OsvProcessResult,
  files: Record<string, string> = {},
) {
  const { repository, output } = await setup();
  await writeFile(join(repository, "package-lock.json"), npmLock());
  for (const [path, content] of Object.entries(files)) {
    await mkdir(join(repository, path, ".."), { recursive: true });
    await writeFile(join(repository, path), content);
  }
  return runOsvScan(
    { repositoryPath: repository, outputDir: output },
    {
      executable: process.execPath,
      runProcess: async (_exe, argv) =>
        argv[0] === "--version"
          ? { stdout: "osv-scanner version: 2.6.0\n", stderr: "", exitCode: 0 }
          : out,
    },
  );
}

test.each(
  [
    null,
    "registry+https://github.com/rust-lang/crates.io-index",
    "registry+https://registry.example.test/index",
  ].flatMap((source) =>
    [false, true].map((inherited) => [source, inherited] as const),
  ),
)(
  "excludes only unambiguous first-party Cargo matches and retains raw output (source-bearing twin: %p, inherited version: %p)",
  async (source, inherited) => {
    const { repository, output } = await setup();
    await writeFile(
      join(repository, "Cargo.toml"),
      '[package]\nname="synthetic-lib"\n' +
        (inherited
          ? 'version.workspace=true\n[workspace.package]\nversion="1.2.0"\n'
          : 'version="1.2.0"\n[workspace.package]\nversion="9.9.9"\n'),
    );
    await writeFile(
      join(repository, "Cargo.lock"),
      'version=4\n[[package]]\nname="synthetic-lib"\nversion="1.2.0"\n' +
        (source === null
          ? ""
          : `dependencies=["synthetic-lib 1.2.0 (${source})"]\n[[package]]\nname="synthetic-lib"\nversion="1.2.0"\nsource="${source}"\n`),
    );
    const vulnerability = advisory("SYNTHETIC-CARGO-1");
    vulnerability.affected[0]!.package.ecosystem = "crates.io";
    const raw = rawOutput("Cargo.lock", [vulnerability]);
    raw.results[0]!.packages[0]!.package.ecosystem = "crates.io";
    if (source !== null)
      raw.results[0]!.packages.push(
        structuredClone(raw.results[0]!.packages[0]!),
      );
    const serialized = JSON.stringify(raw);
    const result = await runOsvScan(
      { repositoryPath: repository, outputDir: output },
      {
        executable: process.execPath,
        runProcess: async (_exe, argv) => ({
          stdout: argv[0] === "--version" ? "2.6.0" : serialized,
          stderr: "",
          exitCode: argv[0] === "--version" ? 0 : 1,
        }),
      },
    );
    const alternate = source === "registry+https://registry.example.test/index";
    expect(result.coverage.firstPartyPackages).toHaveLength(
      source === null ? 1 : 0,
    );
    expect(result.components).toHaveLength(source === null ? 0 : 1);
    expect(result.matches).toHaveLength(source === null ? 0 : 1);
    if (source !== null)
      expect(result.matches[0]!.advisoryIds).toEqual(["SYNTHETIC-CARGO-1"]);
    expect(result.status).toBe(alternate ? "partial" : "completed");
    expect(result.coverage.status).toBe(alternate ? "partial" : "complete");
    expect(result.coverage.unresolvedPackages).toBe(alternate ? 1 : 0);
    if (alternate)
      expect(result.coverage.limitations.join("\n")).toContain(source!);
    expect(result.diagnostics).toEqual([]);
    expect(await readFile(result.scanner.rawOutputPath, "utf8")).toBe(
      serialized,
    );
  },
);

test.each(["missing", "external", "mismatched"] as const)(
  "keeps inherited Cargo version unresolved without a matching same-manifest value: %s",
  async (kind) => {
    const { root, repository, output } = await setup();
    if (kind === "external") {
      await mkdir(join(root, "workspace"));
      await writeFile(
        join(root, "workspace", "Cargo.toml"),
        '[workspace.package]\nversion="1.2.0"\n',
      );
    }
    await writeFile(
      join(repository, "Cargo.toml"),
      '[package]\nname="synthetic-lib"\nversion.workspace=true\n' +
        (kind === "external"
          ? 'workspace="../workspace"\n'
          : kind === "mismatched"
            ? '[workspace.package]\nversion="1.2.1"\n'
            : ""),
    );
    await writeFile(
      join(repository, "Cargo.lock"),
      'version=4\n[[package]]\nname="synthetic-lib"\nversion="1.2.0"\n',
    );
    const vulnerability = advisory("SYNTHETIC-CARGO-1");
    vulnerability.affected[0]!.package.ecosystem = "crates.io";
    const raw = rawOutput("Cargo.lock", [vulnerability]);
    raw.results[0]!.packages[0]!.package.ecosystem = "crates.io";
    const serialized = JSON.stringify(raw);
    const result = await runOsvScan(
      { repositoryPath: repository, outputDir: output },
      {
        executable: process.execPath,
        runProcess: async (_exe, argv) => ({
          stdout: argv[0] === "--version" ? "2.6.0" : serialized,
          stderr: "",
          exitCode: argv[0] === "--version" ? 0 : 1,
        }),
      },
    );
    expect(result.coverage.firstPartyPackages).toEqual([]);
    expect(result.coverage.unresolvedPackages).toBe(1);
    expect(result.status).toBe("partial");
    expect(result.coverage.status).toBe("partial");
    expect(result.components).toHaveLength(1);
    expect(result.matches[0]!.advisoryIds).toEqual(["SYNTHETIC-CARGO-1"]);
    expect(result.coverage.limitations.join("\n")).toContain(
      "workspace-or-path",
    );
    expect(await readFile(result.scanner.rawOutputPath, "utf8")).toBe(
      serialized,
    );
  },
);

test("first-party Cargo exclusion preserves other sources, names, versions, and ecosystems", async () => {
  const { repository, output } = await setup();
  await writeFile(
    join(repository, "Cargo.toml"),
    '[package]\nname="synthetic-lib"\nversion="1.2.0"\n',
  );
  await writeFile(
    join(repository, "Cargo.lock"),
    'version=4\n[[package]]\nname="synthetic-lib"\nversion="1.2.0"\n',
  );
  await mkdir(join(repository, "nested"));
  await writeFile(
    join(repository, "nested/Cargo.lock"),
    'version=4\n[[package]]\nname="synthetic-lib"\nversion="1.2.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n',
  );
  const rawSources: unknown[] = [];
  const result = await runOsvScan(
    { repositoryPath: repository, outputDir: output },
    {
      executable: process.execPath,
      runProcess: async (_exe, argv) => {
        if (argv[0] === "--version")
          return { stdout: "2.6.0", stderr: "", exitCode: 0 };
        const raw = rawOutput(argv.at(-1)!, [advisory("SYNTHETIC-CARGO-1")]);
        const source = raw.results[0]!;
        source.packages[0]!.package.ecosystem = "crates.io";
        if (argv.at(-1) === join(repository, "Cargo.lock")) {
          for (const identity of [
            { name: "synthetic-other" },
            { version: "1.2.1" },
            { ecosystem: "npm" },
          ]) {
            const item = structuredClone(source.packages[0]!);
            Object.assign(item.package, identity);
            source.packages.push(item);
          }
        }
        rawSources.push(source);
        return { stdout: JSON.stringify(raw), stderr: "", exitCode: 1 };
      },
    },
  );
  expect(result.components).toHaveLength(4);
  expect(
    result.components.map(({ sourcePath, name, version, ecosystem }) => ({
      sourcePath,
      name,
      version,
      ecosystem,
    })),
  ).toEqual(
    expect.arrayContaining([
      {
        sourcePath: "Cargo.lock",
        name: "synthetic-other",
        version: "1.2.0",
        ecosystem: "crates.io",
      },
      {
        sourcePath: "Cargo.lock",
        name: "synthetic-lib",
        version: "1.2.1",
        ecosystem: "crates.io",
      },
      {
        sourcePath: "Cargo.lock",
        name: "synthetic-lib",
        version: "1.2.0",
        ecosystem: "npm",
      },
      {
        sourcePath: "nested/Cargo.lock",
        name: "synthetic-lib",
        version: "1.2.0",
        ecosystem: "crates.io",
      },
    ]),
  );
  expect(result.matches.map((match) => match.componentId).sort()).toEqual(
    result.components.map((component) => component.id).sort(),
  );
  expect(result.status).toBe("completed");
  expect(
    JSON.parse(await readFile(result.scanner.rawOutputPath, "utf8")),
  ).toEqual({ results: rawSources });
});

test("first-party Cargo exclusion retains malformed advisory diagnostics", async () => {
  const { repository, output } = await setup();
  await writeFile(
    join(repository, "Cargo.toml"),
    '[package]\nname="synthetic-lib"\nversion="1.2.0"\n',
  );
  await writeFile(
    join(repository, "Cargo.lock"),
    'version=4\n[[package]]\nname="synthetic-lib"\nversion="1.2.0"\n',
  );
  const raw = rawOutput("Cargo.lock", [{}]);
  raw.results[0]!.packages[0]!.package.ecosystem = "crates.io";
  const serialized = JSON.stringify(raw);
  const result = await runOsvScan(
    { repositoryPath: repository, outputDir: output },
    {
      executable: process.execPath,
      runProcess: async (_exe, argv) => ({
        stdout: argv[0] === "--version" ? "2.6.0" : serialized,
        stderr: "",
        exitCode: argv[0] === "--version" ? 0 : 1,
      }),
    },
  );
  expect(result.components).toEqual([]);
  expect(result.matches).toEqual([]);
  expect(result.status).not.toBe("completed");
  expect(result.diagnostics).toContain(
    "OSV advisory ID is missing for Cargo.lock:synthetic-lib; inspect retained raw output.",
  );
  expect(result.diagnostics).toContain(
    "Cargo.lock: OSV reported findings but no advisory matches could be normalized.",
  );
  expect(await readFile(result.scanner.rawOutputPath, "utf8")).toBe(serialized);
});

test("matching progress counts finished invocations, including failures, independently of input selection", async () => {
  const { repository, output } = await setup();
  await mkdir(join(repository, "nested"));
  await writeFile(join(repository, "package-lock.json"), npmLock());
  await writeFile(join(repository, "nested", "package-lock.json"), npmLock());
  const events: DependencyScanProgress[] = [];
  const observedDuringProcess: DependencyScanProgress[] = [];
  let invocations = 0;
  const result = await runOsvScan(
    {
      repositoryPath: repository,
      outputDir: output,
      onProgress: (event) => {
        events.push(event);
      },
    },
    {
      executable: process.execPath,
      runProcess: async (_executable, argv) => {
        if (argv[0] === "--version")
          return { stdout: "2.6.0", stderr: "", exitCode: 0 };
        observedDuringProcess.push(events.at(-1)!);
        invocations++;
        return invocations === 1
          ? {
              stdout: JSON.stringify(
                rawOutput(argv.at(-1)!, [advisory("SYNTHETIC-1")]),
              ),
              stderr: "",
              exitCode: 1,
            }
          : { stdout: "", stderr: "synthetic scanner failure", exitCode: 2 };
      },
    },
  );
  expect(events[0]).toEqual({ phase: "discovering" });
  expect(observedDuringProcess).toEqual([
    expect.objectContaining({
      phase: "matching",
      inputsTotal: 2,
      inputsProcessed: 0,
      inputsFailed: 0,
      currentInput: expect.any(String),
    }),
    expect.objectContaining({
      phase: "matching",
      inputsTotal: 2,
      inputsProcessed: 1,
      inputsFailed: 0,
      currentInput: expect.any(String),
    }),
  ]);
  expect(events.at(-1)).toEqual({
    phase: "matching",
    inputsTotal: 2,
    inputsProcessed: 2,
    inputsFailed: 1,
    currentInput: null,
    components: result.components.length,
    matches: result.matches.length,
  });
  expect(result.matches).toHaveLength(1);
  expect(result.status).toBe("partial");
});

test.each(["throw", "reject", "pending"] as const)(
  "OSV work continues when its progress observer is %s",
  async (behavior) => {
    const { repository, output } = await setup();
    await writeFile(join(repository, "package-lock.json"), npmLock());
    const result = await runOsvScan(
      {
        repositoryPath: repository,
        outputDir: output,
        onProgress: () => {
          if (behavior === "throw") throw new Error("progress unavailable");
          if (behavior === "reject")
            return Promise.reject(new Error("progress unavailable"));
          return new Promise<void>(() => {});
        },
      },
      {
        executable: process.execPath,
        runProcess: async (_executable, argv) => ({
          stdout:
            argv[0] === "--version"
              ? "2.6.0"
              : JSON.stringify(rawOutput(argv.at(-1)!)),
          stderr: "",
          exitCode: 0,
        }),
      },
    );
    expect(result.status).toBe("completed");
    expect(result.components).toHaveLength(1);
  },
);

test.each(["missing", "version", "invocation"] as const)(
  "matching progress includes inputs that fail before processing: %s",
  async (failure) => {
    const { repository, output, root } = await setup();
    await mkdir(join(repository, "nested"));
    await writeFile(join(repository, "package-lock.json"), npmLock());
    await writeFile(join(repository, "nested", "package-lock.json"), npmLock());
    const progress: DependencyScanProgress[] = [];
    const result = await runOsvScan(
      {
        repositoryPath: repository,
        outputDir: output,
        onProgress: (event) => {
          progress.push(event);
        },
      },
      {
        executable:
          failure === "missing"
            ? join(root, "missing-scanner")
            : process.execPath,
        runProcess: async (_executable, argv) => {
          if (failure === "version" || argv[0] !== "--version")
            throw new Error("synthetic scanner failure");
          return { stdout: "2.6.0", stderr: "", exitCode: 0 };
        },
      },
    );
    expect(result.status).toBe("failed");
    expect(progress.at(-1)).toMatchObject({
      phase: "matching",
      inputsTotal: 2,
      inputsProcessed: failure === "invocation" ? 1 : 0,
      inputsFailed: 2,
      currentInput: null,
    });
  },
);

async function initializedSubmodule(
  repository: string,
  path = "vendor/library",
) {
  const git = async (cwd: string, args: string[]) =>
    execFile("git", [
      "-c",
      `core.hooksPath=${join(repository, ".git", "empty-hooks")}`,
      "-c",
      "commit.gpgSign=false",
      "-c",
      "user.name=Synthetic",
      "-c",
      "user.email=synthetic@example.test",
      "-C",
      cwd,
      ...args,
    ]);
  await git(repository, ["init", "--quiet"]);
  const nested = join(repository, path);
  await mkdir(nested, { recursive: true });
  await git(nested, ["init", "--quiet"]);
  await writeFile(join(nested, "package-lock.json"), npmLock());
  await git(nested, ["add", "package-lock.json"]);
  await git(nested, [
    "commit",
    "--quiet",
    "-m",
    "Synthetic dependency fixture",
  ]);
  const revision = (await git(nested, ["rev-parse", "HEAD"])).stdout.trim();
  await git(repository, [
    "update-index",
    "--add",
    "--cacheinfo",
    "160000",
    revision,
    path,
  ]);
  return nested;
}

describe("SCA input selection", () => {
  test.skipIf(process.platform !== "linux").each([
    ...[false, true].flatMap((tracked) =>
      [".", "selected"].map((scope) => ({
        tracked,
        scope,
        unreadable: false,
      })),
    ),
    { tracked: true, scope: ".", unreadable: true },
  ])(
    "retains incomplete Git coverage for byte paths: %p",
    async ({ tracked, scope, unreadable }) => {
      const { repository, output } = await setup();
      await execFile("git", ["init", "--quiet", repository]);
      const selected = join(repository, scope);
      await mkdir(selected, { recursive: true });
      const rawDirectory = Buffer.concat([
        Buffer.from(`${selected}/project-`),
        Buffer.from([0xff]),
      ]);
      const rawPath = Buffer.concat([
        rawDirectory,
        Buffer.from("/package-lock.json"),
      ]);
      await mkdir(rawDirectory);
      await writeFile(rawPath, npmLock());
      await writeFile(join(selected, "package-lock.json"), npmLock());
      if (tracked) await execFile("git", ["-C", repository, "add", "--all"]);
      if (unreadable) await filesystem.chmod(rawDirectory, 0);
      const result = await runOsvScan(
        { repositoryPath: selected, outputDir: output },
        {
          executable: process.execPath,
          runProcess: async (_executable, argv) =>
            argv[0] === "--version"
              ? { stdout: "2.6.0", stderr: "", exitCode: 0 }
              : {
                  stdout: JSON.stringify(rawOutput("package-lock.json")),
                  stderr: "",
                  exitCode: 0,
                },
        },
      ).finally(async () => {
        if (unreadable) await filesystem.chmod(rawDirectory, 0o700);
      });
      expect(result.status).toBe("partial");
      expect(result.coverage.status).toBe("partial");
      expect(result.coverage.inputs.map((input) => input.path)).toEqual([
        "package-lock.json",
      ]);
      expect(result.components).toHaveLength(1);
      expect(result.scanner.invocations).toHaveLength(1);
      const pathBytes = Buffer.concat([
        Buffer.from("project-"),
        Buffer.from([0xff]),
        Buffer.from("/package-lock.json"),
      ]).toString("hex");
      expect(result.diagnostics).toHaveLength(1);
      expect(result.diagnostics[0]).toContain(pathBytes);
      if (unreadable && process.getuid?.() !== 0)
        expect(result.diagnostics[0]).toContain("EACCES");
      expect(result.coverage.limitations).toContain(result.diagnostics[0]!);
      expect(await readFile(rawPath, "utf8")).toBe(npmLock());
      expect(
        JSON.parse(await readFile(result.scanner.rawOutputPath, "utf8")),
      ).toEqual(rawOutput("package-lock.json"));
    },
  );

  test
    .skipIf(process.platform !== "linux")
    .each(["sparse", "nested", "gitlink"])(
    "retains incomplete Git coverage for byte-path %s boundaries",
    async (kind) => {
      const { root, repository } = await setup();
      const git = (cwd: string, ...args: string[]) =>
        execFile("git", [
          "-c",
          "core.hooksPath=",
          "-c",
          "commit.gpgSign=false",
          "-c",
          "user.name=Synthetic",
          "-c",
          "user.email=synthetic@example.test",
          "-C",
          cwd,
          ...args,
        ]);
      await git(repository, "init", "--quiet");
      await writeFile(join(repository, "package-lock.json"), npmLock());
      const directoryBytes = Buffer.concat([
        Buffer.from("project-"),
        Buffer.from([0xff]),
      ]);
      const rawDirectory = Buffer.concat([
        Buffer.from(`${repository}/`),
        directoryBytes,
      ]);
      const rawPath = Buffer.concat([
        rawDirectory,
        Buffer.from("/package-lock.json"),
      ]);
      await mkdir(rawDirectory);
      await writeFile(rawPath, npmLock());
      if (kind === "sparse") {
        await mkdir(join(repository, "included"));
        await writeFile(
          join(repository, "included", "README.md"),
          "Synthetic sparse fixture\n",
        );
        await git(repository, "add", "--all");
        await git(
          repository,
          "commit",
          "--quiet",
          "-m",
          "Synthetic sparse inventory",
        );
        await git(repository, "sparse-checkout", "init", "--cone");
        await git(repository, "sparse-checkout", "set", "included");
        expect(
          await filesystem
            .lstat(rawPath)
            .catch((error: NodeJS.ErrnoException) => error.code),
        ).toBe("ENOENT");
      } else {
        const alias = join(root, "nested-checkout");
        await symlink(rawDirectory, alias);
        await git(alias, "init", "--quiet");
        if (kind === "gitlink") {
          await git(alias, "add", "--all");
          await git(
            alias,
            "commit",
            "--quiet",
            "-m",
            "Synthetic nested inventory",
          );
          await git(repository, "add", "--all");
          expect(
            (await git(repository, "ls-files", "--stage")).stdout,
          ).toContain("160000 ");
        }
      }
      const result = await discoverScaInputs(repository);
      expect(result.inputs.map((input) => input.path)).toEqual([
        "package-lock.json",
      ]);
      expect(result.diagnostics).toHaveLength(1);
      const pathBytes =
        kind === "sparse"
          ? Buffer.concat([directoryBytes, Buffer.from("/package-lock.json")])
          : directoryBytes;
      expect(result.diagnostics[0]).toContain(pathBytes.toString("hex"));
      expect(result.limitations).toContain(result.diagnostics[0]!);
    },
  );

  test("Git inventory preserves UTF-8 replacement characters and leading BOMs", async () => {
    const { repository } = await setup();
    await execFile("git", ["init", "--quiet", repository]);
    const paths = [
      "project-\uFFFD/package-lock.json",
      "\uFEFFproject/package-lock.json",
    ];
    for (const path of paths) {
      await mkdir(join(repository, path, ".."), { recursive: true });
      await writeFile(join(repository, path), npmLock());
    }
    await execFile("git", ["-C", repository, "add", "--all"]);
    const result = await discoverScaInputs(repository);
    expect(result.inputs.map((input) => input.path)).toEqual(paths.sort());
    expect(result.inputs.every((input) => input.sha256 !== "")).toBe(true);
    expect(result.diagnostics).toEqual([]);
  });

  test.skipIf(process.platform !== "linux")(
    "Git byte paths preserve excluded, unrelated, deleted and sibling scope",
    async () => {
      const { repository } = await setup();
      await execFile("git", ["init", "--quiet", repository]);
      const selected = join(repository, "selected");
      await mkdir(selected);
      await writeFile(join(selected, "package-lock.json"), npmLock());
      let deleted: Buffer | undefined;
      for (const [directory, filename] of [
        ["sibling", "package-lock.json"],
        ["selected/node_modules", "package-lock.json"],
        ["selected/unrelated", "README.md"],
        ["selected/deleted", "package-lock.json"],
      ]) {
        const rawDirectory = Buffer.concat([
          Buffer.from(`${repository}/${directory}/project-`),
          Buffer.from([0xff]),
        ]);
        await mkdir(rawDirectory, { recursive: true });
        const path = Buffer.concat([rawDirectory, Buffer.from(`/${filename}`)]);
        await writeFile(path, npmLock());
        if (directory === "selected/deleted") deleted = path;
      }
      await execFile("git", ["-C", repository, "add", "--all"]);
      await rm(deleted!);
      const result = await discoverScaInputs(selected);
      expect(result.inputs.map((input) => input.path)).toEqual([
        "package-lock.json",
      ]);
      expect(result.diagnostics).toEqual([]);
    },
  );

  test("retains absent sparse-checkout lockfiles without counting ordinary deletions or unselected paths", async () => {
    const { repository, output } = await setup();
    const git = (...args: string[]) =>
      execFile("git", [
        "-c",
        "core.hooksPath=",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "user.name=Synthetic",
        "-c",
        "user.email=synthetic@example.test",
        "-C",
        repository,
        ...args,
      ]);
    for (const directory of ["included", "omitted"]) {
      await mkdir(join(repository, directory));
      await writeFile(
        join(repository, directory, "package-lock.json"),
        npmLock(),
      );
    }
    await git("init", "--quiet");
    await git("add", ".");
    await git("commit", "--quiet", "-m", "Synthetic sparse inventory");
    await git("sparse-checkout", "init", "--cone");
    await git("sparse-checkout", "set", "included");
    expect((await git("status", "--porcelain")).stdout).toBe("");
    const discovered = await discoverScaInputs(repository);
    expect(
      discovered.inputs.map(({ path, status }) => ({ path, status })),
    ).toEqual([
      { path: "included/package-lock.json", status: "scanned" },
      { path: "omitted/package-lock.json", status: "unsupported" },
    ]);
    expect(discovered.inputs[1]!.reason).toContain("sparse checkout");
    expect(
      (await discoverScaInputs(join(repository, "included"))).inputs,
    ).toMatchObject([{ path: "package-lock.json", status: "scanned" }]);
    const result = await runOsvScan(
      { repositoryPath: repository, outputDir: output },
      {
        executable: process.execPath,
        runProcess: async (_executable, argv) => ({
          stdout:
            argv[0] === "--version"
              ? "2.6.0"
              : JSON.stringify(rawOutput("included/package-lock.json")),
          stderr: "",
          exitCode: 0,
        }),
      },
    );
    expect(result.status).toBe("partial");
    expect(result.coverage.status).toBe("partial");
    expect(result.coverage.inputs).toEqual(discovered.inputs);
    expect(result.components).toHaveLength(1);
    // A non-directory ancestor does not make a sparse input an ordinary deletion.
    await writeFile(join(repository, "omitted"), "replacement file\n");
    expect((await discoverScaInputs(repository)).inputs).toEqual(
      discovered.inputs,
    );
    await rm(join(repository, "omitted"));
    await rm(join(repository, "included", "package-lock.json"));
    expect((await discoverScaInputs(repository)).inputs).toEqual([
      discovered.inputs[1]!,
    ]);
    expect(
      (await discoverScaInputs(join(repository, "included"))).inputs,
    ).toEqual([]);
  });
  test("selects npm v2/v3 and pnpm v9 across nested workspaces, excluding installed trees", async () => {
    const { repository } = await setup();
    await Promise.all([
      mkdir(join(repository, "packages", "app"), { recursive: true }),
      mkdir(join(repository, "node_modules", "library"), { recursive: true }),
    ]);
    await Promise.all([
      writeFile(join(repository, "package-lock.json"), npmLock(2)),
      writeFile(
        join(repository, "packages", "app", "pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\npackages: {}\n",
      ),
      writeFile(
        join(repository, "node_modules", "library", "package-lock.json"),
        npmLock(),
      ),
    ]);
    const discovered = await discoverScaInputs(repository);
    expect(discovered.inputs.map((item) => [item.path, item.status])).toEqual([
      ["package-lock.json", "scanned"],
      ["packages/app/pnpm-lock.yaml", "scanned"],
    ]);
    expect(
      discovered.inputs.every((item) => /^[a-f0-9]{64}$/u.test(item.sha256)),
    ).toBe(true);
  });
  test.each(
    ["non-Git", "Git untracked", "Git tracked", "Git subdirectory"].flatMap(
      (mode) => [false, true].map((mixedCase) => [mode, mixedCase] as const),
    ),
  )(
    "excludes installed dependency trees with native casing (%s, mixed case: %p)",
    async (mode, mixedCase) => {
      const { repository: checkout } = await setup();
      const repository =
        mode === "Git subdirectory"
          ? join(checkout, "packages", "selected")
          : checkout;
      await mkdir(repository, { recursive: true });
      if (mode !== "non-Git") await execFile("git", ["init", checkout]);
      const caseVariants: Record<string, string> = {
        node_modules: "Node_Modules",
        ".venv": ".VENV",
        venv: "Venv",
        ".tox": ".Tox",
        ".nox": ".Nox",
        ".m2": ".M2",
        repository: "Repository",
        vendor: "Vendor",
        bundle: "Bundle",
      };
      const spelling = (path: string) =>
        mixedCase
          ? path
              .split("/")
              .map((name) => caseVariants[name] ?? name)
              .join("/")
          : path;
      const installed = [
        "node_modules/library/package-lock.json",
        ".venv/lib/python3.12/site-packages/synthetic/requirements.txt",
        "venv/Lib/site-packages/synthetic/requirements.txt",
        ".tox/py312/lib/python3.12/site-packages/synthetic/requirements.txt",
        ".nox/tests/Lib/site-packages/synthetic/requirements.txt",
        ".m2/repository/example/synthetic/1.2.3/synthetic-1.2.3.pom",
        "vendor/bundle/ruby/3.3.0/gems/synthetic/Gemfile.lock",
        "packages/app/.venv/lib/python3.12/site-packages/synthetic/requirements.txt",
        "packages/app/.tox/py312/Lib/site-packages/synthetic/requirements.txt",
        "packages/app/.nox/tests/lib/python3.12/site-packages/synthetic/requirements.txt",
        "packages/app/.m2/repository/example/synthetic/1.2.3/synthetic-1.2.3.pom",
        "packages/app/vendor/bundle/ruby/3.3.0/gems/synthetic/Gemfile.lock",
      ].map(spelling);
      const selected = [
        ".m2/source-project/pom.xml",
        "package-lock.json",
        "packages/app/package-lock.json",
        "packages/nox/requirements.txt",
        "packages/tox/requirements.txt",
        "repository/pom.xml",
        "vendor/source-project/package-lock.json",
      ].map(spelling);
      for (const path of [...installed, ...selected]) {
        await mkdir(join(repository, path, ".."), { recursive: true });
        await writeFile(
          join(repository, path),
          path.endsWith(".pom") || path.endsWith("pom.xml")
            ? "<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>synthetic</artifactId><version>1.2.3</version></project>"
            : path.endsWith("requirements.txt")
              ? "synthetic==1.2.3\n"
              : path.endsWith("Gemfile.lock")
                ? "GEM\n  remote: https://rubygems.org/\n  specs:\n    synthetic (1.2.3)\n"
                : npmLock(),
        );
      }
      if (mode === "Git tracked")
        await execFile("git", ["-C", checkout, "add", "."]);
      expect(
        (await discoverScaInputs(repository)).inputs.map((item) => item.path),
      ).toEqual(
        (mixedCase && process.platform !== "win32"
          ? [...installed, ...selected]
          : selected
        ).sort(),
      );
    },
  );
  test("scans every pnpm lockfile document", async () => {
    const { repository, output } = await setup();
    const content = ["synthetic-tool", "synthetic-lib"]
      .map((name) => `lockfileVersion: '9.0'\npackages:\n  ${name}@1.2.0: {}\n`)
      .join("---\n");
    await writeFile(join(repository, "pnpm-lock.yaml"), content);
    const calls: string[][] = [];
    const result = await runOsvScan(
      { repositoryPath: repository, outputDir: output },
      {
        executable: process.execPath,
        runProcess: async (_executable, argv) => {
          calls.push(argv);
          if (argv[0] === "--version")
            return { stdout: "2.6.0", stderr: "", exitCode: 0 };
          const raw = rawOutput("pnpm-lock.yaml");
          raw.results[0]!.packages.push({
            ...raw.results[0]!.packages[0]!,
            package: {
              name: "synthetic-tool",
              version: "1.2.0",
              ecosystem: "npm",
            },
          });
          return { stdout: JSON.stringify(raw), stderr: "", exitCode: 0 };
        },
      },
    );
    expect(result.status).toBe("completed");
    expect(result.coverage.inputs).toEqual([
      expect.objectContaining({
        path: "pnpm-lock.yaml",
        status: "scanned",
        sha256: createHash("sha256").update(content).digest("hex"),
      }),
    ]);
    expect(result.components.map((item) => item.name).sort()).toEqual([
      "synthetic-lib",
      "synthetic-tool",
    ]);
    expect(calls.filter((argv) => argv[0] === "scan")).toHaveLength(1);
  });
  test("retains local references from every pnpm document", async () => {
    const { repository } = await setup();
    await writeFile(
      join(repository, "pnpm-lock.yaml"),
      ["first", "second"]
        .map(
          (name) =>
            `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      ${name}:\n        version: link:../${name}\n`,
        )
        .join("---\n"),
    );
    const result = await discoverScaInputs(repository);
    expect(result.inputs[0]?.status).toBe("scanned");
    expect(
      result.localReferences.map(({ name, resolution }) => ({
        name,
        resolution,
      })),
    ).toEqual([
      { name: "first", resolution: "link:../first" },
      { name: "second", resolution: "link:../second" },
    ]);
  });
  test("filesystem inventory avoids repeated ancestor marker lookups", async () => {
    const name = "filesystem inventory avoids repeated ancestor marker lookups";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const { repository } = await setup();
    const directories = [
      "services",
      "services/api",
      "services/api/src",
      "services/web",
      "services/web/src",
      "packages",
      "packages/shared",
      "packages/shared/src",
    ];
    for (const directory of directories)
      await mkdir(join(repository, directory), { recursive: true });
    const paths = [
      "services/api/src/package-lock.json",
      "services/web/src/package-lock.json",
      "packages/shared/src/package-lock.json",
    ];
    for (const path of paths)
      await writeFile(join(repository, path), npmLock());
    const markers = new Set(
      directories.map((directory) => join(repository, directory, ".git")),
    );
    let markerLookups = 0;
    const original = filesystem.lstat;
    const checking = spyOn(filesystem, "lstat").mockImplementation((async (
      ...args: Parameters<typeof original>
    ) => {
      if (typeof args[0] === "string" && markers.has(args[0])) markerLookups++;
      return original(...args);
    }) as typeof original);
    try {
      const discovered = await discoverScaInputs(repository);
      expect(discovered.inputs.map((input) => input.path)).toEqual(
        paths.sort(),
      );
      expect(discovered.diagnostics).toEqual([]);
      expect(markerLookups).toBeLessThanOrEqual(directories.length);
    } finally {
      checking.mockRestore();
    }
  });
  test.each([
    ["", "unsupported", "Unsupported pnpm lockfile version: undefined."],
    [
      "lockfileVersion: '9.0'\n---\nlockfileVersion: '8.0'\n",
      "unsupported",
      "Unsupported pnpm lockfile version: 8.0.",
    ],
    [
      "lockfileVersion: '9.0'\n---\nlockfileVersion: [\n",
      "failed",
      "end with a ]",
    ],
  ] as const)(
    "retains pnpm rejection for %p",
    async (content, status, reason) => {
      const { repository } = await setup();
      await writeFile(join(repository, "pnpm-lock.yaml"), content);
      const result = await discoverScaInputs(repository);
      expect(result.inputs[0]?.status).toBe(status);
      expect(result.inputs[0]?.reason).toContain(reason);
    },
  );
  test.each([true, false])(
    "gitlink coverage remains incomplete when initialized: %p",
    async (initialized) => {
      const { repository, output } = await setup();
      await writeFile(join(repository, "package-lock.json"), npmLock());
      const nested = await initializedSubmodule(repository);
      if (!initialized) await rm(nested, { recursive: true });
      const result = await runOsvScan(
        { repositoryPath: repository, outputDir: output },
        {
          executable: process.execPath,
          runProcess: async (_executable, argv) =>
            argv[0] === "--version"
              ? { stdout: "2.6.0", stderr: "", exitCode: 0 }
              : {
                  stdout: JSON.stringify(rawOutput("package-lock.json")),
                  stderr: "",
                  exitCode: 0,
                },
        },
      );
      expect(result.status).toBe("partial");
      expect(result.coverage.status).toBe("partial");
      expect(result.coverage.inputs.map((item) => item.path)).toEqual([
        "package-lock.json",
      ]);
      expect(result.components).toHaveLength(1);
      expect(result.matches).toEqual([]);
      expect(result.diagnostics.join("\n")).toContain(
        "Git submodule vendor/library",
      );
      expect(result.coverage.limitations.join("\n")).toContain(
        "coverage is incomplete",
      );
    },
  );
  test.each([".", "selected"])(
    "untracked nested Git checkouts leave coverage incomplete for scope %s",
    async (scope) => {
      const { repository, output } = await setup();
      await execFile("git", ["init", "--quiet", repository]);
      const selected = join(repository, scope);
      const nested = join(selected, "nested-checkout");
      const ignored = join(selected, "ignored-checkout");
      await mkdir(nested, { recursive: true });
      await mkdir(ignored);
      await writeFile(join(selected, "package-lock.json"), npmLock());
      await writeFile(join(selected, ".gitignore"), "ignored-checkout/\n");
      for (const checkout of [nested, ignored]) {
        await execFile("git", ["init", "--quiet", checkout]);
        await writeFile(join(checkout, "package-lock.json"), npmLock());
      }
      const result = await runOsvScan(
        { repositoryPath: selected, outputDir: output },
        {
          executable: process.execPath,
          runProcess: async (_executable, argv) =>
            argv[0] === "--version"
              ? { stdout: "2.6.0", stderr: "", exitCode: 0 }
              : {
                  stdout: JSON.stringify(rawOutput("package-lock.json")),
                  stderr: "",
                  exitCode: 0,
                },
        },
      );
      expect(result.status).toBe("partial");
      expect(result.coverage.status).toBe("partial");
      expect(result.coverage.inputs.map((item) => item.path)).toEqual([
        "package-lock.json",
      ]);
      expect(result.components).toHaveLength(1);
      expect(result.diagnostics).toHaveLength(1);
      expect(result.diagnostics[0]).toContain(
        "Untracked nested Git repository nested-checkout",
      );
      expect(result.coverage.limitations.join("\n")).toContain(
        "coverage is incomplete",
      );
      const direct = await discoverScaInputs(nested);
      expect(direct.inputs.map((item) => item.path)).toEqual([
        "package-lock.json",
      ]);
      expect(direct.diagnostics).toEqual([]);
    },
  );
  test.each([
    "checkout",
    "worktree",
    "invalid-marker",
    "case-variant",
  ] as const)(
    "filesystem inventory respects nested %s boundaries",
    async (kind) => {
      const { root, repository, output } = await setup();
      const nested = join(repository, "container", "nested-checkout");
      await mkdir(join(repository, "ordinary", "deep"), { recursive: true });
      await mkdir(join(repository, "container"));
      const git = (cwd: string, args: string[]) =>
        execFile("git", [
          "-c",
          `core.hooksPath=${join(root, "empty-hooks")}`,
          "-c",
          "commit.gpgSign=false",
          "-c",
          "user.name=Synthetic",
          "-c",
          "user.email=synthetic@example.test",
          "-C",
          cwd,
          ...args,
        ]);
      let nestedRepository = true;
      if (kind === "worktree") {
        const owner = join(root, "worktree-owner");
        await mkdir(owner);
        await git(owner, ["init", "--quiet"]);
        await writeFile(join(owner, "README"), "Synthetic worktree fixture\n");
        await git(owner, ["add", "README"]);
        await git(owner, ["commit", "--quiet", "-m", "Synthetic fixture"]);
        await git(owner, [
          "worktree",
          "add",
          "--quiet",
          "--detach",
          nested,
          "HEAD",
        ]);
      } else {
        await mkdir(nested);
        if (kind === "invalid-marker")
          await writeFile(join(nested, ".git"), "invalid gitfile\n");
        else {
          await git(nested, ["init", "--quiet"]);
          if (kind === "case-variant") {
            await filesystem.rename(
              join(nested, ".git"),
              join(nested, "git-metadata"),
            );
            await filesystem.rename(
              join(nested, "git-metadata"),
              join(nested, ".GIT"),
            );
            nestedRepository = await git(nested, [
              "rev-parse",
              "--is-inside-work-tree",
            ]).then(
              ({ stdout }) => stdout.trim() === "true",
              () => false,
            );
          }
        }
      }
      for (const directory of [
        repository,
        join(repository, "ordinary"),
        join(repository, "ordinary", "deep"),
        nested,
      ])
        await writeFile(join(directory, "package-lock.json"), npmLock());
      const scanned: string[] = [];
      const result = await runOsvScan(
        { repositoryPath: repository, outputDir: output },
        {
          executable: process.execPath,
          runProcess: async (_executable, argv) => {
            if (argv[0] === "--version")
              return { stdout: "2.6.0", stderr: "", exitCode: 0 };
            const path = argv.at(-1)!;
            scanned.push(path);
            return {
              stdout: JSON.stringify(rawOutput(path)),
              stderr: "",
              exitCode: 0,
            };
          },
        },
      );
      expect(result.status).toBe(nestedRepository ? "partial" : "completed");
      expect(result.coverage.status).toBe(
        nestedRepository ? "partial" : "complete",
      );
      const expected = [
        "ordinary/deep/package-lock.json",
        "ordinary/package-lock.json",
        "package-lock.json",
      ];
      if (!nestedRepository)
        expected.unshift("container/nested-checkout/package-lock.json");
      expect(result.coverage.inputs.map((input) => input.path)).toEqual(
        expected,
      );
      expect(
        result.components.map((component) => component.sourcePath).sort(),
      ).toEqual(expected);
      expect(scanned).toHaveLength(expected.length);
      expect(scanned.some((path) => path.includes("nested-checkout"))).toBe(
        !nestedRepository,
      );
      expect(result.diagnostics).toHaveLength(nestedRepository ? 1 : 0);
      if (nestedRepository) {
        expect(result.diagnostics[0]).toContain(
          "Untracked nested Git repository container/nested-checkout",
        );
        expect(result.coverage.limitations.join("\n")).toContain(
          "coverage is incomplete",
        );
      }
      if (kind === "invalid-marker")
        await expect(discoverScaInputs(nested)).rejects.toThrow(
          "Could not determine the Git worktree root",
        );
      else {
        const direct = await discoverScaInputs(nested);
        expect(direct.inputs.map((input) => input.path)).toEqual([
          "package-lock.json",
        ]);
        expect(direct.diagnostics).toEqual([]);
      }
    },
  );
  test("selected directory inventory does not include sibling files or gitlinks", async () => {
    const { repository, output } = await setup();
    await initializedSubmodule(repository);
    const selected = join(repository, "packages", "selected");
    const sibling = join(repository, "packages", "sibling");
    await mkdir(selected, { recursive: true });
    await mkdir(sibling, { recursive: true });
    await writeFile(join(selected, "package-lock.json"), npmLock());
    await writeFile(
      join(sibling, "pnpm-lock.yaml"),
      "lockfileVersion: '9.0'\n",
    );
    await execFile("git", ["-C", repository, "add", "packages"]);
    const result = await runOsvScan(
      { repositoryPath: selected, outputDir: output },
      {
        executable: process.execPath,
        runProcess: async (_executable, argv) =>
          argv[0] === "--version"
            ? { stdout: "2.6.0", stderr: "", exitCode: 0 }
            : {
                stdout: JSON.stringify(rawOutput("package-lock.json")),
                stderr: "",
                exitCode: 0,
              },
      },
    );
    expect(result.status).toBe("completed");
    expect(result.coverage.inputs.map((item) => item.path)).toEqual([
      "package-lock.json",
    ]);
    expect(result.diagnostics).toEqual([]);
  });
  test("a gitlink added during matching invalidates captured inventory scope", async () => {
    const { repository, output } = await setup();
    await execFile("git", ["init", repository]);
    await writeFile(join(repository, "package-lock.json"), npmLock());
    const result = await runOsvScan(
      { repositoryPath: repository, outputDir: output },
      {
        executable: process.execPath,
        runProcess: async (_executable, argv) => {
          if (argv[0] === "--version")
            return { stdout: "2.6.0", stderr: "", exitCode: 0 };
          await initializedSubmodule(repository);
          return {
            stdout: JSON.stringify(rawOutput("package-lock.json")),
            stderr: "",
            exitCode: 0,
          };
        },
      },
    );
    expect(result.status).toBe("partial");
    expect(result.components).toHaveLength(1);
    expect(result.diagnostics.join("\n")).toContain("changed while matching");
  });
  test("prefers shrinkwrap without invoking a competing package-lock", async () => {
    const { repository } = await setup();
    await Promise.all([
      writeFile(join(repository, "package-lock.json"), npmLock()),
      writeFile(join(repository, "npm-shrinkwrap.json"), npmLock()),
    ]);
    const { inputs } = await discoverScaInputs(repository);
    expect(
      inputs.find((item) => item.path === "npm-shrinkwrap.json")?.status,
    ).toBe("scanned");
    expect(
      inputs.find((item) => item.path === "package-lock.json")?.status,
    ).toBe("excluded");
  });
  test("selects nested shrinkwrap consistently in non-Git directories", async () => {
    const { repository } = await setup();
    await mkdir(join(repository, "nested"));
    await Promise.all([
      writeFile(join(repository, "nested", "package-lock.json"), npmLock()),
      writeFile(join(repository, "nested", "npm-shrinkwrap.json"), npmLock()),
    ]);
    const { inputs } = await discoverScaInputs(repository);
    expect(inputs.map((item) => [item.path, item.status])).toEqual([
      ["nested/npm-shrinkwrap.json", "scanned"],
      ["nested/package-lock.json", "excluded"],
    ]);
  });
  test.each([false, true])(
    "scans working-tree replacements before and after staging, ancestor replaced=%p",
    async (replaceAncestor) => {
      const { repository, output } = await setup();
      await execFile("git", ["init", repository]);
      const oldDirectory = replaceAncestor
        ? join(repository, "old workspace")
        : repository;
      if (replaceAncestor) await mkdir(oldDirectory);
      const oldLock = join(oldDirectory, "package-lock.json");
      await writeFile(oldLock, npmLock());
      await execFile("git", ["-C", repository, "add", "."]);
      await rm(oldLock);
      if (replaceAncestor) {
        await rm(oldDirectory, { recursive: true });
        await writeFile(oldDirectory, "replacement file\n");
      }
      await writeFile(
        join(repository, "pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\npackages: {}\n",
      );
      const before = await discoverScaInputs(repository);
      expect(before.inputs.map((item) => [item.path, item.status])).toEqual([
        ["pnpm-lock.yaml", "scanned"],
      ]);
      const result = await runOsvScan(
        { repositoryPath: repository, outputDir: output },
        {
          executable: process.execPath,
          runProcess: async (_executable, argv) =>
            argv[0] === "--version"
              ? {
                  stdout: "osv-scanner version: 2.6.0",
                  stderr: "",
                  exitCode: 0,
                }
              : {
                  stdout: JSON.stringify(rawOutput("pnpm-lock.yaml")),
                  stderr: "",
                  exitCode: 0,
                },
        },
      );
      expect(result.status).toBe("completed");
      expect(result.coverage.inputs).toEqual(before.inputs);
      await execFile("git", ["-C", repository, "add", "--update"]);
      expect((await discoverScaInputs(repository)).inputs).toEqual(
        before.inputs,
      );
    },
  );
  test("reports unsupported versions and malformed lockfiles", async () => {
    const { repository } = await setup();
    await Promise.all([
      writeFile(join(repository, "package-lock.json"), npmLock(1)),
      writeFile(join(repository, "pnpm-lock.yaml"), "lockfileVersion: [\n"),
    ]);
    const { inputs } = await discoverScaInputs(repository);
    expect(inputs.map((item) => item.status)).toEqual([
      "unsupported",
      "failed",
    ]);
  });
  test("does not follow repository-controlled lockfile or directory links", async () => {
    const { repository, root } = await setup();
    const other = join(root, "other");
    await mkdir(other);
    await writeFile(join(other, "package-lock.json"), npmLock());
    await symlink(
      join(other, "package-lock.json"),
      join(repository, "package-lock.json"),
      "file",
    );
    await symlink(
      other,
      join(repository, "linked"),
      process.platform === "win32" ? "junction" : "dir",
    );
    const { inputs } = await discoverScaInputs(repository);
    expect(inputs).toHaveLength(1);
    expect(inputs[0]?.status).toBe("unsupported");
  });
  test("records OSV config digests and exclusions without overriding them", async () => {
    const { repository } = await setup();
    await writeFile(join(repository, "package-lock.json"), npmLock());
    await writeFile(
      join(repository, "osv-scanner.toml"),
      '[[PackageOverrides]]\nname="synthetic-lib"\nignore=true\n',
    );
    const found = await discoverScaInputs(repository);
    expect(found.configFiles[0]?.path).toBe("osv-scanner.toml");
    expect(found.configFiles[0]?.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(
      found.limitations.some((line) => line.includes("suppressed counts")),
    ).toBe(true);
  });
  test.each([0, 130])(
    "retains all lockfile evidence after malformed nested configuration with exit %d",
    async (exitCode) => {
      const { repository, output } = await setup();
      await mkdir(join(repository, "nested"));
      await Promise.all([
        writeFile(join(repository, "package-lock.json"), npmLock()),
        writeFile(join(repository, "nested", "package-lock.json"), npmLock()),
        writeFile(
          join(repository, "nested", "osv-scanner.toml"),
          "IgnoredVulns = [",
        ),
      ]);
      const result = await runOsvScan(
        { repositoryPath: repository, outputDir: output },
        {
          executable: process.execPath,
          runProcess: async (_executable, argv) =>
            argv[0] === "--version"
              ? { stdout: "2.6.0", stderr: "", exitCode: 0 }
              : {
                  stdout: JSON.stringify(
                    rawOutput(argv.at(-1)!, [advisory("A")]),
                  ),
                  stderr: "",
                  exitCode,
                },
        },
      );
      expect(result.status).toBe("partial");
      expect(result.matches).toHaveLength(2);
      expect(result.coverage.inputs).toHaveLength(2);
      expect(result.coverage.configFiles[0]?.path).toBe(
        "nested/osv-scanner.toml",
      );
      expect(result.coverage.configFiles[0]?.sha256).toMatch(/^[a-f0-9]{64}$/u);
      expect(
        result.diagnostics.some((line) =>
          line.includes(
            "Unable to parse OSV configuration nested/osv-scanner.toml",
          ),
        ),
      ).toBe(true);
      expect(
        JSON.parse(await readFile(result.scanner.rawOutputPath, "utf8"))
          .results,
      ).toHaveLength(2);
      expect(result.scanner.invocations).toHaveLength(2);
      for (const invocation of result.scanner.invocations!)
        expect(await readFile(invocation.rawOutputPath, "utf8")).toBe(
          JSON.stringify(rawOutput(invocation.argv.at(-1)!, [advisory("A")])),
        );
    },
  );
  test.each(["packageoverrides", "PACKAGEOVERRIDES"])(
    "honors case-insensitive OSV %s and Ignore configuration",
    async (key) => {
      const result = await scanFixture(
        {
          stdout: '{"results":[]}',
          stderr:
            "Package npm/synthetic-lib/1.2.0 has been filtered out because: synthetic exclusion",
          exitCode: 0,
        },
        {
          "osv-scanner.toml": `[[${key}]]\nname="synthetic-lib"\nIgnore=true\n`,
        },
      );
      expect(result.status).toBe("completed");
      expect(result.coverage.inputs[0]?.status).toBe("scanned");
      expect(
        result.coverage.limitations.some((line) =>
          line.includes("suppressed counts"),
        ),
      ).toBe(true);
    },
  );
  test.each(["link", "directory"])(
    "persists discovered inputs when an unsafe config %s prevents scanning",
    async (shape) => {
      const { root, repository, output } = await setup();
      const content = npmLock();
      await mkdir(join(repository, "nested"));
      for (const path of ["package-lock.json", "nested/package-lock.json"])
        await writeFile(join(repository, path), content);
      await writeFile(join(repository, "osv-scanner.toml"), "");
      const unsafeConfig = join(repository, "nested", "osv-scanner.toml");
      if (shape === "link") {
        const outside = join(root, "external.toml");
        await writeFile(outside, "");
        await symlink(outside, unsafeConfig);
      } else await mkdir(unsafeConfig);
      let scannerCalls = 0;
      const progress: DependencyScanProgress[] = [];
      const result = await runOsvScan(
        {
          repositoryPath: repository,
          outputDir: output,
          onProgress: (event) => {
            progress.push(event);
          },
        },
        {
          executable: process.execPath,
          runProcess: async () => {
            scannerCalls += 1;
            throw new Error("Unsafe configuration must prevent OSV invocation");
          },
        },
      );
      await saveDependencyScan(
        dependencyScanResult(
          result,
          { path: repository, revision: null, dirty: null },
          output,
        ),
      );
      const saved = JSON.parse(
        await readFile(join(output, "sca-result.json"), "utf8"),
      );
      const reason = `OSV configuration must be a regular file within the selected repository: ${unsafeConfig}`;
      expect(scannerCalls).toBe(0);
      expect(saved.status).toBe("failed");
      expect(saved.coverage.status).toBe("failed");
      expect(saved.coverage.inputs).toEqual(
        ["nested/package-lock.json", "package-lock.json"].map((path) => ({
          path,
          sha256: createHash("sha256").update(content).digest("hex"),
          format: "npm",
          status: "failed",
          reason,
        })),
      );
      expect(saved.coverage.configFiles).toEqual([
        {
          path: "osv-scanner.toml",
          sha256: createHash("sha256").update("").digest("hex"),
        },
      ]);
      expect(saved.diagnostics).toEqual([reason]);
      expect(saved.scanner.invocations).toEqual([]);
      expect(saved.components).toEqual([]);
      expect(saved.coverage.limitations.length).toBeGreaterThan(0);
      expect(progress.at(-1)).toEqual({
        phase: "matching",
        inputsTotal: 2,
        inputsProcessed: 0,
        inputsFailed: 2,
        currentInput: null,
        components: 0,
        matches: 0,
      });
    },
  );

  test("rejects a config link outside the repository", async () => {
    const { repository, root } = await setup();
    await writeFile(join(repository, "package-lock.json"), npmLock());
    const external = join(root, "external.toml");
    await writeFile(external, "");
    await symlink(external, join(repository, "osv-scanner.toml"), "file");
    await expect(discoverScaInputs(repository)).rejects.toThrow(
      "OSV configuration must be a regular file",
    );
  });
  test("ignores root configuration when only nested sources are selected", async () => {
    const { repository } = await setup();
    await mkdir(join(repository, "nested"));
    await writeFile(join(repository, "nested", "package-lock.json"), npmLock());
    await writeFile(join(repository, "osv-scanner.toml"), "invalid=[");
    const found = await discoverScaInputs(repository);
    expect(found.inputs[0]?.status).toBe("scanned");
    expect(found.configFiles).toEqual([]);
  });
  test("does not inherit root exclusions to explain missing nested inventory", async () => {
    const result = await scanFixture(
      {
        stdout: JSON.stringify(rawOutput("package-lock.json")),
        stderr: "",
        exitCode: 0,
      },
      {
        "nested/package-lock.json": npmLock(),
        "osv-scanner.toml":
          '[[PackageOverrides]]\nname="other-lib"\nignore=true\n',
      },
    );
    expect(result.status).toBe("partial");
    expect(result.coverage.status).toBe("partial");
    expect(
      result.diagnostics.some((line) =>
        line.includes("nested/package-lock.json"),
      ),
    ).toBe(true);
  });
  test("uses Git's tracked and untracked scope, respecting ignored files", async () => {
    const { repository } = await setup();
    await execFile("git", ["init", repository]);
    await writeFile(
      join(repository, ".gitignore"),
      "ignored/\nnpm-shrinkwrap.json\n",
    );
    await mkdir(join(repository, "ignored"));
    await Promise.all([
      writeFile(join(repository, "package-lock.json"), npmLock()),
      writeFile(join(repository, "npm-shrinkwrap.json"), npmLock()),
      writeFile(
        join(repository, "ignored", "pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n",
      ),
    ]);
    const { inputs } = await discoverScaInputs(repository);
    expect(inputs).toHaveLength(1);
    expect(inputs[0]?.status).toBe("unsupported");
    expect(inputs[0]?.reason).toContain("outside the selected file scope");
  });
});

describe("SCA OSV normalization", () => {
  test("retains full advisory records, sources, dependency groups and relevant fixed versions", () => {
    const vulnerability = {
      ...advisory("SYNTHETIC-1", ["CVE-2099-10001"]),
      future_field: { preserved: true },
    };
    vulnerability.affected.push({
      package: { name: "different-lib", ecosystem: "npm" },
      ranges: [
        { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "9.9.9" }] },
      ],
    });
    const normalized = normalizeOsvOutput(
      rawOutput("/repo/package-lock.json", [vulnerability]),
      { repositoryPath: "/repo", inputs: [input()] },
    );
    expect(normalized.components[0]).toMatchObject({
      name: "synthetic-lib",
      sourcePath: "package-lock.json",
      version: "1.2.0",
      dependencyGroups: ["dev"],
    });
    expect(normalized.matches[0]).toMatchObject({
      advisoryIds: ["SYNTHETIC-1"],
      aliases: ["CVE-2099-10001", "SYNTHETIC-1"],
      fixedVersions: ["1.3.0"],
      sourceAdvisories: [vulnerability],
    });
  });
  test("groups intersecting advisory aliases transitively without losing unrelated records", () => {
    const raw = rawOutput("package-lock.json", [
      advisory("A", ["X"]),
      advisory("B", ["Y"]),
      advisory("C", ["X", "Y"]),
      advisory("D"),
    ]);
    const normalized = normalizeOsvOutput(raw, {
      repositoryPath: "/repo",
      inputs: [input()],
    });
    expect(normalized.matches).toHaveLength(2);
    expect(normalized.matches.map((match) => match.advisoryIds)).toEqual([
      ["A", "B", "C"],
      ["D"],
    ]);
  });
  test.each([
    ["A", "B", "C"],
    ["B", "A", "C"],
    ["C", "A", "B"],
  ])(
    "keeps the maximum severity when aliases bridge groups: %p",
    (...order) => {
      const advisories = {
        A: advisory("A", ["X"]),
        B: advisory("B", ["Y"]),
        C: advisory("C", ["X", "Y"]),
      };
      const raw = rawOutput(
        "package-lock.json",
        order.map((id) => advisories[id as keyof typeof advisories]),
      );
      Object.assign(raw.results[0]!.packages[0]!, {
        groups: [
          { ids: ["A"], max_severity: "2.0" },
          { ids: ["B"], max_severity: "9.8" },
          { ids: ["C"], max_severity: "5.0" },
        ],
      });
      const normalized = normalizeOsvOutput(raw, {
        repositoryPath: "/repo",
        inputs: [input()],
      });
      expect(normalized.matches).toHaveLength(1);
      expect(normalized.matches[0]).toMatchObject({
        advisoryIds: ["A", "B", "C"],
        severity: "9.8",
      });
    },
  );
  test.each(["2.0", null])(
    "merges duplicate match metadata in either order with initial severity %p",
    (severity) => {
      const first = advisory("A", ["B"]);
      const second = advisory("B", ["A"]);
      second.modified = "2026-02-01T00:00:00Z";
      second.affected[0]!.ranges[0]!.events.push({ fixed: "1.4.0" });
      const packages = [first, second].map((vulnerability, index) => ({
        ...rawOutput("package-lock.json", [vulnerability]).results[0]!
          .packages[0]!,
        groups:
          index === 0 && severity === null
            ? []
            : [
                {
                  ids: [vulnerability.id],
                  max_severity: index === 0 ? severity : "9.8",
                },
              ],
      }));
      for (const ordered of [packages, [...packages].reverse()]) {
        const raw = rawOutput("package-lock.json");
        raw.results[0]!.packages = ordered;
        const normalized = normalizeOsvOutput(raw, {
          repositoryPath: "/repo",
          inputs: [input()],
        });
        expect(normalized.components).toHaveLength(1);
        expect(normalized.matches).toHaveLength(1);
        expect(normalized.matches[0]).toMatchObject({
          advisoryIds: ["A", "B"],
          aliases: ["A", "B"],
          severity: "9.8",
          fixedVersions: ["1.3.0", "1.4.0"],
          advisoryModifiedAt: ["2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"],
          sourceAdvisories: ordered.flatMap((item) => item.vulnerabilities),
        });
      }
    },
  );
  test("uses scanner group aliases and severity and keeps unavailable fixes empty", () => {
    const raw = rawOutput("package-lock.json", [
      { id: "A" },
      { id: "B", withdrawn: "2026-01-01T00:00:00Z" },
    ]);
    Object.assign(raw.results[0]!.packages[0]!, {
      groups: [{ ids: ["A", "B"], aliases: ["SHARED"], max_severity: "7.5" }],
    });
    const normalized = normalizeOsvOutput(raw, {
      repositoryPath: "/repo",
      inputs: [input()],
    });
    expect(normalized.matches[0]).toMatchObject({
      severity: "7.5",
      fixedVersions: [],
      advisoryIds: ["A", "B"],
    });
    expect(
      normalized.matches[0]?.sourceAdvisories[1]?.["withdrawn"],
    ).toBeDefined();
  });
  test("does not present Git commit fixes as package-version candidates", () => {
    const vulnerability = advisory("A");
    vulnerability.affected[0]!.ranges.push({
      type: "GIT",
      events: [{ introduced: "0" }, { fixed: "abcdef0123456789" }],
    });
    const normalized = normalizeOsvOutput(
      rawOutput("package-lock.json", [vulnerability]),
      { repositoryPath: "/repo", inputs: [input()] },
    );
    expect(normalized.matches[0]?.fixedVersions).toEqual(["1.3.0"]);
    expect(normalized.matches[0]?.sourceAdvisories).toEqual([vulnerability]);
  });
  test("retains unresolved package identities as unknown, not clean", () => {
    const raw = rawOutput("package-lock.json");
    Object.assign(raw.results[0]!.packages[0]!.package, {
      version: "",
      ecosystem: "",
    });
    const normalized = normalizeOsvOutput(raw, {
      repositoryPath: "/repo",
      inputs: [input()],
    });
    expect(normalized.unresolvedPackages).toBe(1);
    expect(normalized.components[0]).toMatchObject({
      version: null,
      ecosystem: null,
    });
  });
  test("distinguishes installed versions and retains packages without matches", () => {
    const raw = rawOutput("package-lock.json");
    raw.results[0]!.packages.push({
      package: { name: "synthetic-lib", version: "2.0.0", ecosystem: "npm" },
      dependency_groups: ["optional"],
      vulnerabilities: [],
    });
    const normalized = normalizeOsvOutput(raw, {
      repositoryPath: "/repo",
      inputs: [input()],
    });
    expect(normalized.components).toHaveLength(2);
    expect(normalized.components[0]?.id).not.toBe(normalized.components[1]?.id);
    expect(normalized.matches).toEqual([]);
  });
  test("component and match identities survive relocation and Windows source paths", () => {
    const first = normalizeOsvOutput(
      rawOutput("/repo/package-lock.json", [advisory("A")]),
      { repositoryPath: "/repo", inputs: [input()] },
    );
    const second = normalizeOsvOutput(
      rawOutput("C:\\work with spaces\\package-lock.json", [advisory("A")]),
      { repositoryPath: "C:\\work with spaces", inputs: [input()] },
    );
    expect(second).toEqual(first);
  });
  test("preserves literal backslashes in POSIX scanner source identities", () => {
    const source = "nested\\folder/package-lock.json";
    const normalized = normalizeOsvOutput(
      rawOutput(`/repo/${source}`, [advisory("A")]),
      {
        repositoryPath: "/repo",
        inputs: [input(source)],
      },
    );
    expect(normalized.components[0]?.sourcePath).toBe(source);
    expect(normalized.matches).toHaveLength(1);
    expect(normalized.diagnostics).toEqual([]);
  });
  test.each(["file:../local-lib", "link:../linked-lib"])(
    "retains %s as an unresolved npm identity",
    (version) => {
      const raw = rawOutput("package-lock.json");
      raw.results[0]!.packages[0]!.package.version = version;
      const normalized = normalizeOsvOutput(raw, {
        repositoryPath: "/repo",
        inputs: [input()],
      });
      expect(normalized.unresolvedPackages).toBe(1);
      expect(normalized.components[0]?.version).toBe(version);
    },
  );
  test("reports malformed fields and unknown sources while preserving valid matches", () => {
    const raw = rawOutput("package-lock.json", [
      { summary: "missing id" },
      advisory("A"),
    ]);
    raw.results.push({
      source: { path: "../other/package-lock.json", type: "lockfile" },
      packages: [],
    });
    const normalized = normalizeOsvOutput(raw, {
      repositoryPath: "/repo",
      inputs: [input()],
    });
    expect(normalized.matches).toHaveLength(1);
    expect(normalized.diagnostics).toHaveLength(2);
    expect(() =>
      normalizeOsvOutput({}, { repositoryPath: "/repo", inputs: [] }),
    ).toThrow("results array");
  });
});

describe("SCA scanner execution", () => {
  test.each([0, 1])(
    "accepts successful OSV exit %d and retains raw artifacts",
    async (exitCode) => {
      const output = JSON.stringify(
        rawOutput("package-lock.json", exitCode === 1 ? [advisory("A")] : []),
      );
      const result = await scanFixture({
        stdout: output,
        stderr: "Scanned file and found 1 package\n",
        exitCode,
      });
      expect(result.status).toBe("completed");
      expect(result.scanner.version).toContain("2.6.0");
      expect(await readFile(result.scanner.rawOutputPath, "utf8")).toBe(output);
      expect(result.matches.length).toBe(exitCode);
    },
  );
  test.each([
    "unchanged",
    "lockfile",
    "lockfile-add",
    "lockfile-delete",
    "config",
    "config-add",
    "config-delete",
  ] as const)(
    "preserves scanner evidence and verifies post-scan provenance for %s inputs",
    async (change) => {
      const { repository, output } = await setup();
      const lockfile = join(repository, "package-lock.json");
      const config = join(repository, "osv-scanner.toml");
      await writeFile(lockfile, npmLock());
      if (change !== "config-add") await writeFile(config, "");
      const before = await discoverScaInputs(repository);
      const raw = JSON.stringify(
        rawOutput("package-lock.json", [advisory("A")]),
      );
      const result = await runOsvScan(
        { repositoryPath: repository, outputDir: output },
        {
          executable: process.execPath,
          runProcess: async (_executable, argv) => {
            if (argv[0] === "--version")
              return {
                stdout: "osv-scanner version: 2.6.0",
                stderr: "",
                exitCode: 0,
              };
            if (change === "lockfile") await writeFile(lockfile, npmLock(2));
            if (change === "lockfile-add")
              await writeFile(
                join(repository, "npm-shrinkwrap.json"),
                npmLock(),
              );
            if (change === "lockfile-delete") await rm(lockfile);
            if (change === "config" || change === "config-add")
              await writeFile(config, '[[IgnoredVulns]]\nid="A"\n');
            if (change === "config-delete") await rm(config);
            return { stdout: raw, stderr: "", exitCode: 1 };
          },
        },
      );
      expect(result.status).toBe(
        change === "unchanged" ? "completed" : "partial",
      );
      expect(result.coverage.status).toBe(
        change === "unchanged" ? "complete" : "partial",
      );
      expect(result.matches).toHaveLength(1);
      expect(result.coverage.inputs[0]?.sha256).toBe(before.inputs[0]?.sha256);
      expect(result.coverage.configFiles).toEqual(before.configFiles);
      expect(
        result.diagnostics.some((line) =>
          line.includes("changed while matching"),
        ),
      ).toBe(change !== "unchanged");
      expect(await readFile(result.scanner.rawOutputPath, "utf8")).toBe(raw);
    },
  );
  test.each([127, 128, 130, null])(
    "never reports clean for error/no-package exit %p",
    async (exitCode) => {
      const result = await scanFixture({
        stdout:
          exitCode === 128
            ? ""
            : JSON.stringify(rawOutput("package-lock.json")),
        stderr: "diagnostic",
        exitCode,
      });
      expect(result.status).not.toBe("completed");
      expect(result.diagnostics.length).toBeGreaterThan(0);
    },
  );
  test("detects real pinned matcher failure diagnostics even with exit 0 and valid inventory", async () => {
    const stderr =
      "could not load db for npm ecosystem: unable to fetch OSV database: no offline version of the OSV database is available\nError during extraction: (extracting as vulnmatch/osvlocal) unable to fetch OSV database: no offline version of the OSV database is available\n";
    const result = await scanFixture({
      stdout: JSON.stringify(rawOutput("package-lock.json")),
      stderr,
      exitCode: 0,
    });
    expect(result.status).toBe("partial");
    expect(result.components).toHaveLength(1);
    expect(result.coverage.inputs[0]?.status).toBe("failed");
    expect(
      osvErrorDiagnostics("Starting filesystem walk\nEnd status: 0 dirs\n"),
    ).toEqual([]);
    expect(
      osvErrorDiagnostics(
        "Error during extraction: (extracting as vulnmatch/osvdev) API unavailable",
      ),
    ).toHaveLength(1);
  });
  test("keeps matching partial when OSV skips a short commit query", async () => {
    const stderr =
      'Skipping synthetic-lib: short commit hash "abc1234" cannot be queried; OSV API requires a full 40-character SHA.\n';
    const result = await scanFixture({
      stdout: JSON.stringify(rawOutput("package-lock.json")),
      stderr,
      exitCode: 0,
    });
    expect(result.status).toBe("partial");
    expect(result.coverage.status).toBe("partial");
    expect(result.coverage.inputs[0]?.status).toBe("failed");
    expect(result.components).toHaveLength(1);
    expect(result.matches).toHaveLength(0);
    expect(result.diagnostics).toContain(stderr.trim());
  });
  test("retains matches when another scanner stage fails", async () => {
    const result = await scanFixture({
      stdout: JSON.stringify(rawOutput("package-lock.json", [advisory("A")])),
      stderr:
        "Error during extraction: (extracting as vulnmatch/osvdev) API unavailable",
      exitCode: 127,
    });
    expect(result.status).toBe("partial");
    expect(result.matches).toHaveLength(1);
  });
  test.each(["", "not JSON", '{"results":{}}'])(
    "reports invalid JSON contract %s",
    async (stdout) => {
      const result = await scanFixture({ stdout, stderr: "", exitCode: 0 });
      expect(result.status).toBe("failed");
    },
  );
  test("does not count unsupported Git identities as complete npm registry coverage", async () => {
    const raw = rawOutput("package-lock.json");
    Object.assign(raw.results[0]!.packages[0]!.package, {
      ecosystem: "GIT",
      name: "https://example.test/synthetic/lib",
      commit: "a".repeat(40),
    });
    const result = await scanFixture({
      stdout: JSON.stringify(raw),
      stderr: "",
      exitCode: 0,
    });
    expect(result.status).toBe("partial");
    expect(result.coverage.unresolvedPackages).toBe(1);
    expect(
      result.diagnostics.some((line) =>
        line.includes("unsupported ecosystem GIT"),
      ),
    ).toBe(true);
  });
  test.each([2, 3])(
    "keeps npm v%d local tarball provenance incomplete despite a registry-shaped scanner tuple",
    async (version) => {
      const result = await scanFixture(
        {
          stdout: JSON.stringify(
            rawOutput("package-lock.json", [advisory("A")]),
          ),
          stderr: "",
          exitCode: 1,
        },
        {
          "package-lock.json": JSON.stringify({
            lockfileVersion: version,
            packages: {
              "": { name: "synthetic-app", version: "1.0.0" },
              "node_modules/synthetic-lib": {
                version: "1.2.0",
                resolved: "file:../local-lib.tgz",
              },
            },
          }),
        },
      );
      expect(result.status).toBe("partial");
      expect(result.coverage.unresolvedPackages).toBe(1);
      expect(result.components[0]?.version).toBe("1.2.0");
      expect(result.matches).toHaveLength(1);
      expect(
        result.coverage.limitations.some((line) =>
          line.includes("file:../local-lib.tgz"),
        ),
      ).toBe(true);
    },
  );
  test.each(
    [
      ...[2, 3].flatMap((lockfileVersion) =>
        ["https", "HTTPS", "HtTpS"].map((scheme) => ({
          path: "package-lock.json",
          content: JSON.stringify({
            lockfileVersion,
            packages: {
              "": { dependencies: { "synthetic-lib": "^1.2.0" } },
              "node_modules/synthetic-lib": {
                version: "1.2.0",
                resolved: `${scheme}://registry.example.test/synthetic-lib.tgz`,
              },
            },
          }),
        })),
      ),
      {
        path: "pnpm-lock.yaml",
        content: `lockfileVersion: '9.0'
packages:
  synthetic-lib@1.2.0:
    resolution: {tarball: https://registry.example.test/synthetic-lib.tgz}
`,
      },
      {
        path: "Pipfile.lock",
        content: JSON.stringify({
          _meta: {
            sources: [
              { name: "alternate", url: "https://index.example.test/simple" },
            ],
          },
          default: {
            "synthetic-lib": { version: "==1.2.0", index: "alternate" },
          },
        }),
      },
      {
        path: "uv.lock",
        content:
          '[[package]]\nname="synthetic-lib"\nversion="1.2.0"\nsource={registry="https://index.example.test/simple"}',
      },
      {
        path: "poetry.lock",
        content:
          '[[package]]\nname="synthetic-lib"\nversion="1.2.0"\nsource={type="legacy",url="https://index.example.test/simple"}',
      },
      ...[
        ["https://gems.example.test"],
        ["https://rubygems.org/", "https://gems.example.test"],
      ].map((remotes) => ({
        path: "Gemfile.lock",
        content: `GEM\n${remotes.map((remote) => `  remote: ${remote}\n`).join("")}  specs:\n    synthetic-lib (1.2.0)\n`,
      })),
    ].flatMap((input) =>
      [false, true].map((matched) => ({
        ...input,
        matched,
        ecosystem: ["package-lock.json", "pnpm-lock.yaml"].includes(input.path)
          ? "npm"
          : input.path === "Gemfile.lock"
            ? "RubyGems"
            : "PyPI",
      })),
    ),
  )(
    "keeps $path alternate-registry coverage incomplete with advisory matches: $matched (case %#)",
    async ({ path, content, matched, ecosystem }) => {
      const { repository, output } = await setup();
      await writeFile(join(repository, path), content);
      const vulnerability = advisory("SYNTHETIC-REGISTRY-1");
      vulnerability.affected[0]!.package.ecosystem = ecosystem;
      const raw = rawOutput(path, matched ? [vulnerability] : []);
      raw.results[0]!.packages[0]!.package.ecosystem = ecosystem;
      const result = await runOsvScan(
        { repositoryPath: repository, outputDir: output },
        {
          executable: process.execPath,
          runProcess: async (_exe, argv) => ({
            stdout: argv[0] === "--version" ? "2.6.0" : JSON.stringify(raw),
            stderr: "",
            exitCode: argv[0] === "--version" || !matched ? 0 : 1,
          }),
        },
      );
      expect(result.status).toBe("partial");
      expect(result.coverage.unresolvedPackages).toBe(1);
      expect(result.coverage.limitations.join("\n")).toContain(
        ecosystem === "npm"
          ? "registry.example.test"
          : ecosystem === "RubyGems"
            ? "https://gems.example.test"
            : "https://index.example.test/simple",
      );
      expect(result.matches).toHaveLength(matched ? 1 : 0);
    },
  );
  test.each(
    [
      "https://pypi.org:443/simple",
      "http://pypi.python.org:80/simple/",
    ].flatMap((url) => [
      {
        path: "uv.lock",
        content: `version=1\n[[package]]\nname="synthetic-lib"\nversion="1.2.0"\nsource={registry="${url}"}\n`,
      },
      {
        path: "poetry.lock",
        content: `[[package]]\nname="synthetic-lib"\nversion="1.2.0"\nsource={type="legacy",url="${url}"}\n`,
      },
      {
        path: "Pipfile.lock",
        content: JSON.stringify({
          _meta: { sources: [{ name: "public", url }] },
          default: {
            "synthetic-lib": { version: "==1.2.0", index: "public" },
          },
        }),
      },
    ]),
  )(
    "keeps $path public default-port coverage complete (case %#)",
    async ({ path, content }) => {
      const { repository, output } = await setup();
      await writeFile(join(repository, path), content);
      const raw = rawOutput(path, []);
      raw.results[0]!.packages[0]!.package.ecosystem = "PyPI";
      const result = await runOsvScan(
        { repositoryPath: repository, outputDir: output },
        {
          executable: process.execPath,
          runProcess: async (_exe, argv) => ({
            stdout: argv[0] === "--version" ? "2.6.0" : JSON.stringify(raw),
            stderr: "",
            exitCode: 0,
          }),
        },
      );
      expect(result.status).toBe("completed");
      expect(result.coverage.status).toBe("complete");
      expect(result.coverage.unresolvedPackages).toBe(0);
      expect(result.components).toHaveLength(1);
      expect(result.matches).toEqual([]);
    },
  );
  test.each(
    ["https://rubygems.org:443/", "http://rubygems.org:80"].flatMap((remote) =>
      [false, true].map((matched) => ({ remote, matched })),
    ),
  )(
    "keeps RubyGems default-port $remote coverage complete with advisory matches: $matched",
    async ({ remote, matched }) => {
      const { repository, output } = await setup();
      await writeFile(
        join(repository, "Gemfile.lock"),
        `GEM\n  remote: ${remote}\n  specs:\n    synthetic-lib (1.2.0)\n`,
      );
      const vulnerability = advisory("SYNTHETIC-RUBYGEMS-1");
      vulnerability.affected[0]!.package.ecosystem = "RubyGems";
      const raw = rawOutput("Gemfile.lock", matched ? [vulnerability] : []);
      raw.results[0]!.packages[0]!.package.ecosystem = "RubyGems";
      const result = await runOsvScan(
        { repositoryPath: repository, outputDir: output },
        {
          executable: process.execPath,
          runProcess: async (_exe, argv) => ({
            stdout: argv[0] === "--version" ? "2.6.0" : JSON.stringify(raw),
            stderr: "",
            exitCode: argv[0] === "--version" || !matched ? 0 : 1,
          }),
        },
      );
      expect(result.status).toBe("completed");
      expect(result.coverage.status).toBe("complete");
      expect(result.coverage.unresolvedPackages).toBe(0);
      expect(result.components).toHaveLength(1);
      expect(result.matches).toHaveLength(matched ? 1 : 0);
    },
  );
  test.each([false, true])(
    "keeps relative Composer archive coverage incomplete with advisory matches: %p",
    async (matched) => {
      const { repository, output } = await setup();
      await writeFile(
        join(repository, "composer.lock"),
        JSON.stringify({
          packages: [
            {
              name: "synthetic-lib",
              version: "1.2.0",
              dist: { type: "zip", url: "archives/library.zip" },
            },
          ],
        }),
      );
      const vulnerability = advisory("SYNTHETIC-ARCHIVE-1");
      vulnerability.affected[0]!.package.ecosystem = "Packagist";
      const raw = rawOutput("composer.lock", matched ? [vulnerability] : []);
      raw.results[0]!.packages[0]!.package.ecosystem = "Packagist";
      const result = await runOsvScan(
        { repositoryPath: repository, outputDir: output },
        {
          executable: process.execPath,
          runProcess: async (_exe, argv) => ({
            stdout: argv[0] === "--version" ? "2.6.0" : JSON.stringify(raw),
            stderr: "",
            exitCode: argv[0] === "--version" || !matched ? 0 : 1,
          }),
        },
      );
      expect(result.status).toBe("partial");
      expect(result.coverage.unresolvedPackages).toBe(1);
      expect(result.coverage.limitations.join("\n")).toContain(
        "archives/library.zip",
      );
      expect(result.matches).toHaveLength(matched ? 1 : 0);
    },
  );
  test.each([2, 3, "pnpm9"] as const)(
    "classifies registry tarball authorities in lockfile %p",
    async (format) => {
      for (const [resolved, publicRegistry] of [
        ["https://registry.npmjs.org/synthetic.tgz", true],
        ["https://registry.npmjs.org:443/synthetic.tgz", true],
        ["http://registry.npmjs.org:80/synthetic.tgz", true],
        ["HTTPS://REGISTRY.NPMJS.ORG:0443/@synthetic/lib/-/lib.tgz", true],
        ["https://registry.npmjs.org:8443/synthetic.tgz", false],
        ["https://registry.npmjs.org:80/synthetic.tgz", false],
        ["http://registry.npmjs.org:443/synthetic.tgz", false],
        ["https://registry.example.test:443/synthetic.tgz", false],
        [
          "https://synthetic:password@registry.npmjs.org:443/synthetic.tgz",
          false,
        ],
        ["https://registry.npmjs.org:443/synthetic.tgz?source=example", true],
        ["https://registry.npmjs.org:443/synthetic.tgz#example", true],
        ["https://registry.npmjs.org?source=example", false],
        ["https://registry.npmjs.org:443?source=example", false],
        ["https://registry%2enpmjs.org/synthetic.tgz", false],
      ] as const) {
        const path =
          format === "pnpm9" ? "pnpm-lock.yaml" : "package-lock.json";
        const { repository, output } = await setup();
        await writeFile(
          join(repository, path),
          JSON.stringify(
            format === "pnpm9"
              ? {
                  lockfileVersion: "9.0",
                  packages: {
                    "synthetic-lib@1.2.0": {
                      resolution: { tarball: resolved },
                    },
                  },
                }
              : {
                  lockfileVersion: format,
                  packages: {
                    "node_modules/synthetic-lib": {
                      version: "1.2.0",
                      resolved,
                    },
                  },
                },
          ),
        );
        const result = await runOsvScan(
          { repositoryPath: repository, outputDir: output },
          {
            executable: process.execPath,
            runProcess: async (_exe, argv) => ({
              stdout:
                argv[0] === "--version"
                  ? "2.6.0"
                  : JSON.stringify(rawOutput(path, [])),
              stderr: "",
              exitCode: 0,
            }),
          },
        );
        expect(result.status, resolved).toBe(
          publicRegistry ? "completed" : "partial",
        );
        expect(result.coverage.unresolvedPackages, resolved).toBe(
          publicRegistry ? 0 : 1,
        );
        expect(result.components).toHaveLength(1);
        if (!publicRegistry)
          expect(result.coverage.limitations.join("\n")).toContain(resolved);
      }
    },
  );
  test.each(
    ["dependencies", "devDependencies", "optionalDependencies"].flatMap(
      (group) =>
        [
          "https://registry.npmjs.org",
          "HTTPS://REGISTRY.NPMJS.ORG",
          "HtTpS://Registry.Npmjs.Org",
          "https://registry.npmjs.org:443",
          "http://registry.npmjs.org:80",
        ].map((origin) => ({ group, origin })),
    ),
  )(
    "preserves npm direct URL provenance from $origin in $group without changing registry tarballs",
    async ({ group, origin }) => {
      const resolved = `${origin}/synthetic-lib/-/synthetic-lib-1.2.0.tgz`;
      for (const direct of [false, true]) {
        const result = await scanFixture(
          {
            stdout: JSON.stringify(
              rawOutput("package-lock.json", [advisory("A")]),
            ),
            stderr: "",
            exitCode: 1,
          },
          {
            "package-lock.json": JSON.stringify({
              lockfileVersion: 3,
              packages: {
                "": {
                  [group]: { "synthetic-lib": direct ? resolved : "^1.2.0" },
                },
                "node_modules/synthetic-lib": { version: "1.2.0", resolved },
              },
            }),
          },
        );
        expect(result.status).toBe(direct ? "partial" : "completed");
        expect(result.coverage.unresolvedPackages).toBe(direct ? 1 : 0);
        expect(result.matches).toHaveLength(1);
      }
    },
  );
  test.each([2, 3])(
    "keeps npm v%p local Git provenance when OSV emits a registry tuple",
    async (lockfileVersion) => {
      const resolved = `git+file:///synthetic/local-repository#${"a".repeat(40)}`;
      for (const matched of [false, true]) {
        // OSV-Scanner 2.6.0 emits an npm tuple for this local Git locator.
        const result = await scanFixture(
          {
            stdout: JSON.stringify(
              rawOutput("package-lock.json", matched ? [advisory("A")] : []),
            ),
            stderr: "",
            exitCode: matched ? 1 : 0,
          },
          {
            "package-lock.json": JSON.stringify({
              lockfileVersion,
              packages: {
                "node_modules/synthetic-lib": { version: "1.2.0", resolved },
              },
            }),
          },
        );
        expect(result.status).toBe("partial");
        expect(result.coverage.status).toBe("partial");
        expect(result.coverage.unresolvedPackages).toBe(1);
        expect(result.coverage.limitations.join("\n")).toContain(resolved);
        expect(result.components[0]).toMatchObject({
          ecosystem: "npm",
          name: "synthetic-lib",
          version: "1.2.0",
        });
        expect(result.matches).toHaveLength(matched ? 1 : 0);
      }
    },
  );
  test.each([true, false])(
    "counts npm workspace links once when an unresolved tuple is emitted: %p",
    async (emitted) => {
      const raw = rawOutput("package-lock.json");
      if (emitted)
        raw.results[0]!.packages.push({
          package: { name: "linked-lib", version: "", ecosystem: "npm" },
          dependency_groups: [],
          vulnerabilities: [],
        });
      const result = await scanFixture(
        { stdout: JSON.stringify(raw), stderr: "", exitCode: 0 },
        {
          "package-lock.json": JSON.stringify({
            lockfileVersion: 3,
            packages: {
              "node_modules/synthetic-lib": { version: "1.2.0" },
              "node_modules/linked-lib": {
                resolved: "packages/linked-lib",
                link: true,
              },
              "packages/linked-lib": { name: "linked-lib", version: "1.0.0" },
            },
          }),
        },
      );
      expect(result.status).toBe("partial");
      expect(result.coverage.unresolvedPackages).toBe(1);
      expect(
        result.coverage.limitations.some((line) =>
          line.includes("linked-lib@packages/linked-lib"),
        ),
      ).toBe(true);
    },
  );
  test.each(
    [
      "https://registry.npmjs.org",
      "HTTPS://registry.npmjs.org",
      "HtTpS://registry.npmjs.org",
      "HTTP://registry.npmjs.org",
      "https://registry.npmjs.org:443",
      "http://registry.npmjs.org:80",
    ].flatMap((origin) =>
      ["bare", "named", "importer", "snapshot", "registry"].map((layout) => ({
        origin,
        layout,
      })),
    ),
  )(
    "preserves pnpm $origin URL provenance in $layout references",
    async ({ origin, layout }) => {
      const { repository, output } = await setup();
      const resolution = `${origin}/synthetic-lib/-/synthetic-lib-1.2.0.tgz`;
      const key =
        layout === "bare"
          ? resolution
          : layout === "named"
            ? `synthetic-lib@${resolution}`
            : "synthetic-lib@1.2.0";
      await writeFile(
        join(repository, "pnpm-lock.yaml"),
        JSON.stringify({
          lockfileVersion: "9.0",
          ...(layout === "importer"
            ? {
                importers: {
                  ".": {
                    dependencies: {
                      "direct-lib": {
                        specifier: resolution,
                        version: resolution,
                      },
                    },
                  },
                },
              }
            : {}),
          packages: {
            [key]: {
              name: "synthetic-lib",
              version: "1.2.0",
              resolution: { tarball: resolution },
            },
          },
          snapshots: {
            [key]:
              layout === "snapshot"
                ? { dependencies: { "direct-lib": resolution } }
                : {},
          },
        }),
      );
      const result = await runOsvScan(
        { repositoryPath: repository, outputDir: output },
        {
          executable: process.execPath,
          runProcess: async (_exe, argv) => ({
            stdout:
              argv[0] === "--version"
                ? "2.6.0"
                : JSON.stringify(rawOutput("pnpm-lock.yaml", [advisory("A")])),
            stderr: "",
            exitCode: argv[0] === "--version" ? 0 : 1,
          }),
        },
      );
      const direct = layout !== "registry";
      expect(result.status).toBe(direct ? "partial" : "completed");
      expect(result.coverage.unresolvedPackages).toBe(direct ? 1 : 0);
      if (direct)
        expect(result.coverage.limitations.join("\n")).toContain(resolution);
      expect(result.components).toHaveLength(1);
      expect(result.matches).toHaveLength(1);
    },
  );
  test.each([true, false])(
    "accounts for pnpm local and direct URL references when file tuples are emitted: %p",
    async (emitted) => {
      const raw = rawOutput("package-lock.json");
      const pnpm = rawOutput("pnpm-lock.yaml", [advisory("A")]);
      if (emitted)
        pnpm.results[0]!.packages.push({
          package: {
            name: "local-lib",
            version: "file:../local-lib",
            ecosystem: "npm",
          },
          dependency_groups: [],
          vulnerabilities: [],
        });
      raw.results.push(...pnpm.results);
      const result = await scanFixture(
        { stdout: JSON.stringify(raw), stderr: "", exitCode: 0 },
        {
          "pnpm-lock.yaml": `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      synthetic-lib: {specifier: '1.2.0', version: '1.2.0'}
      local-lib: {specifier: 'file:../local-lib', version: 'file:../local-lib'}
      url-lib: {specifier: 'https://example.invalid/url-lib.tgz', version: 'https://example.invalid/url-lib.tgz'}
    devDependencies:
      linked-lib: {specifier: 'link:../linked-lib', version: 'link:../linked-lib'}
packages:
  synthetic-lib@1.2.0: {resolution: {integrity: synthetic, tarball: https://registry.npmjs.org/synthetic-lib/-/synthetic-lib-1.2.0.tgz}}
  local-lib@file:../local-lib: {resolution: {directory: ../local-lib, type: directory}}
snapshots:
  synthetic-lib@1.2.0:
    dependencies:
      local-lib: 'file:../local-lib'
  local-lib@file:../local-lib: {}
`,
        },
      );
      expect(result.status).toBe("partial");
      expect(result.coverage.status).toBe("partial");
      expect(result.coverage.unresolvedPackages).toBe(3);
      expect(result.matches).toHaveLength(1);
      expect(
        result.coverage.limitations.some((line) =>
          line.includes("linked-lib@link:../linked-lib"),
        ),
      ).toBe(true);
    },
  );
  test("does not silently mark an omitted selected source as scanned", async () => {
    const result = await scanFixture(
      {
        stdout: JSON.stringify(rawOutput("package-lock.json")),
        stderr: "",
        exitCode: 0,
      },
      { "nested/package-lock.json": npmLock() },
    );
    expect(result.status).toBe("partial");
    expect(
      result.diagnostics.some((line) =>
        line.includes("nested/package-lock.json"),
      ),
    ).toBe(true);
  });
  test("does not let advisory-only exclusions explain missing package inventory", async () => {
    const result = await scanFixture(
      { stdout: '{"results":[]}', stderr: "", exitCode: 0 },
      { "osv-scanner.toml": '[[IgnoredVulns]]\nid="A"\n' },
    );
    expect(result.status).toBe("failed");
  });
  test("reports unresolved inventory as partial", async () => {
    const raw = rawOutput("package-lock.json");
    raw.results[0]!.packages[0]!.package.version = "";
    expect(
      (
        await scanFixture({
          stdout: JSON.stringify(raw),
          stderr: "",
          exitCode: 0,
        })
      ).status,
    ).toBe("partial");
  });
  test("does not invoke a scanner with no supported inputs", async () => {
    const { repository, output } = await setup();
    let called = false;
    const result = await runOsvScan(
      { repositoryPath: repository, outputDir: output },
      {
        runProcess: async () => {
          called = true;
          throw new Error("unexpected call");
        },
      },
    );
    expect(called).toBe(false);
    expect(result.status).toBe("failed");
  });
  test("reports missing executable without claiming a clean scan", async () => {
    const { repository, output, root } = await setup();
    await writeFile(join(repository, "package-lock.json"), npmLock());
    const result = await runOsvScan(
      { repositoryPath: repository, outputDir: output },
      { executable: join(root, "missing-scanner") },
    );
    expect(result.status).toBe("failed");
    expect(result.diagnostics.join(" ")).toContain("not installed");
  });
  test("preserves hashed inputs when discovery is cancelled between candidates", async () => {
    const name =
      "preserves hashed inputs when discovery is cancelled between candidates";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const { repository, output } = await setup();
    for (const directory of ["a", "b"]) {
      await mkdir(join(repository, directory));
      await writeFile(
        join(repository, directory, "package-lock.json"),
        npmLock(),
      );
    }
    const controller = new AbortController();
    const reason = new Error("requested stop after first input digest");
    const original = filesystem.lstat;
    const checking = spyOn(filesystem, "lstat").mockImplementation((async (
      ...args: Parameters<typeof original>
    ) => {
      try {
        return await original(...args);
      } finally {
        if (args[0] === join(repository, "a", "npm-shrinkwrap.json"))
          controller.abort(reason);
      }
    }) as typeof original);
    let calls = 0;
    let interruption: (Error & { osvResult: OsvScanResult }) | undefined;
    try {
      await runOsvScan(
        {
          repositoryPath: repository,
          outputDir: output,
          signal: controller.signal,
        },
        {
          executable: process.execPath,
          runProcess: async () => {
            calls += 1;
            throw new Error("scanner must not start after cancellation");
          },
        },
      );
    } catch (error) {
      interruption = error as Error & { osvResult: OsvScanResult };
    } finally {
      checking.mockRestore();
    }
    expect(interruption).toBeDefined();
    expect(calls).toBe(0);
    expect(interruption!.osvResult.coverage.inputs).toEqual([
      expect.objectContaining({
        path: "a/package-lock.json",
        sha256: createHash("sha256").update(npmLock()).digest("hex"),
        status: "failed",
        reason: reason.message,
      }),
    ]);
    let cause: Error = interruption!;
    while (cause.cause instanceof Error) cause = cause.cause;
    expect(cause).toBe(reason);
  });
  test("passes explicit selected lockfiles and inherited environment at the child boundary", async () => {
    const { repository, output } = await setup();
    await Promise.all([
      writeFile(join(repository, "package-lock.json"), npmLock()),
      writeFile(join(repository, "npm-shrinkwrap.json"), npmLock()),
    ]);
    const calls: { argv: string[]; options: OsvProcessOptions }[] = [];
    const result = await runOsvScan(
      {
        repositoryPath: repository,
        outputDir: output,
        environment: {
          ...process.env,
          SCA_SYNTHETIC_SETTING: "one",
          HTTPS_PROXY: "http://127.0.0.1:1234",
        },
      },
      {
        executable: process.execPath,
        runProcess: async (_exe, argv, options) => {
          calls.push({ argv, options });
          return argv[0] === "--version"
            ? { stdout: "2.6.0", stderr: "", exitCode: 0 }
            : {
                stdout: JSON.stringify(rawOutput("npm-shrinkwrap.json")),
                stderr: "",
                exitCode: 0,
              };
        },
      },
    );
    expect(result.status).toBe("completed");
    expect(calls[1]?.argv).toEqual([
      "scan",
      "source",
      "--format=json",
      "--all-packages",
      "--no-call-analysis=all",
      "--no-resolve",
      "--",
      join(repository, "npm-shrinkwrap.json"),
    ]);
    expect(calls[1]?.options.environment["SCA_SYNTHETIC_SETTING"]).toBe("one");
    expect(calls[1]?.options.environment["HTTPS_PROXY"]).toBe(
      "http://127.0.0.1:1234",
    );
    expect(calls[1]?.options.cwd).toBe(repository);
  });
  test("isolates concurrent environments and output files", async () => {
    const a = await setup();
    const b = await setup();
    await Promise.all([
      writeFile(join(a.repository, "package-lock.json"), npmLock()),
      writeFile(join(b.repository, "package-lock.json"), npmLock()),
    ]);
    const seen: string[] = [];
    const runProcess = async (
      _exe: string,
      argv: string[],
      options: OsvProcessOptions,
    ) => {
      if (argv[0] === "--version")
        return { stdout: "2.6.0", stderr: "", exitCode: 0 };
      seen.push(options.environment["SCA_SYNTHETIC_SETTING"]!);
      return {
        stdout: JSON.stringify(
          rawOutput("package-lock.json", [
            advisory(options.environment["SCA_SYNTHETIC_SETTING"]!),
          ]),
        ),
        stderr: "",
        exitCode: 1,
      };
    };
    const results = await Promise.all(
      [a, b].map((item, index) =>
        runOsvScan(
          {
            repositoryPath: item.repository,
            outputDir: item.output,
            environment: {
              ...process.env,
              SCA_SYNTHETIC_SETTING: String(index),
            },
          },
          { executable: process.execPath, runProcess },
        ),
      ),
    );
    expect(seen.sort()).toEqual(["0", "1"]);
    expect(results[0]?.matches[0]?.advisoryIds).toEqual(["0"]);
    expect(results[1]?.matches[0]?.advisoryIds).toEqual(["1"]);
    expect(results[0]?.scanner.rawOutputPath).not.toBe(
      results[1]?.scanner.rawOutputPath,
    );
  });
  test("preserves an explicit empty effective scope when OSV applies exclusions", async () => {
    const result = await scanFixture(
      {
        stdout: '{"results":[]}',
        stderr:
          "Package npm/synthetic-lib/1.2.0 has been filtered out because: synthetic exclusion",
        exitCode: 0,
      },
      {
        "osv-scanner.toml":
          '[[PackageOverrides]]\nname="synthetic-lib"\nignore=true\n',
      },
    );
    expect(result.status).toBe("completed");
    expect(result.components).toEqual([]);
  });
  test.each([
    ["unrelated", 'name="other-package"'],
    ["expired", 'name="synthetic-lib"\neffectiveUntil=2000-01-01'],
  ])(
    "does not accept missing inventory based on an %s override without a receipt",
    async (_label, fields) => {
      const result = await scanFixture(
        { stdout: '{"results":[]}', stderr: "", exitCode: 0 },
        {
          "osv-scanner.toml": `[[PackageOverrides]]\n${fields}\nignore=true\n`,
        },
      );
      expect(result.status).toBe("failed");
      expect(result.coverage.inputs[0]?.status).toBe("failed");
      expect(result.diagnostics.join("\n")).toContain(
        "absent from OSV output without evidence",
      );
    },
  );
  test("streams native child output and preserves it on cancellation", async () => {
    const { repository, output } = await setup();
    const controller = new AbortController();
    const stdoutPath = join(output, "child.json");
    const stderrPath = join(output, "child.log");
    const execution = runOsvProcess(
      process.execPath,
      [
        "-e",
        'console.log(process.env.SCA_SYNTHETIC_SETTING); console.error("started"); setTimeout(() => {}, 15000);',
      ],
      {
        cwd: repository,
        environment: { ...process.env, SCA_SYNTHETIC_SETTING: "inherited" },
        signal: controller.signal,
        stdoutPath,
        stderrPath,
      },
    );
    const settled = execution.catch(() => {});
    try {
      const deadline = Date.now() + 10_000;
      while (true) {
        const [stdout, stderr] = await Promise.all([
          readFile(stdoutPath, "utf8").catch(() => ""),
          readFile(stderrPath, "utf8").catch(() => ""),
        ]);
        if (stdout.includes("inherited") && stderr.includes("started")) break;
        if (Date.now() >= deadline)
          throw new Error("Synthetic child did not write its startup output.");
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      controller.abort(new Error("requested stop"));
      await expect(execution).rejects.toThrow();
      expect(await readFile(stdoutPath, "utf8")).toContain("inherited");
      expect(await readFile(stderrPath, "utf8")).toContain("started");
    } finally {
      controller.abort();
      await settled;
    }
  });
  test("attaches partial scanner context to interruption for orchestration persistence", async () => {
    const { repository, output } = await setup();
    await writeFile(join(repository, "package-lock.json"), npmLock());
    const controller = new AbortController();
    const pending = runOsvScan(
      {
        repositoryPath: repository,
        outputDir: output,
        signal: controller.signal,
      },
      {
        executable: process.execPath,
        runProcess: async (_exe, argv, processOptions) => {
          if (argv[0] === "--version")
            return { stdout: "2.6.0", stderr: "", exitCode: 0 };
          await writeFile(
            processOptions.stdoutPath!,
            JSON.stringify(rawOutput("package-lock.json", [advisory("A")])),
          );
          controller.abort(new Error("requested stop"));
          controller.signal.throwIfAborted();
          throw new Error("unreachable");
        },
      },
    );
    try {
      await pending;
      throw new Error("expected interruption");
    } catch (error) {
      expect(error).toHaveProperty("osvResult");
      expect(
        (error as { osvResult: { matches: unknown[] } }).osvResult.matches,
      ).toHaveLength(1);
      expect(
        (error as { osvResult: { scanner: { completedAt: string } } }).osvResult
          .scanner.completedAt,
      ).not.toBe("");
    }
  });
});
