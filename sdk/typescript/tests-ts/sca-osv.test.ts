import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
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
import { afterEach, describe, expect, test } from "bun:test";
import {
  discoverScaInputs,
  normalizeOsvOutput,
  osvErrorDiagnostics,
  runOsvProcess,
  runOsvScan,
  type OsvProcessOptions,
  type OsvProcessResult,
} from "../src/sca-osv.js";
import type { ScaInput } from "../src/sca-types.js";
import { dependencyScanResult, saveDependencyScan } from "../src/sca.js";

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
      const result = await runOsvScan(
        { repositoryPath: repository, outputDir: output },
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
      ...[2, 3].map((lockfileVersion) => ({
        path: "package-lock.json",
        content: JSON.stringify({
          lockfileVersion,
          packages: {
            "": { dependencies: { "synthetic-lib": "^1.2.0" } },
            "node_modules/synthetic-lib": {
              version: "1.2.0",
              resolved: "https://registry.example.test/synthetic-lib.tgz",
            },
          },
        }),
      })),
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
          ? "https://registry.example.test"
          : ecosystem === "RubyGems"
            ? "https://gems.example.test"
            : "https://index.example.test/simple",
      );
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
  test.each(["dependencies", "devDependencies", "optionalDependencies"])(
    "preserves npm direct URL provenance recorded in %s without changing registry tarballs",
    async (group) => {
      const resolved =
        "https://registry.npmjs.org/synthetic-lib/-/synthetic-lib-1.2.0.tgz";
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
