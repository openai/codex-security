import { execFile as execFileCallback, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";

const execFile = promisify(execFileCallback);
const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

test.each(["missing-git", "broken-metadata", "standalone"] as const)(
  "inventory distinguishes failed Git discovery from standalone directories: %s",
  async (scenario) => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "sca-git-discovery-")),
    );
    directories.push(root);
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
      await execFile("git", ["init", "--quiet", repository]);
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
    const child = spawnSync(
      process.execPath,
      [
        "-e",
        script,
        repository,
        join(root, "output"),
        pathToFileURL(join(import.meta.dir, "../src/sca-osv.ts")).href,
      ],
      { encoding: "utf8", env: environment },
    );
    expect(child.stderr).toBe("");
    expect(child.status).toBe(0);
    const { discovery, result, scannerCalls } = JSON.parse(child.stdout);
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
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "sca-git-scope-")),
    );
    directories.push(root);
    const repository = join(root, "repository");
    const selected = join(repository, "SRC");
    const indexed = join(repository, "src");
    await mkdir(selected, { recursive: true });
    await writeFile(join(repository, ".gitignore"), "*\n");
    await writeFile(
      join(selected, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 3, packages: {} }),
    );
    await execFile("git", ["init", "--quiet", repository]);
    const { stdout } = await execFile("git", [
      "-C",
      repository,
      "hash-object",
      "-w",
      "--",
      join(selected, "package-lock.json"),
    ]);
    await execFile("git", [
      "-C",
      repository,
      "update-index",
      "--add",
      "--cacheinfo",
      "100644",
      stdout.trim(),
      "src/package-lock.json",
    ]);
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
    const child = spawnSync(
      process.execPath,
      [
        "-e",
        script,
        selected,
        indexed,
        other,
        String(sameDirectory),
        pathToFileURL(join(import.meta.dir, "../src/sca-osv.ts")).href,
      ],
      { encoding: "utf8" },
    );
    expect(child.stderr).toBe("");
    expect(child.status).toBe(0);
    const result = JSON.parse(child.stdout);
    expect(
      result.inputs.map((input: { path: string; status: string }) => [
        input.path,
        input.status,
      ]),
    ).toEqual(sameDirectory ? [["package-lock.json", "scanned"]] : []);
    expect(result.diagnostics).toEqual([]);
  },
);
