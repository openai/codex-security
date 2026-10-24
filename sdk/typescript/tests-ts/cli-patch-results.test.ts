import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import {
  main,
  runCodexSkillCommand,
  runRepositoryCommand,
} from "../src/cli.js";
import type { Finding } from "../src/models.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";

type FixtureOptions = NonNullable<Parameters<typeof dependencies>[0]>;

async function repositoryFixture({
  initializeGit = true,
  initialCommit = true,
} = {}) {
  const directory = await mkdtemp(join(tmpdir(), "patch-results-"));
  const git = (...args: string[]) =>
    runRepositoryCommand("git", args, directory);
  try {
    await writeFile(join(directory, "app.ts"), "original\n");
    if (initializeGit) {
      await git("init", "--initial-branch=main");
      await git("config", "user.name", "Synthetic User");
      await git("config", "user.email", "synthetic@example.test");
      await git("add", ".");
      if (initialCommit) await git("commit", "-m", "Synthetic fixture");
    }
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
  return {
    directory,
    git,
    async [Symbol.asyncDispose]() {
      await rm(directory, { recursive: true, force: true });
    },
    async patch(args: string[], options: FixtureOptions = {}) {
      const { stdout, stderr, runCli } = createCliTest(main);

      const status = await runCli(
        ["patch", ...args, "--json"],
        dependencies({
          currentDirectory: directory,
          environment: {
            CODEX_HOME: join(directory, ".codex-home"),
            CODEX_API_KEY: "sk-proj-SYNTHETIC_KEY",
          },
          onRepositoryCommand: runRepositoryCommand,
          ...options,
        }),
      );
      return {
        status,
        result: JSON.parse(stdout.text()),
        stdout: stdout.text(),
        stderr: stderr.text(),
      };
    },
  };
}

describe("patch outcomes", () => {
  test("uses the external sandbox only after explicit opt-in and prints a warning", async () => {
    await using fixture = await repositoryFixture();
    const source = `
const assert = require("node:assert/strict");
const lines = require("node:readline").createInterface({ input: process.stdin });
const send = (value) => process.stdout.write(JSON.stringify(value) + "\\n");
lines.on("line", (line) => {
  const request = JSON.parse(line);
  if (["initialize", "account/login/start", "config/read"].includes(request.method)) send({ id: request.id, result: {} });
  if (request.method === "experimentalFeature/list") send({ id: request.id, result: { data: [{ name: "cli_daybreak", enabled: true }, { name: "api_key_cyber_access_programs", enabled: true }], nextCursor: null } });
  if (request.method === "thread/start") {
    assert.equal(request.params.sandbox, "workspace-write");
    send({ id: request.id, result: { thread: { id: "thread" }, sandbox: { type: "workspaceWrite" } } });
  }
  if (request.method === "command/exec") {
    assert.deepEqual(request.params.sandboxPolicy, { type: "externalSandbox", networkAccess: "enabled" });
    send({ id: request.id, result: { exitCode: 0 } });
  }
  if (request.method === "turn/start") {
    assert.deepEqual(request.params.sandboxPolicy, { type: "externalSandbox", networkAccess: "enabled" });
    require("node:fs").writeFileSync("app.ts", "fixed\\n");
    send({ id: request.id, result: { turn: { id: "turn" } } });
    send({ method: "item/completed", params: { threadId: "thread", turnId: "turn", item: { type: "agentMessage", text: "Applied the fix." } } });
    send({ method: "turn/completed", params: { threadId: "thread", turn: { id: "turn", status: "completed" } } });
  }
});`;
    const outcome = await fixture.patch(
      ["Synthetic issue", "--external-sandbox"],
      {
        onCodex: nodeCodex(source),
      },
    );
    expect(outcome.status).toBe(0);
    expect(outcome.result).toMatchObject({
      applied: true,
      filesChanged: 1,
      files: ["app.ts"],
    });
    expect(outcome.stderr).toContain(
      "WARNING: --external-sandbox disables Codex sandbox enforcement",
    );
  });

  test.each([false, true])(
    "fails a no-op with full output %j and preserves local changes",
    async (fullOutput) => {
      await using fixture = await repositoryFixture();
      await writeFile(join(fixture.directory, "app.ts"), "staged change\n");
      await fixture.git("add", "app.ts");
      await writeFile(join(fixture.directory, "app.ts"), "unstaged change\n");
      await writeFile(join(fixture.directory, "local.txt"), "untracked\n");
      const index = await fixture.git("write-tree");
      const outcome = await fixture.patch(
        ["Synthetic issue", ...(fullOutput ? ["--full-output"] : [])],
        {
          onCodex: (_args, output) => {
            output?.stdout.write("I could not run the patch commands.");
            return 0;
          },
        },
      );
      expect(outcome.status).toBe(2);
      expect(outcome.result).toMatchObject({
        ok: false,
        error: { code: "NO_PATCH_APPLIED" },
      });
      expect(await fixture.git("write-tree")).toBe(index);
      expect(await readFile(join(fixture.directory, "app.ts"), "utf8")).toBe(
        "unstaged change\n",
      );
      expect(await readFile(join(fixture.directory, "local.txt"), "utf8")).toBe(
        "untracked\n",
      );
    },
  );

  test("reports actual changed files and preserves the index", async () => {
    await using fixture = await repositoryFixture();
    await writeFile(join(fixture.directory, "local.txt"), "unrelated\n");
    await fixture.git("add", "local.txt");
    const index = await fixture.git("write-tree");
    const outcome = await fixture.patch(["Synthetic issue", "--full-output"], {
      onCodex: async (_args, output) => {
        await writeFile(join(fixture.directory, "app.ts"), "fixed\n");
        await writeFile(
          join(fixture.directory, "regression.test.ts"),
          "test\n",
        );
        output?.stdout.write("Applied the patch.");
        return 0;
      },
    });
    expect(outcome.status).toBe(0);
    expect(outcome.result).toMatchObject({
      ok: true,
      data: {
        applied: true,
        filesChanged: 2,
        files: ["app.ts", "regression.test.ts"],
      },
    });
    expect(await fixture.git("write-tree")).toBe(index);
  });

  test.each([
    ["directory", false],
    ["directory", true],
    ["unborn Git", false],
    ["unborn Git", true],
    ["committed Git", false],
    ["committed Git", true],
  ] as const)(
    "checks patch changes in %s with source edits: %j",
    async (kind, apply) => {
      const initializeGit = kind !== "directory";
      await using fixture = await repositoryFixture({
        initializeGit,
        initialCommit: kind === "committed Git",
      });
      if (initializeGit) {
        await writeFile(join(fixture.directory, ".gitignore"), "dist/\n");
        await mkdir(join(fixture.directory, "dist"));
        await writeFile(join(fixture.directory, "staged.ts"), "staged\n");
        await fixture.git("add", ".gitignore", "staged.ts");
      }
      const indexPath = join(fixture.directory, ".git", "index");
      const index = initializeGit ? await readFile(indexPath) : null;
      const metadata = join(fixture.directory, initializeGit ? ".git" : ".svn");
      await mkdir(metadata, { recursive: true });
      const outcome = await fixture.patch(["Synthetic issue"], {
        onCodex: async () => {
          await writeFile(join(metadata, "synthetic-state"), "updated\n");
          if (initializeGit)
            await writeFile(
              join(fixture.directory, "dist", "test-output.log"),
              "test ran\n",
            );
          if (apply)
            await writeFile(join(fixture.directory, "app.ts"), "fixed\n");
          return 0;
        },
      });
      expect(outcome.status, outcome.stderr).toBe(apply ? 0 : 2);
      expect(outcome.result).toMatchObject({
        applied: apply,
        filesChanged: apply ? 1 : 0,
        files: apply ? ["app.ts"] : [],
      });
      if (index !== null) expect(await readFile(indexPath)).toEqual(index);
      if (!apply)
        expect(outcome.result.error).toMatchObject({
          code: "NO_PATCH_APPLIED",
        });
    },
  );

  test.each([
    [false, false, false],
    [false, false, true],
    [false, true, false],
    [false, true, true],
    [true, false, false],
    [true, false, true],
    [true, true, false],
    [true, true, true],
  ])(
    "ignores SVN metadata in Git with commits: %j, tracked metadata: %j and source edits: %j",
    async (committed, tracked, apply) => {
      await using fixture = await repositoryFixture({
        initialCommit: committed,
      });
      const metadata = [".svn", "nested/.svn"];
      for (const directory of metadata) {
        await mkdir(join(fixture.directory, directory), { recursive: true });
        await writeFile(
          join(fixture.directory, directory, "wc.db"),
          "original metadata\n",
        );
      }
      const source = join(fixture.directory, "nested", ".svn-backup", "app.ts");
      await mkdir(join(fixture.directory, "nested", ".svn-backup"));
      await writeFile(source, "original source\n");
      if (tracked) await fixture.git("add", ".");
      if (committed) {
        await fixture.git("add", "nested/.svn-backup/app.ts");
        await fixture.git("commit", "-m", "Synthetic source and metadata");
      }
      const indexPath = join(fixture.directory, ".git", "index");
      const index = await readFile(indexPath);

      const outcome = await fixture.patch(["Synthetic issue"], {
        currentDirectory: join(fixture.directory, "nested"),
        onRepositoryCommand: (command, args, repository, options) =>
          runRepositoryCommand(command, args, repository, {
            ...options,
            environment: {
              GIT_LITERAL_PATHSPECS: "1",
              ...options?.environment,
            },
          }),
        onCodex: async () => {
          for (const directory of metadata)
            await writeFile(
              join(fixture.directory, directory, "wc.db"),
              "updated metadata\n",
            );
          if (apply) await writeFile(source, "fixed\n");
          return 0;
        },
      });

      expect(outcome.status, outcome.stderr).toBe(apply ? 0 : 2);
      expect(outcome.result).toMatchObject({
        applied: apply,
        filesChanged: apply ? 1 : 0,
        files: apply ? ["nested/.svn-backup/app.ts"] : [],
      });
      if (!apply)
        expect(outcome.result.error).toMatchObject({
          code: "NO_PATCH_APPLIED",
        });
      expect(await readFile(indexPath)).toEqual(index);
      for (const directory of metadata)
        expect(
          await readFile(join(fixture.directory, directory, "wc.db"), "utf8"),
        ).toBe("updated metadata\n");
    },
  );

  test
    .skipIf(process.platform === "win32" || process.getuid?.() === 0)
    .each([false, true])(
    "patches readable source with unreadable SVN metadata, tracked: %j",
    async (tracked) => {
      await using fixture = await repositoryFixture({ initialCommit: false });
      const metadata = [".svn", "nested/.svn"].map((directory) =>
        join(fixture.directory, directory, "wc.db"),
      );
      for (const directory of [".svn", "nested/.svn"])
        await mkdir(join(fixture.directory, directory), { recursive: true });
      for (const file of metadata) await writeFile(file, "metadata\n");
      if (tracked) await fixture.git("add", ".");
      const indexPath = join(fixture.directory, ".git", "index");
      const index = await readFile(indexPath);
      for (const file of metadata) await chmod(file, 0);
      try {
        for (const file of metadata)
          await expect(readFile(file)).rejects.toMatchObject({
            code: "EACCES",
          });
        const outcome = await fixture.patch(["Synthetic issue"], {
          onCodex: async () => {
            await writeFile(join(fixture.directory, "app.ts"), "fixed\n");
            return 0;
          },
        });

        expect(outcome.status, outcome.stderr).toBe(0);
        expect(outcome.result).toMatchObject({
          applied: true,
          filesChanged: 1,
          files: ["app.ts"],
        });
        expect(await readFile(indexPath)).toEqual(index);
        expect(await readFile(join(fixture.directory, "app.ts"), "utf8")).toBe(
          "fixed\n",
        );
      } finally {
        for (const file of metadata) await chmod(file, 0o600);
      }
    },
  );

  test.each([
    [false, undefined],
    [true, undefined],
    [true, "assume-unchanged"],
    [true, "skip-worktree"],
  ] as const)(
    "tracks force-staged ignored files in unborn Git with intent-to-add: %j and flag: %s",
    async (intentToAdd, flag) => {
      await using fixture = await repositoryFixture({ initialCommit: false });
      await writeFile(
        join(fixture.directory, ".gitignore"),
        "ignored file.ts\n",
      );
      const source = join(fixture.directory, "ignored file.ts");
      await writeFile(source, "original\n");
      await fixture.git(
        "add",
        "--force",
        ...(intentToAdd ? ["--intent-to-add"] : []),
        "ignored file.ts",
      );
      if (flag)
        await fixture.git("update-index", `--${flag}`, "ignored file.ts");
      const indexPath = join(fixture.directory, ".git", "index");
      const index = await readFile(indexPath);

      const outcome = await fixture.patch(["Synthetic issue"], {
        onCodex: async () => {
          await writeFile(source, "fixed\n");
          return 0;
        },
      });

      expect(outcome.status, outcome.stderr).toBe(0);
      expect(outcome.result).toMatchObject({
        applied: true,
        filesChanged: 1,
        files: ["ignored file.ts"],
      });
      expect(await readFile(indexPath)).toEqual(index);
    },
  );

  test("tracks ignored files with an inherited literal-pathspec environment", async () => {
    await using fixture = await repositoryFixture({ initialCommit: false });
    await writeFile(join(fixture.directory, ".gitignore"), "app.ts\n");
    const indexPath = join(fixture.directory, ".git", "index");
    const index = await readFile(indexPath);

    const outcome = await fixture.patch(["Synthetic issue"], {
      onRepositoryCommand: (command, args, repository, options) =>
        runRepositoryCommand(command, args, repository, {
          ...options,
          environment: {
            GIT_LITERAL_PATHSPECS: "1",
            ...options?.environment,
          },
        }),
      onCodex: async () => {
        await writeFile(join(fixture.directory, "app.ts"), "fixed\n");
        return 0;
      },
    });

    expect(outcome.status, outcome.stderr).toBe(0);
    expect(outcome.result).toMatchObject({
      applied: true,
      filesChanged: 1,
      files: ["app.ts"],
    });
    expect(await readFile(indexPath)).toEqual(index);
  });

  test.skipIf(process.platform === "win32")(
    "tracks ignored filenames with raw bytes and Git quoting characters",
    async () => {
      await using fixture = await repositoryFixture({ initialCommit: false });
      await fixture.git("config", "core.quotePath", "false");
      await writeFile(join(fixture.directory, ".gitignore"), "ignored*\n");
      const source = Buffer.concat([
        Buffer.from(join(fixture.directory, "ignored-")),
        process.platform === "darwin" ? Buffer.from("é") : Buffer.from([0xff]),
        Buffer.from('\n"\\\t\r.ts'),
      ]);
      await writeFile(source, "original\n");
      await fixture.git("add", "--force", ".");
      const indexPath = join(fixture.directory, ".git", "index");
      const index = await readFile(indexPath);

      const outcome = await fixture.patch(["Synthetic issue"], {
        onCodex: async () => {
          await writeFile(source, "fixed\n");
          return 0;
        },
      });

      expect(outcome.status, outcome.stderr).toBe(0);
      expect(outcome.result).toMatchObject({ applied: true, filesChanged: 1 });
      expect(await readFile(source, "utf8")).toBe("fixed\n");
      expect(await readFile(indexPath)).toEqual(index);
    },
  );

  test.each([
    ["assume-unchanged", "edit"],
    ["assume-unchanged", "delete"],
    ["assume-unchanged", "none"],
    ["skip-worktree", "edit"],
    ["skip-worktree", "delete"],
    ["skip-worktree", "none"],
    ["core.ignorestat", "edit"],
    ["core.ignorestat", "delete"],
    ["core.ignorestat", "none"],
  ] as const)(
    "checks unborn Git patches despite %s with change: %s",
    async (flag, change) => {
      await using fixture = await repositoryFixture({ initialCommit: false });
      if (flag === "core.ignorestat") await fixture.git("config", flag, "true");
      else await fixture.git("update-index", `--${flag}`, "app.ts");
      const indexPath = join(fixture.directory, ".git", "index");
      const index = await readFile(indexPath);

      const outcome = await fixture.patch(["Synthetic issue"], {
        onCodex: async () => {
          const source = join(fixture.directory, "app.ts");
          if (change === "delete") await rm(source);
          if (change === "edit") await writeFile(source, "fixed\n");
          return 0;
        },
      });

      const applied = change !== "none";
      expect(outcome.status, outcome.stderr).toBe(applied ? 0 : 2);
      expect(outcome.result).toMatchObject({
        applied,
        filesChanged: applied ? 1 : 0,
        files: applied ? ["app.ts"] : [],
      });
      expect(await readFile(indexPath)).toEqual(index);
    },
  );

  test("detects same-size changes with racy unborn Git index timestamps", async () => {
    await using fixture = await repositoryFixture({ initialCommit: false });
    await fixture.git("config", "core.checkStat", "minimal");
    await fixture.git("config", "core.trustctime", "false");
    const source = join(fixture.directory, "app.ts");
    const indexPath = join(fixture.directory, ".git", "index");
    const timestamp = new Date("2000-01-01T00:00:00Z");
    await utimes(source, timestamp, timestamp);
    await fixture.git("add", "app.ts");
    await utimes(indexPath, timestamp, timestamp);
    await writeFile(source, "unsafe!!\n");
    await utimes(source, timestamp, timestamp);
    const index = await readFile(indexPath);

    const outcome = await fixture.patch(["Synthetic issue"], {
      onCodex: async () => {
        await writeFile(source, "original\n");
        await utimes(source, timestamp, timestamp);
        return 0;
      },
    });

    expect(outcome.status, outcome.stderr).toBe(0);
    expect(outcome.result).toMatchObject({
      applied: true,
      filesChanged: 1,
      files: ["app.ts"],
    });
    expect(await readFile(indexPath)).toEqual(index);
  });

  test.each([false, true])(
    "checks unborn Git without an index with source edits: %j",
    async (apply) => {
      await using fixture = await repositoryFixture({ initialCommit: false });
      const indexPath = join(fixture.directory, ".git", "index");
      await rm(indexPath);
      await writeFile(join(fixture.directory, ".gitignore"), "dist/\n");
      await mkdir(join(fixture.directory, "dist"));

      const outcome = await fixture.patch(["Synthetic issue"], {
        onCodex: async () => {
          await writeFile(
            join(fixture.directory, "dist", "test-output.log"),
            "test ran\n",
          );
          if (apply)
            await writeFile(join(fixture.directory, "app.ts"), "fixed\n");
          return 0;
        },
      });

      expect(outcome.status, outcome.stderr).toBe(apply ? 0 : 2);
      expect(outcome.result).toMatchObject({
        applied: apply,
        filesChanged: apply ? 1 : 0,
        files: apply ? ["app.ts"] : [],
      });
      await expect(readFile(indexPath)).rejects.toMatchObject({
        code: "ENOENT",
      });
    },
  );

  test.each([
    ["missing commit", `${"1".repeat(40)}\n`],
    ["malformed ref", "broken\n"],
  ])("does not patch a Git checkout with a %s", async (_kind, ref) => {
    await using fixture = await repositoryFixture({ initialCommit: false });
    await writeFile(
      join(fixture.directory, ".git", "refs", "heads", "main"),
      ref,
    );
    let started = false;
    const outcome = await fixture.patch(["Synthetic issue"], {
      onCodex: () => {
        started = true;
        return 0;
      },
    });
    expect(outcome.status).toBe(2);
    expect(started).toBe(false);
  });

  test("rejects a verified saved-finding result when no files change", async () => {
    await using fixture = await repositoryFixture();
    const finding = {
      occurrenceId: "occ_1",
      findingId: "csf_1",
      title: "Synthetic finding",
      severity: { level: "high" },
      locations: [{ path: "app.ts", startLine: 1 }],
    };
    const outcome = await fixture.patch(["--scan", "scan-1"], {
      readSavedFindings: async () => [finding as Finding],
      onWorkbench: () => ({
        scan: {
          scanId: "scan-1",
          targetPath: fixture.directory,
          findings: [finding],
        },
      }),
      onCodex: (_args, output) => {
        output?.stdout.write(
          JSON.stringify({
            patches: [
              {
                occurrenceId: "occ_1",
                status: "verified",
                files: ["app.ts"],
                verification: "The checks pass.",
              },
            ],
          }),
        );
        return 0;
      },
    });
    expect(outcome.status).toBe(2);
    expect(outcome.result).toMatchObject({
      ok: false,
      error: { code: "PATCH_FAILED" },
    });
    expect(outcome.stderr).toContain("No patch was applied; 0 files changed.");
  });

  test.each(["exit", "rpc", "stdout", "empty"])(
    "fails before starting a model turn when sandbox preflight returns %s failure",
    async (failure) => {
      await using fixture = await repositoryFixture();
      const diagnostic =
        "sandbox: unshare: Permission denied /synthetic/repository sk-proj-SYNTHETIC_SECRET";
      const response =
        failure === "rpc"
          ? { error: { code: -32603, message: diagnostic } }
          : {
              result: {
                exitCode: 1,
                stdout: failure === "stdout" ? diagnostic : "",
                stderr: failure === "exit" ? diagnostic : "",
              },
            };
      const source = `
const assert = require("node:assert/strict");
const lines = require("node:readline").createInterface({ input: process.stdin });
const send = (value) => process.stdout.write(JSON.stringify(value) + "\\n");
lines.on("line", (line) => {
  const request = JSON.parse(line);
  if (["initialize", "account/login/start", "config/read"].includes(request.method)) send({ id: request.id, result: {} });
  if (request.method === "thread/start") send({ id: request.id, result: { thread: { id: "thread" }, sandbox: { type: "workspaceWrite", writableRoots: [], networkAccess: false, excludeTmpdirEnvVar: false, excludeSlashTmp: false } } });
  if (request.method === "command/exec") {
    assert.equal(request.params.sandboxPolicy.type, "workspaceWrite");
    assert.deepEqual(request.params.command, [process.execPath, "-e", ""]);
    send({ id: request.id, ...${JSON.stringify(response)} });
  }
  if (request.method === "turn/start") throw new Error("Model turn must not start");
});`;
      const outcome = await fixture.patch(
        ["Synthetic issue", "--full-output"],
        {
          onCodex: nodeCodex(source),
        },
      );
      expect(outcome.status).toBe(2);
      expect(outcome.result).toMatchObject({
        ok: false,
        error: { code: "SANDBOX_UNAVAILABLE" },
      });
      if (failure !== "empty")
        expect(outcome.stdout + outcome.stderr).toContain(diagnostic);
      expect(outcome.stderr).toContain(
        "No patch was applied; 0 files changed.",
      );
      expect(await fixture.git("status", "--porcelain")).toBe("");
    },
  );
});

function nodeCodex(source: string): NonNullable<FixtureOptions["onCodex"]> {
  return (_args, output, environment) =>
    runCodexSkillCommand(
      ["-e", source],
      output,
      { command: process.execPath },
      environment,
    );
}
