import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { main, runCodexSkillCommand } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";

type FixtureOptions = NonNullable<Parameters<typeof dependencies>[0]>;
const directories: string[] = [];
afterEach(async () => {
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
});

async function repositoryFixture() {
  const directory = await mkdtemp(join(tmpdir(), "patch-results-"));
  directories.push(directory);
  const runRepositoryCommand: NonNullable<
    FixtureOptions["onRepositoryCommand"]
  > = (command, args, cwd, options) => {
    const result = execFileSync(command, [...args], {
      cwd,
      encoding: "utf8",
      env: { ...process.env, ...options?.environment },
      stdio: ["ignore", "pipe", "pipe"],
    });
    return options?.trim === false ? result : result.trim();
  };
  const git = (...args: string[]) =>
    runRepositoryCommand("git", args, directory);
  git("init", "--initial-branch=main");
  git("config", "user.name", "Synthetic User");
  git("config", "user.email", "synthetic@example.test");
  await writeFile(join(directory, "app.ts"), "original\n");
  git("add", ".");
  git("commit", "-m", "Synthetic fixture");
  return {
    directory,
    git,
    async patch(args: string[], options: FixtureOptions = {}) {
      const stdout = capture();
      const stderr = capture();
      const status = await main(
        ["patch", ...args, "--json"],
        stdout.stream,
        stderr.stream,
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
    const fixture = await repositoryFixture();
    const source = `
const assert = require("node:assert/strict");
const lines = require("node:readline").createInterface({ input: process.stdin });
const send = (value) => process.stdout.write(JSON.stringify(value) + "\\n");
lines.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.method === "initialize" || request.method === "account/login/start") send({ id: request.id, result: {} });
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
        onCodex: (_args, output, environment) =>
          runCodexSkillCommand(
            ["-e", source],
            output,
            {
              command: process.execPath,
            },
            environment,
          ),
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
    "fails a no-op with full output %s and preserves local changes",
    async (fullOutput) => {
      const fixture = await repositoryFixture();
      await writeFile(join(fixture.directory, "app.ts"), "staged change\n");
      fixture.git("add", "app.ts");
      await writeFile(join(fixture.directory, "app.ts"), "unstaged change\n");
      await writeFile(join(fixture.directory, "local.txt"), "untracked\n");
      const index = fixture.git("write-tree");
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
      expect(fixture.git("write-tree")).toBe(index);
      expect(await readFile(join(fixture.directory, "app.ts"), "utf8")).toBe(
        "unstaged change\n",
      );
      expect(await readFile(join(fixture.directory, "local.txt"), "utf8")).toBe(
        "untracked\n",
      );
    },
  );

  test("reports actual changed files and preserves the index", async () => {
    const fixture = await repositoryFixture();
    await writeFile(join(fixture.directory, "local.txt"), "unrelated\n");
    fixture.git("add", "local.txt");
    const index = fixture.git("write-tree");
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
    expect(fixture.git("write-tree")).toBe(index);
  });

  test.each([false, true])(
    "checks patch changes outside a Git repository: %s",
    async (apply) => {
      const fixture = await repositoryFixture();
      await rm(join(fixture.directory, ".git"), {
        recursive: true,
        force: true,
      });
      const outcome = await fixture.patch(["Synthetic issue"], {
        onCodex: async () => {
          if (apply)
            await writeFile(join(fixture.directory, "app.ts"), "fixed\n");
          return 0;
        },
      });
      expect(outcome.status).toBe(apply ? 0 : 2);
      expect(outcome.result).toMatchObject({
        applied: apply,
        filesChanged: apply ? 1 : 0,
      });
    },
  );

  test("rejects a verified saved-finding result when no files change", async () => {
    const fixture = await repositoryFixture();
    const outcome = await fixture.patch(["--scan", "scan-1"], {
      onWorkbench: () => ({
        scan: {
          scanId: "scan-1",
          targetPath: fixture.directory,
          findings: [
            {
              occurrenceId: "occ_1",
              title: "Synthetic finding",
              severity: { level: "high" },
              locations: [{ path: "app.ts", startLine: 1 }],
            },
          ],
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

  test.each(["exit", "rpc"])(
    "fails before starting a model turn when sandbox preflight returns %s failure",
    async (failure) => {
      const fixture = await repositoryFixture();
      const source = `
const assert = require("node:assert/strict");
const lines = require("node:readline").createInterface({ input: process.stdin });
const send = (value) => process.stdout.write(JSON.stringify(value) + "\\n");
lines.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.method === "initialize" || request.method === "account/login/start") send({ id: request.id, result: {} });
  if (request.method === "thread/start") send({ id: request.id, result: { thread: { id: "thread" }, sandbox: { type: "workspaceWrite", writableRoots: [], networkAccess: false, excludeTmpdirEnvVar: false, excludeSlashTmp: false } } });
  if (request.method === "command/exec") {
    assert.equal(request.params.sandboxPolicy.type, "workspaceWrite");
    assert.deepEqual(request.params.command, [process.execPath, "-e", ""]);
    send({ id: request.id, ${failure === "rpc" ? 'error: { code: -32603, message: "sandbox: unshare: Permission denied /private/repository sk-proj-SYNTHETIC_SECRET" }' : 'result: { exitCode: 1, stdout: "", stderr: "sandbox: unshare: Permission denied /private/repository sk-proj-SYNTHETIC_SECRET" }'} });
  }
  if (request.method === "turn/start") throw new Error("Model turn must not start");
});`;
      const outcome = await fixture.patch(
        ["Synthetic issue", "--full-output"],
        {
          onCodex: (_args, output, environment) =>
            runCodexSkillCommand(
              ["-e", source],
              output,
              {
                command: process.execPath,
              },
              environment,
            ),
        },
      );
      expect(outcome.status).toBe(2);
      expect(outcome.result).toMatchObject({
        ok: false,
        error: { code: "SANDBOX_UNAVAILABLE" },
      });
      expect(outcome.stdout + outcome.stderr).not.toContain("SYNTHETIC_SECRET");
      expect(outcome.stdout + outcome.stderr).not.toContain(
        "/private/repository",
      );
      expect(fixture.git("status", "--porcelain")).toBe("");
    },
  );
});
