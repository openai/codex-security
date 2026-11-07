import { afterEach, expect, test } from "bun:test";
import { execFileSync, spawn } from "node:child_process";
import { constants, closeSync, openSync, writeSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { setTimeout as delay } from "node:timers/promises";
import { readSkillCommandOutput } from "../src/cli.js";
import {
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test("cancelling patch preparation prevents a late turn/start", async () => {
  const controller = new AbortController();
  const requests: { method?: string }[] = [];
  let receivedSignal: AbortSignal | undefined;
  async function* messages() {
    for (const message of [
      { id: 1, result: {} },
      {
        id: 2,
        result: {
          thread: { id: "synthetic" },
          sandbox: { type: "workspaceWrite" },
        },
      },
      { id: 5, result: { exitCode: 0 } },
    ])
      yield JSON.stringify(message) + "\n";
  }
  await readSkillCommandOutput(messages(), {
    directory: process.cwd(),
    prompt: "Synthetic patch",
    threadSource: "security_remediation",
    signal: controller.signal,
    input: new Writable({
      write(chunk, _encoding, callback) {
        requests.push(JSON.parse(chunk.toString()));
        callback();
      },
    }),
    onBeforeTurn: async (signal) => {
      receivedSignal = signal;
      controller.abort();
      await Promise.resolve();
    },
  });
  expect(requests.map((request) => request.method)).not.toContain("turn/start");
  expect(receivedSignal).toBe(controller.signal);
});

test.each(["saved", "supplied"])(
  "does not snapshot after an interrupted %s patch turn",
  async (source) => {
    const repository = await fixtures.create("patch-interrupted-turn-");
    const git = repositoryGit(repository);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await writeFile(join(repository, "app.ts"), "original\n");
    git("add", ".");
    git("commit", "-m", "Synthetic interruption baseline");
    let interrupted = false;
    const snapshots: string[][] = [];
    const outcome = await runWorkflow(
      source === "saved"
        ? ["patch", "--scan", "scan-1", "--json"]
        : ["patch", "Synthetic issue", "--json"],
      {
        currentDirectory: repository,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", repository),
        onCodex: async () => {
          await writeFile(join(repository, "app.ts"), "partial edit\n");
          interrupted = true;
          return 143;
        },
        onRepositoryCommand: (command, args, cwd, options) => {
          if (interrupted && options?.patchSnapshot) snapshots.push([...args]);
          return runGitRepositoryCommand(command, args, cwd, options);
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(143);
    expect(interrupted).toBe(true);
    expect(snapshots).toEqual([]);
    const response = JSON.parse(outcome.stdout);
    expect(response).not.toHaveProperty("applied");
    expect(response).not.toHaveProperty("filesChanged");
    expect(response.error.message).toContain("not fully inspected");
    expect(await readFile(join(repository, "app.ts"), "utf8")).toBe(
      "partial edit\n",
    );
  },
);

test.each([false, true])(
  "retains completed batch changes when the next patch is interrupted (Git: %p)",
  async (useGit) => {
    const repository = await fixtures.create("patch-interrupted-batch-");
    await mkdir(join(repository, "src"));
    for (const name of ["src/finding-1.ts", "src/finding-2.ts", "local.txt"])
      await writeFile(join(repository, name), "original\n");
    if (useGit) {
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("add", ".");
      git("commit", "-m", "Synthetic batch baseline");
    }
    await writeFile(join(repository, "local.txt"), "pre-existing edit\n");
    let calls = 0;
    let interrupted = false;
    const snapshots: string[][] = [];
    const outcome = await runWorkflow(["patch", "--scan", "scan-1", "--json"], {
      currentDirectory: repository,
      onWorkbench: () =>
        savedScan(resultWithFindings(["high", "high"]), "scan-1", repository),
      onRepositoryCommand: (command, args, cwd, options) => {
        if (interrupted && options?.patchSnapshot) snapshots.push([...args]);
        if (!useGit) throw new Error("fatal: not a git repository");
        return runGitRepositoryCommand(command, args, cwd, options);
      },
      onCodex: async (_args, output) => {
        calls++;
        await writeFile(
          join(repository, `src/finding-${calls}.ts`),
          "partial edit\n",
        );
        if (calls === 2) {
          interrupted = true;
          return 143;
        }
        output!.stdout.write(
          JSON.stringify({
            patches: [
              {
                occurrenceId: "occ_1",
                status: "verified",
                files: ["src/finding-1.ts"],
                verification: "Synthetic check.",
              },
            ],
          }),
        );
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(143);
    expect(calls).toBe(2);
    expect(snapshots).toEqual([]);
    const response = JSON.parse(outcome.stdout);
    expect(response.files).toEqual(["src/finding-1.ts"]);
    expect(response).not.toHaveProperty("applied");
    expect(response).not.toHaveProperty("filesChanged");
    expect(response.error.message).toContain("not fully inspected");
    expect(response.patches[0]).toMatchObject({
      status: "verified",
      files: ["src/finding-1.ts"],
    });
    expect(response.patches[1]).toMatchObject({
      status: "failed",
      reason: expect.stringContaining("not inspected"),
    });
    for (const name of ["src/finding-1.ts", "src/finding-2.ts"])
      expect(await readFile(join(repository, name), "utf8")).toBe(
        "partial edit\n",
      );
    expect(await readFile(join(repository, "local.txt"), "utf8")).toBe(
      "pre-existing edit\n",
    );
  },
);

test
  .skipIf(process.platform === "win32")
  .each([
    "supplied SIGTERM",
    "saved SIGTERM",
    "app-server exit",
    "supplied preflight exit",
    "saved pre-turn exit",
  ] as const)(
  "cancels an active pre-turn Git snapshot without restarting: %s",
  async (mode) => {
    const saved = mode.startsWith("saved");
    const preflight = mode === "supplied preflight exit";
    const nativeExit = mode.endsWith("exit");
    const snapshotCount = saved || preflight ? 2 : 1;
    const root = await fixtures.create("patch-preparation-cancel-");
    const repository = join(root, "repository"),
      home = join(root, "home");
    await Promise.all([mkdir(repository), mkdir(home)]);
    await writeFile(join(home, "config.toml"), "");
    const git = repositoryGit(repository);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await writeFile(join(repository, "app.ts"), "original\n");
    git("add", ".");
    git("commit", "-m", "Synthetic cancellation baseline");
    if (preflight) {
      const remote = join(root, "remote");
      await mkdir(remote);
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
    }
    const fifo = join(root, "slow-input"),
      ready = join(root, "ready"),
      serverPid = join(root, "server-pid"),
      lateTurn = join(root, "late-turn");
    execFileSync("mkfifo", [fifo]);
    const server = join(root, "app-server.mjs");
    await writeFile(
      server,
      `
import { createInterface } from "node:readline";
import { writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
if (process.argv[2] === "sandbox") {
  const separator = process.argv.indexOf("--");
  if (separator < 0) throw new Error("Synthetic executor did not receive a command.");
  const [command, ...args] = process.argv.slice(separator + 1);
  const child = spawn(command, args, { stdio: "inherit" });
  child.once("error", (error) => { console.error(error); process.exitCode = 1; });
  child.once("exit", (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    else process.exitCode = code ?? 1;
  });
} else {
writeFileSync(${JSON.stringify(serverPid)}, String(process.pid));
process.on("SIGUSR1", () => process.exit(7));
const send = (message) => process.stdout.write(JSON.stringify(message) + "\\n");
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (request.method === "config/read") send({ id: request.id, result: { config: {} } });
  else if (request.method === "thread/start") send({ id: request.id, result: { thread: { id: "synthetic" }, sandbox: { type: "workspaceWrite" } } });
  else if (request.method === "command/exec") send({ id: request.id, result: { exitCode: 0 } });
  else if (request.method === "turn/start") writeFileSync(${JSON.stringify(lateTurn)}, "unexpected");
  else if (request.id !== undefined) send({ id: request.id, result: {} });
}
}
`,
    );
    // This fixture exercises cancellation through its synthetic executor.
    // Native permission enforcement has separate integration coverage.
    const executor = join(root, "executor");
    const quoted = [process.execPath, server]
      .map((value) => `'${value.replaceAll("'", "'\\''")}'`)
      .join(" ");
    await writeFile(executor, `#!/bin/sh\nexec ${quoted} "$@"\n`, {
      mode: 0o755,
    });
    const wrapper = join(root, "wrapper.mts");
    await writeFile(
      wrapper,
      `
import { writeFileSync } from "node:fs";
import { runWorkflow, savedScan, resultWithFindings } from ${JSON.stringify(new URL("./cli-patch-fixtures.ts", import.meta.url).href)};
import { runCodexSkillCommand, runRepositoryCommand } from ${JSON.stringify(new URL("../src/cli.ts", import.meta.url).href)};
let snapshots = 0;
const outcome = await runWorkflow(${JSON.stringify(saved ? ["patch", "--scan", "scan-1", "--json"] : ["patch", "Synthetic issue", ...(preflight ? ["--create-pr"] : []), "--json"])}, {
  currentDirectory: ${JSON.stringify(repository)}, environment: { ...process.env, CODEX_HOME: ${JSON.stringify(home)}, CODEX_CLI_PATH: ${JSON.stringify(executor)} }, manualCodexPreparation: true,
  onWorkbench: () => savedScan(resultWithFindings(["high"]), "scan-1", ${JSON.stringify(repository)}),
  onCodex: (args, output, environment) => runCodexSkillCommand([${JSON.stringify(server)}], { ...output, auth: undefined }, { command: process.execPath }, environment),
  onRepositoryCommand: (command, args, cwd, options) => {
    if (command !== "git") return "[]";
    if (options?.sandbox && options.sandbox.environment.CODEX_CLI_PATH !== ${JSON.stringify(executor)})
      throw new Error("Cancellation fixture lost its synthetic executor.");
    if (options?.patchSnapshot && args.includes("write-tree") && ++snapshots === ${snapshotCount}) {
      writeFileSync(${JSON.stringify(ready)}, "ready");
      return runRepositoryCommand("git", ["hash-object", ${JSON.stringify(fifo)}], cwd, options);
    }
    return runRepositoryCommand(command, args, cwd, options);
  },
});
process.stdout.write(JSON.stringify({ ...outcome, snapshots }) + "\\n");
process.exitCode = outcome.exitCode;
`,
    );
    const invocation = spawn(process.execPath, [wrapper], {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let output = "",
      diagnostic = "";
    invocation.stdout.setEncoding("utf8").on("data", (chunk) => {
      output += chunk;
    });
    invocation.stderr.setEncoding("utf8").on("data", (chunk) => {
      diagnostic += chunk;
    });
    const closed = new Promise<number | null>((resolve, reject) => {
      invocation.once("error", reject);
      invocation.once("close", resolve);
    });
    let writer: number | undefined;
    try {
      const deadline = Date.now() + 10_000;
      while (writer === undefined) {
        try {
          await readFile(ready);
          writer = openSync(fifo, constants.O_WRONLY | constants.O_NONBLOCK);
        } catch (error) {
          if (Date.now() >= deadline || invocation.exitCode !== null)
            throw new Error(
              `Git snapshot did not reach its input: ${output}\n${diagnostic}`,
              { cause: error },
            );
          await delay(25);
        }
      }
      if (nativeExit) {
        process.kill(Number(await readFile(serverPid, "utf8")), "SIGUSR1");
      } else {
        invocation.kill("SIGTERM");
      }
      const status = await Promise.race([
        closed,
        delay(5_000).then(() => {
          throw new Error(
            `Cancelled CLI stayed alive: ${output}\n${diagnostic}`,
          );
        }),
      ]);
      expect(status, output + diagnostic).toBe(
        nativeExit ? (saved ? 2 : 7) : 143,
      );
      expect(JSON.parse(output.trim()).snapshots).toBe(snapshotCount);
      if (mode !== "app-server exit") {
        const response = JSON.parse(JSON.parse(output.trim()).stdout);
        expect(response).not.toHaveProperty("applied");
        expect(response).not.toHaveProperty("filesChanged");
        expect(response.error.message).toContain("not fully inspected");
      }
      let readerError: unknown;
      try {
        writeSync(writer!, "probe");
      } catch (error) {
        readerError = error;
      }
      expect(readerError).toMatchObject({ code: "EPIPE" });
      await expect(readFile(lateTurn)).rejects.toMatchObject({
        code: "ENOENT",
      });
      expect(await readFile(join(repository, "app.ts"), "utf8")).toBe(
        "original\n",
      );
    } finally {
      if (writer !== undefined) closeSync(writer);
      invocation.kill("SIGKILL");
      await closed;
    }
  },
  30_000,
);
