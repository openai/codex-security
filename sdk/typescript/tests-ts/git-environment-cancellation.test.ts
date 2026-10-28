import * as childProcess from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { delimiter, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, expect, spyOn, test } from "bun:test";
import { ScanInterruptedError } from "../src/index.js";
import { git } from "./git-fixture.js";
import { mockWorkbench, TestClient } from "./support/api-client.js";
import {
  preparedRuntime,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { nodeCommand, pythonExecutable } from "./support/shell.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

test.skipIf(process.platform === "win32")(
  "user cancellation stops private Git configuration inspection and its child",
  async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "home");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    await mkdir(scanDir, { mode: 0o700 });
    git(repository, "init", "-q");
    const selectedGit = Bun.which("git")!;
    const python = pythonExecutable()!;
    const block = join(root, "block");
    const ready = join(root, "ready");
    // The first projection registers the scan. The second is the per-operation
    // Codex launch, where the selected Git parser blocks until user cancellation.
    await writeFile(
      join(root, "git"),
      `#!${nodeCommand().command}
const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const args = process.argv.slice(2);
if (args.includes("--no-includes") && fs.existsSync(${JSON.stringify(block)})) {
  fs.writeFileSync(${JSON.stringify(ready)}, String(process.pid));
  setInterval(() => {}, 1000);
} else {
  const child = spawnSync(${JSON.stringify(selectedGit)}, args, {
    env: { ...process.env, PATH: ${JSON.stringify(process.env["PATH"])} },
    stdio: "inherit",
  });
  process.exit(child.status ?? 1);
}
`,
      { mode: 0o700 },
    );
    const environment = {
      PATH: `${root}${delimiter}${process.env["PATH"]}`,
      HOME: process.env["HOME"],
      GIT_CONFIG_PARAMETERS: "'http.extraHeader=synthetic-private-header'",
    };
    const controller = new AbortController();
    const deadline = new AbortController();
    const bounded = <T>(operation: Promise<T>): Promise<T> =>
      Promise.race([
        operation,
        delay(5000, undefined, { signal: deadline.signal }).then(() => {
          throw new Error("Git inspection did not settle after cancellation");
        }),
      ]);
    const until = async (condition: () => boolean) => {
      while (!condition())
        await delay(10, undefined, { signal: deadline.signal });
    };
    const alive = (pid: number) => {
      try {
        process.kill(pid, 0);
        return true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
        throw error;
      }
    };
    let child: childProcess.ChildProcess | undefined;
    let childSignal: AbortSignal | null | undefined;
    let gitPid: number | undefined;
    const closed = Promise.withResolvers<void>();
    const originalSpawn = childProcess.spawn;
    const observer = spyOn(childProcess, "spawn").mockImplementation(((
      ...args: Parameters<typeof originalSpawn>
    ) => {
      const spawned = originalSpawn(...args);
      if (
        existsSync(block) &&
        (args[1] as readonly string[]).some((argument) =>
          argument.includes(
            "from workbench_target import git_inspection_environment",
          ),
        )
      ) {
        child = spawned;
        childSignal = (args[2] as childProcess.SpawnOptions).signal;
        spawned.once("close", () => closed.resolve());
      }
      return spawned;
    }) as typeof originalSpawn);
    const client = new TestClient(
      {},
      {
        ...scanRuntimeDependencies(codexHome, scanDir),
        environment,
        resolvePluginPython: async () => python,
        prepareRuntime: async () => ({
          ...preparedRuntime(codexHome),
          environment: Object.fromEntries(
            Object.entries(environment).filter(
              (entry): entry is [string, string] => entry[1] !== undefined,
            ),
          ),
        }),
        runWorkbench: async (_options, args, input) => {
          if (args[0] === "register-cli-scan") await writeFile(block, "ready");
          return mockWorkbench(args, input);
        },
      },
    );
    const outcome = client.run(repository, { signal: controller.signal }).then(
      () => undefined,
      (error: unknown) => error,
    );
    try {
      await bounded(
        Promise.race([
          until(() => existsSync(ready)),
          outcome.then((error) => {
            throw error ?? new Error("Git parser did not start");
          }),
        ]),
      );
      gitPid = Number(await readFile(ready, "utf8"));
      expect(child).toBeDefined();
      expect(childSignal?.aborted).toBe(false);
      expect(alive(gitPid)).toBe(true);
      const reason = new Error("synthetic user cancellation");
      controller.abort(reason);
      expect(await bounded(outcome)).toBeInstanceOf(ScanInterruptedError);
      expect(childSignal?.aborted).toBe(true);
      expect(childSignal?.reason).toBe(reason);
      await bounded(closed.promise);
      await bounded(until(() => !alive(gitPid!)));
      expect(child!.exitCode !== null || child!.signalCode !== null).toBe(true);
    } finally {
      controller.abort();
      observer.mockRestore();
      child?.kill("SIGKILL");
      if (gitPid !== undefined && alive(gitPid))
        process.kill(gitPid, "SIGKILL");
      await bounded(outcome);
      await client.close();
      deadline.abort();
    }
  },
);
