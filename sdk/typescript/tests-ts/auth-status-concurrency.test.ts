import * as childProcess from "node:child_process";
import { existsSync } from "node:fs";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, mock, spyOn, test } from "bun:test";
import type { JsonObject } from "../src/index.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

for (const surface of ["CLI", "SDK"] as const) {
  for (const first of ["status", "logout"] as const) {
    const name = `${surface} keeps credentials removed when ${first} starts before a concurrent ${first === "status" ? "logout" : "status"}`;
    test(name, async () => {
      if (runTestInSubprocess(import.meta.filename, name)) return;

      const originalFs = { ...fs };
      const root = await fs.realpath(
        await fs.mkdtemp(join(tmpdir(), "codex-security-auth-concurrency-")),
      );
      const ambientHome = join(root, "ambient");
      const source = join(ambientHome, "auth.json");
      await fs.mkdir(ambientHome, { mode: 0o700 });
      await fs.writeFile(source, '{"auth_mode":"chatgpt"}\n', { mode: 0o600 });
      const paused = Promise.withResolvers<void>();
      const resume = Promise.withResolvers<void>();
      const contending = Promise.withResolvers<void>();
      let reachedPause = false;
      mock.module("node:fs/promises", () => ({
        ...originalFs,
        copyFile: async (...args: Parameters<typeof fs.copyFile>) => {
          if (first === "status" && String(args[0]) === source) {
            reachedPause = true;
            paused.resolve();
            await resume.promise;
          }
          return await originalFs.copyFile(...args);
        },
      }));
      const runtime = { ...(await import("../src/runtime.js")) };
      let lockRequests = 0;
      mock.module("../src/runtime.js", () => ({
        ...runtime,
        withCredentialHomeLock: (
          ...args: Parameters<typeof runtime.withCredentialHomeLock>
        ) => {
          if (++lockRequests === 2) contending.resolve();
          return runtime.withCredentialHomeLock(...args);
        },
      }));
      const environment = {
        CODEX_HOME: ambientHome,
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      };
      const home =
        await runtime.prepareCodexSecurityCredentialHome(environment);
      const credentials = join(home, "auth.json");
      if (first === "logout") {
        await fs.link(source, credentials);
      }
      const removeCredentials = async (): Promise<void> => {
        if (first === "logout") expect(existsSync(credentials)).toBe(false);
        await fs.rm(credentials, { force: true });
        if (first === "logout") {
          reachedPause = true;
          paused.resolve();
          await resume.promise;
        }
      };
      let operations: Record<"status" | "logout", () => Promise<unknown>>;
      const clients: Array<{ close(): Promise<void> }> = [];
      if (surface === "CLI") {
        const { main } = await import("../src/cli.js");
        const { capture, dependencies } = await import("./cli-fixtures.js");
        const run = async (args: string[]): Promise<number> =>
          await main(args, capture().stream, capture().stream, {
            ...dependencies({ environment }),
            runCodex: async (command) => {
              if (command[0] === "logout") {
                await removeCredentials();
                return 0;
              }
              return existsSync(credentials) ? 0 : 1;
            },
          });
        operations = {
          status: async () => {
            expect([0, 1]).toContain(await run(["login", "status"]));
          },
          logout: async () => {
            expect(await run(["logout"])).toBe(0);
          },
        };
      } else {
        const auth = { ...(await import("../src/auth.js")) };
        mock.module("../src/auth.js", () => ({
          ...auth,
          accountStatus: async () => ({
            authenticated: existsSync(credentials),
            details: "Synthetic credential status",
          }),
          logout: removeCredentials,
        }));
        const { TestClient } = await import("./support/api-client.js");
        const createClient = () =>
          new TestClient(
            {},
            {
              environment,
              resolveCodexCommand: () => ({ command: process.execPath }),
            },
          );
        const statusClient = createClient();
        const logoutClient = createClient();
        clients.push(statusClient, logoutClient);
        operations = {
          status: () => statusClient.account(),
          logout: () => logoutClient.logout(),
        };
      }
      let firstOperation: Promise<unknown> | undefined;
      let secondOperation: Promise<unknown> | undefined;
      try {
        firstOperation = operations[first]();
        await Promise.race([paused.promise, firstOperation]);
        expect(reachedPause).toBe(true);
        secondOperation =
          operations[first === "status" ? "logout" : "status"]();
        // Continue once the other operation finishes or queues for the lock,
        // without depending on a particular scheduler delay.
        await Promise.race([secondOperation, contending.promise]);
        resume.resolve();
        await Promise.all([firstOperation, secondOperation]);
        expect(existsSync(credentials)).toBe(false);
        expect(await fs.readFile(source, "utf8")).toBe(
          '{"auth_mode":"chatgpt"}\n',
        );
        expect(
          await runtime.codexSecurityCredentialAllowsAmbientImport(home),
        ).toBe(false);
      } finally {
        resume.resolve();
        await Promise.allSettled([firstOperation, secondOperation]);
        await Promise.all(clients.map((client) => client.close()));
        await fs.rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const operation of ["account", "logout"] as const) {
  const name = `SDK close cancels ${operation} waiting for the credential-home lock`;
  test(name, async () => {
    if (runTestInSubprocess(import.meta.filename, name)) return;

    const root = await fs.realpath(
      await fs.mkdtemp(join(tmpdir(), "codex-security-auth-cancel-")),
    );
    const environment = {
      CODEX_HOME: join(root, "ambient"),
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    };
    const runtime = { ...(await import("../src/runtime.js")) };
    const home = await runtime.prepareCodexSecurityCredentialHome(environment);
    const release = await runtime.acquireCodexSecurityCredentialHomeLock(home);
    const waiting = Promise.withResolvers<void>();
    mock.module("../src/runtime.js", () => ({
      ...runtime,
      withCredentialHomeLock: (
        ...args: Parameters<typeof runtime.withCredentialHomeLock>
      ) => {
        waiting.resolve();
        return runtime.withCredentialHomeLock(...args);
      },
    }));
    const { TestClient } = await import("./support/api-client.js");
    const client = new TestClient(
      {},
      {
        environment,
        resolveCodexCommand: () => {
          throw new Error("Must not invoke Codex while waiting for the lock");
        },
      },
    );
    const pending = client[operation]();
    const outcome = pending.catch((error: unknown) => error);
    try {
      await Promise.race([waiting.promise, pending]);
      await client.close();
      expect(await outcome).toMatchObject({ name: "AbortError" });
    } finally {
      await release();
      await client.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });
}

const verificationAbort =
  "batched verification cancels stored authentication before starting a worker";
test(verificationAbort, async () => {
  if (runTestInSubprocess(import.meta.filename, verificationAbort)) return;

  const root = await fs.realpath(
    await fs.mkdtemp(join(tmpdir(), "verify-auth-")),
  );
  const directory = join(root, "repository");
  const environment = {
    CODEX_HOME: join(root, "ambient"),
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const signals: Array<AbortSignal | undefined> = [];
  const targets = { ...(await import("../src/targets.js")) };
  const runtime = { ...(await import("../src/runtime.js")) };
  mock.module("../src/targets.js", () => ({
    ...targets,
    enclosingGitWorktreeRoots: async (
      _directory: string,
      signal?: AbortSignal,
    ) => {
      signals.push(signal);
      return [];
    },
  }));
  mock.module("../src/runtime.js", () => ({
    ...runtime,
    acquireCodexSecurityCredentialHomeLock: (
      ...args: Parameters<typeof runtime.acquireCodexSecurityCredentialHomeLock>
    ) => {
      signals.push(args[1]);
      return runtime.acquireCodexSecurityCredentialHomeLock(...args);
    },
  }));
  const probeSource =
    "if (process.argv.slice(-2).join(' ') !== 'login status') process.exit(1); " +
    // Acknowledge the first interrupt with a second real signal while the probe is still running.
    "process.on('SIGTERM', () => process.kill(process.ppid, 'SIGTERM')); " +
    "process.stdout.write('ready'); setTimeout(() => process.exit(1), 4_000);";
  const start = childProcess.spawn;
  const probes: childProcess.ChildProcess[] = [];
  using spawns = spyOn(childProcess, "spawn").mockImplementation(((
    ...args: Parameters<typeof start>
  ) => {
    const child = start(...args);
    const argv = args[1];
    if (
      !Array.isArray(argv) ||
      argv[1] !== probeSource ||
      argv.at(-2) !== "login" ||
      argv.at(-1) !== "status"
    )
      return child;
    probes.push(child);
    child.stdout!.once("data", () => {
      if (process.platform === "win32") process.emit("SIGINT");
      else process.kill(process.pid, "SIGINT");
    });
    return child;
  }) as typeof start);
  try {
    await fs.mkdir(directory);
    const { main, runCodexSkillCommand } = await import("../src/cli.js");
    const { capture, dependencies, fakeResult } =
      await import("./cli-fixtures.js");
    const result = fakeResult(["high", "high"]);
    result.findings.findings.forEach((finding, index) => {
      Object.assign(finding, {
        occurrenceId: `occ_${index}`,
        findingId: `csf_${index}`,
        codeEvidence: [{ path: "source.ts", code: "a".repeat(600_000) }],
      });
    });
    const deps = dependencies({
      result,
      environment,
      onWorkbench: () => ({
        scan: {
          scanId: "scan",
          targetPath: directory,
          findings: result.findings.findings as unknown as JsonObject[],
        },
      }),
      onCodex: (args, output) =>
        runCodexSkillCommand(
          args,
          output,
          {
            command: process.execPath,
            args: ["-e", probeSource, "--"],
          },
          environment,
        ),
    });
    const runCodex = mock(deps.runCodex);
    const stdout = capture();
    const stderr = capture();
    const exit = await main(
      ["verify-fix", "--scan", "scan", "--auth", "chatgpt", "--json"],
      stdout.stream,
      stderr.stream,
      {
        ...deps,
        runCodex,
        addSignalListener: (signal, listener) => process.on(signal, listener),
        removeSignalListener: (signal, listener) =>
          process.off(signal, listener),
      },
    );
    expect(exit, stdout.text() + stderr.text()).toBe(130);
    expect(signals).toEqual([signals[0], signals[0]]);
    expect(signals[0]?.reason).toBe("SIGINT");
    expect(runCodex).toHaveBeenCalledTimes(1);
    expect(probes).toHaveLength(1);
    expect(
      spawns.mock.calls.some(
        ([, argv]) => Array.isArray(argv) && argv[0] === "app-server",
      ),
    ).toBe(false);
    if (process.platform !== "win32")
      expect(probes[0]!.signalCode).toBe("SIGKILL");
    const home = await runtime.prepareCodexSecurityCredentialHome(environment);
    const release = await runtime.acquireCodexSecurityCredentialHomeLock(home);
    await release();
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
