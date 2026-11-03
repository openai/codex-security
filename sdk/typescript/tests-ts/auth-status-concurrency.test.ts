import { existsSync } from "node:fs";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, mock, test } from "bun:test";
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
        await fs.writeFile(credentials, '{"auth_mode":"chatgpt"}\n', {
          mode: 0o600,
        });
      }
      const removeCredentials = async (): Promise<void> => {
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

for (const [signal, status] of [
  ["SIGINT", 130],
  ["SIGTERM", 143],
] as const) {
  const name = `exploitability check exits on ${signal} while waiting for the credential-home lock`;
  test(name, async () => {
    if (runTestInSubprocess(import.meta.filename, name)) return;
    const { scopedTemporaryDirectory } =
      await import("./support/temporary-directories.js");
    await using temp = await scopedTemporaryDirectory(
      "codex-security-skill-lock-",
    );
    const repository = join(temp.path, "checkout");
    await fs.mkdir(repository);
    const environment = {
      CODEX_HOME: join(temp.path, "ambient"),
      CODEX_SECURITY_STATE_DIR: join(temp.path, "state"),
    };
    const runtime = await import("../src/runtime.js");
    const home = await runtime.prepareCodexSecurityCredentialHome(environment);
    const release = await runtime.acquireCodexSecurityCredentialHomeLock(home);
    const waiting = Promise.withResolvers<AbortSignal | undefined>();
    const timers = { ...(await import("node:timers/promises")) };
    mock.module("node:timers/promises", () => ({
      ...timers,
      setTimeout: (...args: Parameters<typeof timers.setTimeout>) => {
        const poll = timers.setTimeout(...args);
        waiting.resolve(args[2]?.signal);
        return poll;
      },
    }));

    const { main, runCodexSkillCommand } = await import("../src/cli.js");
    const { capture, dependencies, FakeSignals } =
      await import("./cli-fixtures.js");
    const signals = new FakeSignals();
    const started = join(temp.path, "skill-started");
    const deps = dependencies({
      currentDirectory: repository,
      environment,
      signals,
      onCodex: (_args, output) =>
        runCodexSkillCommand(
          [
            "-e",
            `require("node:fs").writeFileSync(${JSON.stringify(started)}, "")`,
          ],
          output,
          { command: process.execPath },
          environment,
        ),
    });
    let lookupSignal: AbortSignal | undefined;
    deps.lookupDependencyAdvisory = async (cve, signal) => {
      lookupSignal = signal;
      return { cve, advisories: [] };
    };
    const stdout = capture();
    const stderr = capture();
    const pending = main(
      ["exploitability", "check", "CVE-2024-1000", "--json"],
      stdout.stream,
      stderr.stream,
      deps,
    );
    try {
      const lockSignal = await Promise.race([
        waiting.promise,
        pending.then((code) => {
          throw new Error(`Exited ${code} before waiting: ${stderr.text()}`);
        }),
      ]);
      expect(lockSignal).toBe(lookupSignal);
      signals.emit(signal);
      expect(await pending).toBe(status);
      expect(existsSync(started)).toBe(false);
      expect(stdout.text()).toBe("");
    } finally {
      await release();
      await pending;
    }
  });
}
