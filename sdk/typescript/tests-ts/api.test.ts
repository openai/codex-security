import {
  cp,
  mkdir,
  mkdtemp,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { CodexOptions, ThreadEvent } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import {
  AuthenticationRequiredError,
  CodexSecurity,
  InvalidTargetError,
  OutputDirectoryError,
  type ScanEvent,
  ScanHandle,
  ScanInterruptedError,
  UnsupportedCodexSdkCapabilityError,
} from "../src/index.js";
import { initialCredentialsAvailable } from "../src/api.js";
import { INTEGRATION_TARGET, PLUGIN_ROOT } from "./plugin-root.js";

const REPOSITORY_ROOT = fileURLToPath(new URL("../../..", import.meta.url));
const EXAMPLE = join(PLUGIN_ROOT, "examples", "completed-scan");
const temporaryDirectories: string[] = [];
const TestClient = CodexSecurity as unknown as new (
  config: Record<string, unknown>,
  dependencies: Record<string, unknown>,
) => CodexSecurity;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-api-")),
  );
  temporaryDirectories.push(path);
  return path;
}

async function copyCompletedScan(root: string): Promise<string> {
  const scanDir = join(root, "scan");
  await cp(EXAMPLE, scanDir, { recursive: true });
  await writeFile(join(scanDir, "report.md"), "# Scan report\n");
  return scanDir;
}

async function* completedEvents(): AsyncGenerator<ThreadEvent> {
  yield { type: "thread.started", thread_id: "thread-1" };
  yield { type: "turn.started" };
  yield {
    type: "item.completed",
    item: { id: "message-1", type: "agent_message", text: "scan complete" },
  };
  yield {
    type: "turn.completed",
    usage: {
      input_tokens: 10,
      cached_input_tokens: 2,
      output_tokens: 3,
      reasoning_output_tokens: 1,
    },
  };
}

function scanHandle(
  scanDir: string,
  events: AsyncGenerator<ThreadEvent>,
  abortController = new AbortController(),
  replayEvents = true,
): ScanHandle {
  return new ScanHandle({
    thread: {
      id: null,
      async runStreamed() {
        return { events };
      },
    },
    events,
    abortController,
    scanDir,
    pluginRoot: PLUGIN_ROOT,
    replayEvents,
    expectation: {
      repository: "/repository",
      repositoryRevision: "deadbeef",
      target: { kind: "repository", paths: [] },
      mode: "standard",
      pluginVersion: "0.1.0",
    },
    onSettled() {},
  });
}

function preparedRuntime(codexHome: string): Record<string, unknown> {
  return {
    codexHome,
    plugin: {
      pluginRoot: PLUGIN_ROOT,
      marketplaceRoot: PLUGIN_ROOT,
      installedRoot: PLUGIN_ROOT,
      marketplaceName: "codex-security-sdk",
      name: "codex-security",
      version: "0.1.0",
    },
    environment: {},
    credentialsAvailable: true,
  };
}

describe("ScanHandle", () => {
  test("replays streamed events and validates completed scan artifacts", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const handle = scanHandle(scanDir, completedEvents());

    const result = await handle.run();
    const events: ScanEvent[] = [];
    for await (const event of handle.stream()) events.push(event);

    expect(events.map((event) => event.type)).toEqual([
      "thread.started",
      "turn.started",
      "item.completed",
      "turn.completed",
    ]);
    expect(handle.threadId).toBe("thread-1");
    expect(result.threadId).toBe("thread-1");
    expect(result.turnResult).toMatchObject({
      status: "completed",
      finalResponse: "scan complete",
    });
  });

  test("retains partial output and reports interruption", async () => {
    const root = await temporaryDirectory();
    const scanDir = join(root, "partial-scan");
    await mkdir(scanDir);
    const abortController = new AbortController();
    async function* interruptedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-2" };
      await new Promise<void>((resolve) => {
        if (abortController.signal.aborted) resolve();
        else
          abortController.signal.addEventListener("abort", () => resolve(), {
            once: true,
          });
      });
      throw new DOMException("aborted", "AbortError");
    }
    const handle = scanHandle(scanDir, interruptedEvents(), abortController);

    handle.interrupt();
    await expect(handle.run()).rejects.toMatchObject({
      name: ScanInterruptedError.name,
      scanDir,
    });
    expect(
      await import("node:fs/promises").then(({ stat }) => stat(scanDir)),
    ).toBeDefined();
  });

  test("can avoid retaining event history for one-shot scans", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const handle = scanHandle(
      scanDir,
      completedEvents(),
      new AbortController(),
      false,
    );
    await expect(handle.run()).resolves.toBeDefined();
    const events: ScanEvent[] = [];
    for await (const event of handle.stream()) events.push(event);
    expect(events).toEqual([]);
  });

  test("reports the public SDK steering capability gap", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const handle = scanHandle(scanDir, completedEvents());
    await expect(handle.steer("focus on auth")).rejects.toBeInstanceOf(
      UnsupportedCodexSdkCapabilityError,
    );
    await handle.run();
  });
});

describe("CodexSecurity orchestration", () => {
  test("selects a real-scan target in the active repository layout", async () => {
    await expect(
      stat(join(REPOSITORY_ROOT, INTEGRATION_TARGET)),
    ).resolves.toBeDefined();
  });

  test("validates local inputs before runtime or plugin Python discovery", async () => {
    const client = new CodexSecurity({
      pythonPath: "/definitely/missing/python",
    });
    await expect(
      client.turn("/definitely/missing/repository"),
    ).rejects.toBeInstanceOf(InvalidTargetError);
    await client.close();
  });

  test("rejects scan output inside the repository before runtime initialization", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    let runtimeStarted = false;
    const client = new TestClient(
      {},
      {
        environment: {},
        prepareRuntime: async () => {
          runtimeStarted = true;
          throw new Error("runtime should not initialize");
        },
      },
    );

    await expect(
      client.turn(repository, { outputDir: join(repository, "scan") }),
    ).rejects.toBeInstanceOf(OutputDirectoryError);
    if (process.platform !== "win32") {
      const linkedRepository = join(root, "linked-repository");
      await symlink(repository, linkedRepository);
      await expect(
        client.turn(repository, {
          outputDir: join(linkedRepository, "scan"),
        }),
      ).rejects.toBeInstanceOf(OutputDirectoryError);
    }
    expect(runtimeStarted).toBe(false);
    await client.close();
  });

  test("rejects output inside an enclosing Git worktree before runtime initialization", async () => {
    for (const markerKind of ["directory", "file", "symlink"] as const) {
      const root = await temporaryDirectory();
      const worktree = join(root, "worktree");
      const repository = join(worktree, "packages", "service");
      const output = join(worktree, "scan");
      await mkdir(repository, { recursive: true });
      if (markerKind === "directory") await mkdir(join(worktree, ".git"));
      else if (markerKind === "file") {
        await writeFile(join(worktree, ".git"), "gitdir: ../metadata\n");
      } else if (process.platform !== "win32") {
        await mkdir(join(root, "metadata"));
        await symlink(join(root, "metadata"), join(worktree, ".git"));
      } else {
        continue;
      }
      let runtimeStarted = false;
      const client = new TestClient(
        {},
        {
          environment: {},
          prepareRuntime: async () => {
            runtimeStarted = true;
            throw new Error("runtime should not initialize");
          },
        },
      );

      await expect(
        client.turn(repository, { outputDir: output }),
      ).rejects.toBeInstanceOf(OutputDirectoryError);
      expect(runtimeStarted).toBe(false);
      await expect(stat(output)).rejects.toThrow();
      await client.close();
    }
  });

  test("rejects a repository-local temporary root before runtime initialization", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const temporaryRoot = join(repository, "tmp");
    await mkdir(temporaryRoot, { recursive: true });
    const temporaryVariable = process.platform === "win32" ? "TEMP" : "TMPDIR";
    const previous = process.env[temporaryVariable];
    process.env[temporaryVariable] = temporaryRoot;
    let runtimeStarted = false;
    const client = new TestClient(
      {},
      {
        environment: {},
        prepareRuntime: async () => {
          runtimeStarted = true;
          throw new Error("runtime should not initialize");
        },
      },
    );

    try {
      await expect(client.turn(repository)).rejects.toBeInstanceOf(
        OutputDirectoryError,
      );
      expect(runtimeStarted).toBe(false);
    } finally {
      if (previous === undefined) delete process.env[temporaryVariable];
      else process.env[temporaryVariable] = previous;
      await client.close();
    }
  });

  test("rejects a repository replaced during runtime initialization", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const movedRepository = join(root, "moved-repository");
    const codexHome = join(root, "codex-home");
    const output = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    const client = new TestClient(
      {},
      {
        environment: {},
        prepareRuntime: async () => {
          await rename(repository, movedRepository);
          await mkdir(repository);
          return preparedRuntime(codexHome);
        },
        resolvePluginPython: async () => "/managed/python",
      },
    );

    await expect(
      client.turn(repository, { outputDir: output }),
    ).rejects.toBeInstanceOf(InvalidTargetError);
    await expect(stat(output)).rejects.toThrow();
    await client.close();
  });

  test("keeps a relative repository stable if runtime initialization changes cwd", async () => {
    const root = await temporaryDirectory();
    const initial = join(root, "initial");
    const elsewhere = join(root, "elsewhere");
    const repository = join(initial, "repository");
    const codexHome = join(root, "codex-home");
    const output = join(root, "scan");
    await mkdir(repository, { recursive: true });
    await mkdir(elsewhere);
    await mkdir(codexHome);
    const originalCwd = process.cwd();
    process.chdir(initial);
    const client = new TestClient(
      {},
      {
        environment: {},
        prepareRuntime: async () => {
          process.chdir(elsewhere);
          return preparedRuntime(codexHome);
        },
        resolvePluginPython: async () => "/managed/python",
        repositoryRevision: async () => null,
        createCodex: () => {
          throw new Error("Codex reached");
        },
      },
    );

    try {
      await expect(
        client.turn("repository", { outputDir: output }),
      ).rejects.toThrow("Codex reached");
    } finally {
      process.chdir(originalCwd);
      await client.close();
    }
  });

  test("rejects a path target replaced during scan preparation", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const target = join(repository, "target.ts");
    const output = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    await writeFile(target, "original\n");
    let runStarted = false;
    const client = new TestClient(
      {},
      {
        environment: {},
        prepareRuntime: async () => preparedRuntime(codexHome),
        resolvePluginPython: async () => {
          await rename(target, `${target}.moved`);
          await writeFile(target, "replacement\n");
          return "/managed/python";
        },
        repositoryRevision: async () => null,
        createCodex: () => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              runStarted = true;
              return { events: completedEvents() };
            },
          }),
        }),
      },
    );

    await expect(
      client.turn(repository, { target: ["target.ts"], outputDir: output }),
    ).rejects.toBeInstanceOf(InvalidTargetError);
    expect(runStarted).toBe(false);
    await client.close();
  });

  test("rejects output populated or retargeted during scan preparation", async () => {
    if (process.platform === "win32") return;
    for (const mutation of ["populate", "retarget"] as const) {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const codexHome = join(root, "codex-home");
      const output = join(root, "scan");
      await mkdir(repository);
      await mkdir(codexHome);
      await mkdir(output);
      let runStarted = false;
      const client = new TestClient(
        {},
        {
          environment: {},
          prepareRuntime: async () => preparedRuntime(codexHome),
          resolvePluginPython: async () => "/managed/python",
          prepareOutputDir: async () => output,
          repositoryRevision: async () => {
            if (mutation === "populate") {
              await writeFile(join(output, "unexpected"), "x");
            } else {
              await rename(output, `${output}.moved`);
              await symlink(repository, output);
            }
            return null;
          },
          createCodex: () => ({
            startThread: () => ({
              id: null,
              async runStreamed() {
                runStarted = true;
                return { events: completedEvents() };
              },
            }),
          }),
        },
      );

      await expect(
        client.turn(repository, { outputDir: output }),
      ).rejects.toBeInstanceOf(OutputDirectoryError);
      expect(runStarted).toBe(false);
      await client.close();
    }
  });

  test("rejects a runtime home retargeted during scan preparation", async () => {
    if (process.platform === "win32") return;
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const output = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    let runStarted = false;
    const client = new TestClient(
      {},
      {
        environment: {},
        prepareRuntime: async () => preparedRuntime(codexHome),
        resolvePluginPython: async () => {
          await rename(codexHome, `${codexHome}.moved`);
          await symlink(repository, codexHome);
          return "/managed/python";
        },
        repositoryRevision: async () => null,
        createCodex: () => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              runStarted = true;
              return { events: completedEvents() };
            },
          }),
        }),
      },
    );

    await expect(
      client.turn(repository, { outputDir: output }),
    ).rejects.toBeInstanceOf(OutputDirectoryError);
    expect(runStarted).toBe(false);
    await client.close();
  });

  test("uses deterministic Codex doubles and forwards Python only to plugin execution", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    await mkdir(repository);
    await mkdir(codexHome);
    const scanDir = join(root, "scan");
    await mkdir(scanDir);
    let codexOptions: CodexOptions | null = null;
    let prompt = "";

    const TestClient = CodexSecurity as unknown as new (
      config: Record<string, unknown>,
      dependencies: Record<string, unknown>,
    ) => CodexSecurity;
    const client = new TestClient(
      {},
      {
        environment: { PATH: "/usr/bin", OPENAI_API_KEY: "" },
        prepareRuntime: async () => ({
          codexHome,
          plugin: {
            pluginRoot: PLUGIN_ROOT,
            marketplaceRoot: root,
            installedRoot: PLUGIN_ROOT,
            marketplaceName: "codex-security-sdk",
            name: "codex-security",
            version: "0.1.0",
          },
          environment: { CODEX_HOME: codexHome, PATH: "/usr/bin" },
          credentialsAvailable: true,
        }),
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options: CodexOptions) => {
          codexOptions = options;
          return {
            startThread: () => ({
              id: null,
              async runStreamed(input: string) {
                prompt = input;
                await copyCompletedScan(root);
                return { events: completedEvents() };
              },
            }),
          };
        },
      },
    );

    const result = await client.run(repository);
    expect(result.threadId).toBe("thread-1");
    expect((codexOptions as CodexOptions | null)?.env).toMatchObject({
      CODEX_HOME: codexHome,
      PYTHON: "/managed/python",
    });
    expect((codexOptions as CodexOptions | null)?.apiKey).toBeUndefined();
    expect(prompt).toContain("$codex-security:security-scan");
    expect(prompt).toContain(`Repository root: ${repository}`);
    expect(prompt).toContain(
      'Use "/managed/python" as <python_command> for every plugin helper',
    );
    await client.close();
  });

  test("reports effective ambient API-key authentication", async () => {
    const root = await temporaryDirectory();
    const codexHome = join(root, "codex-home");
    await mkdir(codexHome);
    const TestClient = CodexSecurity as unknown as new (
      config: Record<string, unknown>,
      dependencies: Record<string, unknown>,
    ) => CodexSecurity;
    const client = new TestClient(
      {},
      {
        environment: { OPENAI_API_KEY: "ambient-key" },
        prepareRuntime: async () => ({
          codexHome,
          plugin: {
            pluginRoot: PLUGIN_ROOT,
            marketplaceRoot: PLUGIN_ROOT,
            installedRoot: PLUGIN_ROOT,
            marketplaceName: "codex-security-sdk",
            name: "codex-security",
            version: "0.1.0",
          },
          environment: { CODEX_HOME: codexHome },
          credentialsAvailable: true,
        }),
        createCodex: () => {
          throw new Error("not used");
        },
      },
    );
    await expect(client.account()).resolves.toEqual({
      authenticated: true,
      details: "Authenticated with an API key.",
    });
    await expect(client.account({ refreshToken: true })).rejects.toBeInstanceOf(
      UnsupportedCodexSdkCapabilityError,
    );
    await client.close();
  });

  test("persists an ambient API key without exposing it to scan commands", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const fakeCodex = join(root, "codex.mjs");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    await mkdir(scanDir);
    await writeFile(
      fakeCodex,
      `
if (process.argv.slice(2).join(" ") !== "login --with-api-key") {
  process.exitCode = 2;
} else {
  for await (const _chunk of process.stdin) {}
}
`,
    );
    let codexOptions: CodexOptions | null = null;
    let pythonEnvironment: Record<string, string | undefined> | undefined;
    const TestClient = CodexSecurity as unknown as new (
      config: Record<string, unknown>,
      dependencies: Record<string, unknown>,
    ) => CodexSecurity;
    const client = new TestClient(
      {},
      {
        environment: {
          openai_api_key: "ambient-key",
          Codex_Api_Key: "secondary-key",
        },
        prepareRuntime: async () => ({
          codexHome,
          plugin: {
            pluginRoot: PLUGIN_ROOT,
            marketplaceRoot: PLUGIN_ROOT,
            installedRoot: PLUGIN_ROOT,
            marketplaceName: "codex-security-sdk",
            name: "codex-security",
            version: "0.1.0",
          },
          environment: {
            CODEX_HOME: codexHome,
            OpenAi_Api_Key: "must-not-reach-a-child",
            codex_api_key: "must-not-reach-a-child",
          },
          credentialsAvailable: false,
        }),
        resolveCodexCommand: () => ({
          command: process.execPath,
          prefixArgs: [fakeCodex],
        }),
        resolvePluginPython: async (options: {
          environment?: Record<string, string | undefined>;
        }) => {
          pythonEnvironment = options.environment;
          return "/managed/python";
        },
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options: CodexOptions) => {
          codexOptions = options;
          return {
            startThread: () => ({
              id: null,
              async runStreamed() {
                await copyCompletedScan(root);
                return { events: completedEvents() };
              },
            }),
          };
        },
      },
    );

    await client.run(repository);
    expect((codexOptions as CodexOptions | null)?.apiKey).toBeUndefined();
    expect(
      (codexOptions as CodexOptions | null)?.codexPathOverride,
    ).toBeUndefined();
    expect(
      Object.keys((codexOptions as CodexOptions | null)?.env ?? {}).some(
        (name) =>
          name.toUpperCase() === "OPENAI_API_KEY" ||
          name.toUpperCase() === "CODEX_API_KEY",
      ),
    ).toBe(false);
    expect(
      Object.keys(pythonEnvironment ?? {}).some(
        (name) =>
          name.toUpperCase() === "OPENAI_API_KEY" ||
          name.toUpperCase() === "CODEX_API_KEY",
      ),
    ).toBe(false);
    await client.close();
  });

  test("does not cache an environment key as reusable file authentication", async () => {
    let imported = false;
    await expect(
      initialCredentialsAvailable(
        { OPENAI_API_KEY: "ambient-key" },
        "/unreadable/ambient-home",
        "/isolated-home",
        async () => {
          imported = true;
          throw new Error("ambient auth must not be inspected");
        },
      ),
    ).resolves.toBe(false);
    expect(imported).toBe(false);
  });

  test("revalidates an environment-only key before starting a scan", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    await mkdir(repository);
    await mkdir(codexHome);
    const environment: Record<string, string | undefined> = {
      openai_api_key: "ambient-key",
    };
    const TestClient = CodexSecurity as unknown as new (
      config: Record<string, unknown>,
      dependencies: Record<string, unknown>,
    ) => CodexSecurity;
    const client = new TestClient(
      {},
      {
        environment,
        prepareRuntime: async () => ({
          codexHome,
          plugin: {
            pluginRoot: PLUGIN_ROOT,
            marketplaceRoot: PLUGIN_ROOT,
            installedRoot: PLUGIN_ROOT,
            marketplaceName: "codex-security-sdk",
            name: "codex-security",
            version: "0.1.0",
          },
          environment: { CODEX_HOME: codexHome },
          credentialsAvailable: false,
        }),
        createCodex: () => {
          throw new Error("must not start Codex without credentials");
        },
      },
    );

    await expect(client.account()).resolves.toMatchObject({
      authenticated: true,
    });
    delete environment["openai_api_key"];
    await expect(client.run(repository)).rejects.toBeInstanceOf(
      AuthenticationRequiredError,
    );
    await client.close();
  });

  test("does not continue a turn when close wins a runtime initialization race", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    await mkdir(repository);
    await mkdir(codexHome);
    let releaseRuntime!: (runtime: Record<string, unknown>) => void;
    let preparationStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      preparationStarted = resolve;
    });
    const prepared = new Promise<Record<string, unknown>>((resolve) => {
      releaseRuntime = resolve;
    });
    let createCodexCalled = false;
    const TestClient = CodexSecurity as unknown as new (
      config: Record<string, unknown>,
      dependencies: Record<string, unknown>,
    ) => CodexSecurity;
    const client = new TestClient(
      {},
      {
        environment: {},
        prepareRuntime: async () => {
          preparationStarted();
          return await prepared;
        },
        createCodex: () => {
          createCodexCalled = true;
          throw new Error("turn continued after close");
        },
      },
    );
    const turn = client.turn(repository);
    await started;
    const closing = client.close();
    releaseRuntime({
      codexHome,
      plugin: {
        pluginRoot: PLUGIN_ROOT,
        marketplaceRoot: PLUGIN_ROOT,
        installedRoot: PLUGIN_ROOT,
        marketplaceName: "codex-security-sdk",
        name: "codex-security",
        version: "0.1.0",
      },
      environment: {},
      credentialsAvailable: true,
    });
    await expect(turn).rejects.toThrow("CodexSecurity is closed");
    await closing;
    expect(createCodexCalled).toBe(false);
  });

  test("isolates caller cancellation from shared runtime initialization", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    await mkdir(scanDir);
    let releaseRuntime!: (runtime: Record<string, unknown>) => void;
    let preparationStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      preparationStarted = resolve;
    });
    const prepared = new Promise<Record<string, unknown>>((resolve) => {
      releaseRuntime = resolve;
    });
    const TestClient = CodexSecurity as unknown as new (
      config: Record<string, unknown>,
      dependencies: Record<string, unknown>,
    ) => CodexSecurity;
    const client = new TestClient(
      {},
      {
        environment: {},
        prepareRuntime: async () => {
          preparationStarted();
          return await prepared;
        },
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => "deadbeef",
        createCodex: () => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              await copyCompletedScan(root);
              return { events: completedEvents() };
            },
          }),
        }),
      },
    );
    const controller = new AbortController();
    const canceled = client.turn(repository, { signal: controller.signal });
    const continuing = client.turn(repository);
    await started;
    controller.abort();
    await expect(canceled).rejects.toBeInstanceOf(ScanInterruptedError);
    releaseRuntime({
      codexHome,
      plugin: {
        pluginRoot: PLUGIN_ROOT,
        marketplaceRoot: PLUGIN_ROOT,
        installedRoot: PLUGIN_ROOT,
        marketplaceName: "codex-security-sdk",
        name: "codex-security",
        version: "0.1.0",
      },
      environment: {},
      credentialsAvailable: true,
    });
    await expect((await continuing).run()).resolves.toBeDefined();
    await client.close();
  });

  test("waits for in-flight turn setup before close removes the runtime", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = await copyCompletedScan(root);
    await mkdir(repository);
    await mkdir(codexHome);
    let revisionStarted!: () => void;
    let releaseRevision!: () => void;
    const started = new Promise<void>((resolve) => {
      revisionStarted = resolve;
    });
    const blocked = new Promise<void>((resolve) => {
      releaseRevision = resolve;
    });
    let createCodexCalled = false;
    const TestClient = CodexSecurity as unknown as new (
      config: Record<string, unknown>,
      dependencies: Record<string, unknown>,
    ) => CodexSecurity;
    const client = new TestClient(
      {},
      {
        environment: {},
        prepareRuntime: async () => ({
          codexHome,
          plugin: {
            pluginRoot: PLUGIN_ROOT,
            marketplaceRoot: PLUGIN_ROOT,
            installedRoot: PLUGIN_ROOT,
            marketplaceName: "codex-security-sdk",
            name: "codex-security",
            version: "0.1.0",
          },
          environment: {},
          credentialsAvailable: true,
        }),
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => {
          revisionStarted();
          await blocked;
          return "deadbeef";
        },
        createCodex: () => {
          createCodexCalled = true;
          throw new Error("turn continued after close");
        },
      },
    );
    const turn = client.turn(repository);
    await started;
    const closing = client.close();
    releaseRevision();
    await expect(turn).rejects.toThrow("CodexSecurity is closed");
    await closing;
    expect(createCodexCalled).toBe(false);
  });

  test("cancels interactive login children during close", async () => {
    const root = await temporaryDirectory();
    const codexHome = join(root, "codex-home");
    const fakeCodex = join(root, "codex.mjs");
    await mkdir(codexHome);
    await writeFile(
      fakeCodex,
      'console.error("Open https://auth.example.test/device");\nconsole.error("User code: ABCD-EFGH");\nsetInterval(() => {}, 1000);\n',
    );
    const TestClient = CodexSecurity as unknown as new (
      config: Record<string, unknown>,
      dependencies: Record<string, unknown>,
    ) => CodexSecurity;
    const client = new TestClient(
      {},
      {
        environment: {},
        prepareRuntime: async () => ({
          codexHome,
          plugin: {
            pluginRoot: PLUGIN_ROOT,
            marketplaceRoot: PLUGIN_ROOT,
            installedRoot: PLUGIN_ROOT,
            marketplaceName: "codex-security-sdk",
            name: "codex-security",
            version: "0.1.0",
          },
          environment: {},
          credentialsAvailable: false,
        }),
        resolveCodexCommand: () => ({
          command: process.execPath,
          prefixArgs: [fakeCodex],
        }),
        createCodex: () => {
          throw new Error("not used");
        },
      },
    );
    const login = await client.loginChatGPTDeviceCode();
    expect(login.verificationUrl).toBe("https://auth.example.test/device");
    expect(login.userCode).toBe("ABCD-EFGH");
    await client.close();
    await expect(login.wait()).resolves.toMatchObject({ success: false });
  });

  test("clears a cached API key after successful ChatGPT login", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const fakeCodex = join(root, "codex.mjs");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    await mkdir(scanDir);
    await writeFile(
      fakeCodex,
      `
const args = process.argv.slice(2).join(" ");
if (args === "login --with-api-key") {
  for await (const _chunk of process.stdin) {}
} else if (args === "login") {
  console.error("Open https://auth.example.test/login");
  process.exit(0);
} else {
  process.exitCode = 2;
}
`,
    );
    let codexOptions: CodexOptions | null = null;
    const TestClient = CodexSecurity as unknown as new (
      config: Record<string, unknown>,
      dependencies: Record<string, unknown>,
    ) => CodexSecurity;
    const client = new TestClient(
      {},
      {
        environment: { OPENAI_API_KEY: "ambient-key" },
        prepareRuntime: async () => ({
          codexHome,
          plugin: {
            pluginRoot: PLUGIN_ROOT,
            marketplaceRoot: PLUGIN_ROOT,
            installedRoot: PLUGIN_ROOT,
            marketplaceName: "codex-security-sdk",
            name: "codex-security",
            version: "0.1.0",
          },
          environment: {
            CODEX_HOME: codexHome,
            OPENAI_API_KEY: "ambient-key",
            CODEX_API_KEY: "secondary-ambient-key",
          },
          credentialsAvailable: false,
        }),
        resolveCodexCommand: () => ({
          command: process.execPath,
          prefixArgs: [fakeCodex],
        }),
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options: CodexOptions) => {
          codexOptions = options;
          return {
            startThread: () => ({
              id: null,
              async runStreamed() {
                await copyCompletedScan(root);
                return { events: completedEvents() };
              },
            }),
          };
        },
      },
    );
    await client.loginApiKey("secret-key");
    const login = await client.loginChatGPT();
    await expect(login.wait()).resolves.toMatchObject({ success: true });
    await client.run(repository);
    expect((codexOptions as CodexOptions | null)?.apiKey).toBeUndefined();
    expect(
      (codexOptions as CodexOptions | null)?.env?.["OPENAI_API_KEY"],
    ).toBeUndefined();
    expect(
      (codexOptions as CodexOptions | null)?.env?.["CODEX_API_KEY"],
    ).toBeUndefined();
    await client.close();
  });

  test("aborts and waits for an in-flight API-key login during close", async () => {
    const root = await temporaryDirectory();
    const codexHome = join(root, "codex-home");
    const fakeCodex = join(root, "codex.mjs");
    const ready = join(root, "ready");
    await mkdir(codexHome);
    await writeFile(
      fakeCodex,
      `
import { writeFileSync } from "node:fs";
process.on("SIGTERM", () => {
  writeFileSync(${JSON.stringify(join(codexHome, "auth.json"))}, "late write");
  process.exit(0);
});
writeFileSync(${JSON.stringify(ready)}, "ready");
for await (const _chunk of process.stdin) {}
setInterval(() => {}, 1000);
`,
    );
    const TestClient = CodexSecurity as unknown as new (
      config: Record<string, unknown>,
      dependencies: Record<string, unknown>,
    ) => CodexSecurity;
    const client = new TestClient(
      {},
      {
        environment: {},
        prepareRuntime: async () => ({
          codexHome,
          plugin: {
            pluginRoot: PLUGIN_ROOT,
            marketplaceRoot: PLUGIN_ROOT,
            installedRoot: PLUGIN_ROOT,
            marketplaceName: "codex-security-sdk",
            name: "codex-security",
            version: "0.1.0",
          },
          environment: {},
          credentialsAvailable: false,
        }),
        resolveCodexCommand: () => ({
          command: process.execPath,
          prefixArgs: [fakeCodex],
        }),
        createCodex: () => {
          throw new Error("not used");
        },
      },
    );
    const login = client.loginApiKey("secret-key");
    void login.catch(() => undefined);
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const started = await import("node:fs/promises").then(({ stat }) =>
        stat(ready).catch(() => null),
      );
      if (started !== null) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    await expect(
      import("node:fs/promises").then(({ stat }) => stat(ready)),
    ).resolves.toBeDefined();
    await client.close();
    await expect(login).rejects.toThrow();
    await expect(
      import("node:fs/promises").then(({ stat }) => stat(codexHome)),
    ).rejects.toThrow();
  });
});

if (process.env["CODEX_SECURITY_INTEGRATION"] === "1") {
  test(
    "real Codex and unchanged-plugin integration smoke",
    async () => {
      const client = new CodexSecurity();
      let scanDir: string | null = null;
      try {
        const result = await client.run(REPOSITORY_ROOT, {
          target: [INTEGRATION_TARGET],
          onOutputDirReady: (path) => {
            scanDir = path;
          },
        });
        expect(result.manifest.scan.status).toBe("completed");
      } finally {
        await client.close();
        if (scanDir !== null)
          await rm(scanDir, { recursive: true, force: true });
      }
    },
    { timeout: 10 * 60_000 },
  );
} else {
  test.skip("real Codex and unchanged-plugin integration smoke", () => {});
}
