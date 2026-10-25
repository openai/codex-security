import { mkdir } from "node:fs/promises";
import * as fsPromises from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type {
  CodexOptions,
  ThreadEvent,
  ThreadOptions,
  TurnOptions,
} from "@openai/codex-sdk";
import { afterEach, beforeEach, mock, spyOn } from "bun:test";
import type { JsonObject } from "../../src/config.js";
import { resolvePluginPython, runWorkbench } from "../../src/runtime.js";

import { PLUGIN_ROOT } from "../plugin-root.js";
import { TestClient } from "./api-client.js";
import { preparedRuntime } from "./api-events.js";
import { createApiTestFixtures } from "./temporary-directories.js";
import { FindingWorkflow } from "../../src/finding-workflow.js";

export function createValidationFixtures() {
  const { cleanup, temporaryDirectory } = createApiTestFixtures();

  async function repositoryDirectories() {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    return { root, repository };
  }

  async function runtimeDirectories() {
    const { root, repository } = await repositoryDirectories();
    const codexHome = join(root, "codex-home");
    await mkdir(codexHome);
    return { root, repository, codexHome };
  }

  function runtimePreparer(
    codexHome: string,
    overrides: () => Partial<ReturnType<typeof preparedRuntime>>,
  ) {
    return async () => ({
      ...preparedRuntime(codexHome),
      ...overrides(),
    });
  }
  const actualLstat = fsPromises.lstat;
  let guidanceLookup: ReturnType<typeof spyOn<typeof fsPromises, "lstat">>;
  beforeEach(async () => {
    const ambientGuidance = new Set([
      process.platform === "win32"
        ? join("C:\\ProgramData", "OpenAI", "Codex", "config.toml")
        : "/etc/codex/config.toml",
    ]);
    guidanceLookup = spyOn(fsPromises, "lstat").mockImplementation((async (
      ...args: Parameters<typeof actualLstat>
    ) => {
      if (typeof args[0] === "string" && ambientGuidance.has(args[0]))
        throw Object.assign(new Error("Synthetic absent native guidance"), {
          code: "ENOENT",
        });
      return await actualLstat(...args);
    }) as typeof actualLstat);
    // Guidance below the temporary directory belongs to the fixtures and stays visible.
    let directory = await fsPromises.realpath(tmpdir());
    for (;;) {
      for (const name of [
        ".codex/config.toml",
        "AGENTS.override.md",
        "AGENTS.md",
        "REVIEW.md",
      ])
        ambientGuidance.add(join(directory, name));
      const parent = dirname(directory);
      if (parent === directory) break;
      directory = parent;
    }
  });
  afterEach(async () => {
    guidanceLookup.mockRestore();
    await cleanup();
  });

  const assessment = {
    disposition: "reportable",
    report: "Static trace reaches the SQL sink; runtime proof is still needed.",
  } as const;

  async function* validationEvents(
    response = JSON.stringify(assessment),
    complete = true,
  ): AsyncGenerator<ThreadEvent> {
    yield { type: "thread.started", thread_id: "validation-thread" };
    yield {
      type: "item.completed",
      item: { id: "result", type: "agent_message", text: response },
    };
    if (complete) {
      yield {
        type: "turn.completed",
        usage: {
          input_tokens: 10,
          cached_input_tokens: 0,
          cache_write_input_tokens: 0,
          output_tokens: 3,
          reasoning_output_tokens: 0,
        },
      };
    }
  }

  let fixturePython: Promise<string> | undefined;

  async function validationClient(
    events: (signal: AbortSignal) => AsyncGenerator<ThreadEvent> = () =>
      validationEvents(),
    pluginRoot = PLUGIN_ROOT,
    pythonPath = "/managed/python",
    fixtureRoot?: string,
    environmentOverrides: Record<string, string> = {},
  ) {
    const root = fixtureRoot ?? (await temporaryDirectory());
    const repository = join(root, "repository");
    const codexHome = await temporaryDirectory();
    const stateDirectory =
      environmentOverrides["CODEX_SECURITY_STATE_DIR"] ?? join(root, "state");
    await mkdir(repository, { recursive: true });
    const captured: {
      codex?: CodexOptions;
      thread?: ThreadOptions;
      prompt?: string;
      turn?: TurnOptions;
    } = {};
    const workbench = mock(
      async (
        _options: Parameters<typeof runWorkbench>[0],
        _args: readonly string[],
        _input?: string,
      ): Promise<JsonObject> => ({
        scan: { targetPath: repository },
      }),
    );
    const environment = {
      ...Object.fromEntries(
        ["PATH", "SystemRoot", "TEMP", "TMP"].flatMap((name) =>
          process.env[name] === undefined ? [] : [[name, process.env[name]!]],
        ),
      ),
      CODEX_SECURITY_STATE_DIR: stateDirectory,
      OPENAI_API_KEY: "synthetic-validation-key",
      ...environmentOverrides,
    };
    const client = new TestClient(
      {
        pluginPath: pluginRoot === PLUGIN_ROOT ? undefined : pluginRoot,
        pythonPath,
        codexOverrides: {
          model: "test-model",
          model_reasoning_effort: "high",
          approval_policy: "never",
          analytics: { enabled: false },
        },
      },
      {
        environment,
        prepareRuntime: runtimePreparer(codexHome, () => ({
          plugin: { ...preparedRuntime(codexHome).plugin, pluginRoot },
          environment,
        })),
        resolvePluginPython: async ({ configuredPath } = {}) => configuredPath!,
        runWorkbench: workbench,
        createCodex: (options) => {
          captured.codex = options;
          return {
            startThread: (options) => {
              captured.thread = options;
              return {
                id: null,
                async runStreamed(prompt, options) {
                  captured.prompt = prompt;
                  captured.turn = options;
                  return { events: events(options.signal!) };
                },
              };
            },
          };
        },
      },
    );
    const options = {
      repositoryPath: repository,
      finding: "Candidate finding",
      outputDir: join(root, "validation"),
    };
    return {
      client,
      options,
      stateDirectory,
      captured,
      workbench,
      root,
      codexHome,
    };
  }

  async function persistedValidationClient(
    events?: Parameters<typeof validationClient>[0],
    pluginRoot = PLUGIN_ROOT,
    fixtureRoot?: string,
    environmentOverrides?: Record<string, string>,
  ) {
    const python = await (fixturePython ??= resolvePluginPython());
    const fixture = await validationClient(
      events,
      pluginRoot,
      python,
      fixtureRoot,
      environmentOverrides,
    );
    fixture.workbench.mockImplementation(runWorkbench);
    async function bindWorkflow(
      id: string,
      environment: NodeJS.ProcessEnv = {
        CODEX_SECURITY_STATE_DIR: fixture.stateDirectory,
      },
    ) {
      const workflow = new FindingWorkflow(
        id,
        environment,
        runWorkbench,
        python,
        {
          workbenchOptions: { python, pluginRoot: PLUGIN_ROOT, environment },
        },
      );
      await workflow.bind({ repositoryPath: fixture.options.repositoryPath });
      return id;
    }
    return { ...fixture, python, bindWorkflow };
  }

  return {
    actualLstat,
    assessment,
    validationEvents,
    validationClient,
    persistedValidationClient,
    temporaryDirectory,
    repositoryDirectories,
    runtimeDirectories,
    runtimePreparer,
  };
}
