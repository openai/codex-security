import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { runCodexSkillCommand } from "../src/cli.js";
import {
  inlineToml,
  writeCodexConfig,
  type JsonObject,
} from "../src/config.js";
import {
  prepareCodexSecurityCredentialHome,
  resolveCodexCommand,
} from "../src/runtime.js";
import { capture } from "./cli-fixtures.js";
import { readOperationTelemetry } from "../src/operation-telemetry.js";

test.each([
  ["codex_security_deep_scan", true, false],
  ["codex_security_deep_scan", true, true],
  ["codex_security_deep_scan", false, false],
  ["codex-security", true, false],
] as const)(
  "native configuration fixture owns preflight shutdown: client=%s, layers=%p, error=%p",
  async (clientName, includeLayers, error) => {
    const root = await mkdtemp(join(tmpdir(), "native-config-lifetime-"));
    const exited = join(root, "native-exited");
    const response = {
      id: 2,
      ...(error
        ? { error: { code: -32603, message: "synthetic configuration error" } }
        : {
            result: {
              config: { model: "synthetic-model", daybreak: true },
              origins: { daybreak: { name: { type: "user" } } },
              layers: [{ name: { type: "user" }, config: { daybreak: true } }],
            },
          }),
    };
    const child = spawn(
      process.execPath,
      [
        fileURLToPath(
          new URL("./fixtures/skill-native-config.mjs", import.meta.url),
        ),
        "-e",
        `const { createInterface } = require("node:readline");
         const { writeFileSync } = require("node:fs");
         createInterface({ input: process.stdin }).on("line", line => {
           const request = JSON.parse(line);
           const response = request.method === "config/read"
             ? ${JSON.stringify(response)}
             : { id: request.id, result: {} };
           process.stdout.write(JSON.stringify(response) + "\\n");
         });
         process.on("exit", () => writeFileSync(${JSON.stringify(exited)}, "exited"));`,
      ],
      {
        env: { ...process.env, SYNTHETIC_NATIVE_CODEX: process.execPath },
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      },
    );
    const closed = once(child, "close");
    const lines = createInterface({ input: child.stdout });
    const timeout = setTimeout(() => child.kill(), 10_000);
    try {
      child.stdin.write(
        JSON.stringify({
          id: 1,
          method: "initialize",
          params: { clientInfo: { name: clientName } },
        }) + "\n",
      );
      await once(lines, "line");
      child.stdin.write(
        JSON.stringify({
          id: 2,
          method: "config/read",
          params: { includeLayers },
        }) + "\n",
      );
      const [line] = await once(lines, "line");
      expect(line).toBe(JSON.stringify(response));
      if (clientName === "codex_security_deep_scan" && includeLayers) {
        expect(await readFile(exited, "utf8")).toBe("exited");
        child.stdin.end();
        child.kill("SIGTERM");
      } else {
        await expect(readFile(exited, "utf8")).rejects.toHaveProperty(
          "code",
          "ENOENT",
        );
        child.stdin.end();
      }
      await closed;
      expect(await readFile(exited, "utf8")).toBe("exited");
    } finally {
      child.stdin.end();
      await closed;
      clearTimeout(timeout);
      lines.close();
      child.stderr.destroy();
      await rm(root, { recursive: true, force: true });
    }
  },
);

test.each([0, 23])(
  "native configuration fixture preserves early exit %p with its input still open",
  async (exitCode) => {
    const child = spawn(
      process.execPath,
      [
        fileURLToPath(
          new URL("./fixtures/skill-native-config.mjs", import.meta.url),
        ),
        "-e",
        `process.stderr.write("synthetic native exit\\n"); process.exitCode = ${exitCode};`,
      ],
      {
        env: { ...process.env, SYNTHETIC_NATIVE_CODEX: process.execPath },
        stdio: ["pipe", "ignore", "pipe"],
        windowsHide: true,
      },
    );
    const closed = once(child, "close");
    let diagnostic = "";
    child.stderr.on("data", (chunk) => {
      diagnostic += chunk;
    });
    const timeout = setTimeout(() => child.kill(), 10_000);
    try {
      const [code, signal] = await closed;
      expect({ code, signal, diagnostic }).toEqual({
        code: exitCode,
        signal: null,
        diagnostic: "synthetic native exit\n",
      });
    } finally {
      clearTimeout(timeout);
      child.stdin.destroy();
      child.stderr.destroy();
      child.kill();
    }
  },
);

test.each([
  ["trusted", undefined, "patch", ""],
  ["untrusted", undefined, "patch", ""],
  [undefined, undefined, "patch", ""],
  ["trusted", "openai", "patch", ""],
  ["trusted", undefined, "verify-fix", ""],
  ["trusted", undefined, "patch", "component"],
] as const)(
  "stored-auth commands preserve native project configuration (%s, provider: %s, command: %s, subdirectory: %s)",
  async (trust, modelProvider, command, subdirectory) => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-native-config-")),
    );
    const repository = join(root, "repository");
    const directory = join(repository, subdirectory);
    const ambientHome = join(root, "ambient");
    const environment = {
      ...Object.fromEntries(
        Object.entries(process.env).filter(([name]) =>
          /^(path|systemroot|comspec|temp|tmp|tmpdir)$/iu.test(name),
        ),
      ),
      CODEX_HOME: ambientHome,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      SYNTHETIC_NATIVE_CODEX: resolveCodexCommand({}).command,
    };
    try {
      await mkdir(directory, { recursive: true });
      execFileSync("git", ["init", "--quiet", repository]);
      await writeCodexConfig(join(repository, ".codex", "config.toml"), {
        mcp_servers: {
          synthetic: { command: "synthetic-unused-command", enabled: false },
        },
      });
      await writeCodexConfig(join(ambientHome, "config.toml"), {
        cli_auth_credentials_store: "file",
        ...(trust === undefined
          ? {}
          : { projects: { [repository]: { trust_level: trust } } }),
      });
      const sharedHome = await prepareCodexSecurityCredentialHome(environment);
      await writeCodexConfig(join(sharedHome, "config.toml"), {
        projects: {
          [repository]: {
            trust_level: trust === "trusted" ? "untrusted" : "trusted",
          },
        },
      });
      await writeFile(
        join(sharedHome, "auth.json"),
        JSON.stringify({
          auth_mode: "apikey",
          OPENAI_API_KEY: "SYNTHETIC_KEY",
        }),
        { mode: 0o600 },
      );
      const stdout = capture();
      const stderr = capture();
      const status = await runCodexSkillCommand(
        [
          fileURLToPath(
            new URL("./fixtures/skill-native-config.mjs", import.meta.url),
          ),
          "app-server",
          "--disable",
          "plugins",
          "--config",
          "analytics.enabled=false",
        ],
        {
          command,
          auth: "chatgpt",
          modelProvider,
          directory,
          stdout: stdout.stream,
          stderr: stderr.stream,
          appServer: {
            directory,
            prompt: "Synthetic finding",
            threadSource:
              command === "patch"
                ? "security_remediation"
                : "security_validation",
            ...(command === "verify-fix"
              ? { sandbox: "read-only" as const }
              : {}),
          },
        },
        { command: process.execPath },
        environment,
      );
      expect(status, stderr.text()).toBe(0);
      expect(JSON.parse(stdout.text())).toMatchObject({
        modelProvider: "openai",
        projectServerConfigured: trust === "trusted",
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

const disabledDaybreakFeatures = {
  cli_daybreak: false,
  api_key_cyber_access_programs: false,
  api_key_model_discovery: false,
};

async function withStoredApiKey(
  command: "patch" | "verify-fix",
  check: (fixture: {
    root: string;
    environment: Record<string, string>;
    ambientHome: string;
    sharedHome: string;
    repository: string;
    run: (
      overrides?: JsonObject,
      options?: { inheritAnalytics?: boolean; auth?: "auto" | "api-key" },
    ) => Promise<{
      daybreak: boolean | null;
      daybreakEnabled: boolean | null;
      daybreakFeatures: Record<string, boolean | null>;
      analytics: JsonObject | null;
      otel: JsonObject | null;
      requestMetadata: JsonObject | null;
    }>;
  }) => Promise<void>,
): Promise<void> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-stored-daybreak-")),
  );
  const repository = join(root, "repository");
  const ambientHome = join(root, "ambient");
  const environment = {
    ...Object.fromEntries(
      Object.entries(process.env).filter(([name]) =>
        /^(path|systemroot|comspec|temp|tmp|tmpdir)$/iu.test(name),
      ),
    ),
    CODEX_HOME: ambientHome,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
    SYNTHETIC_NATIVE_CODEX: resolveCodexCommand({}).command,
  };
  try {
    await mkdir(repository);
    execFileSync("git", ["init", "--quiet", repository]);
    const sharedHome = await prepareCodexSecurityCredentialHome(environment);
    await writeFile(
      join(sharedHome, "auth.json"),
      JSON.stringify({
        auth_mode: "apikey",
        OPENAI_API_KEY: "SYNTHETIC_KEY",
      }),
      { mode: 0o600 },
    );
    await check({
      root,
      environment,
      ambientHome,
      sharedHome,
      repository,
      run: async (overrides = {}, options = {}) => {
        const stdout = capture();
        const stderr = capture();
        const status = await runCodexSkillCommand(
          [
            fileURLToPath(
              new URL("./fixtures/skill-native-config.mjs", import.meta.url),
            ),
            "app-server",
            "--disable",
            "plugins",
            ...(options.inheritAnalytics
              ? []
              : ["--config", "analytics.enabled=false"]),
            ...Object.entries(overrides).flatMap(([key, value]) => [
              "--config",
              `${key}=${inlineToml(value)}`,
            ]),
          ],
          {
            command,
            auth: options.auth ?? "auto",
            codexOverrides: overrides,
            directory: repository,
            stdout: stdout.stream,
            stderr: stderr.stream,
            appServer: {
              directory: repository,
              prompt: "Synthetic finding",
              threadSource:
                command === "patch"
                  ? "security_remediation"
                  : "security_validation",
              ...(command === "verify-fix"
                ? { sandbox: "read-only" as const }
                : {}),
            },
          },
          { command: process.execPath },
          {
            ...environment,
            ...(options.auth === "api-key"
              ? { OPENAI_API_KEY: "SYNTHETIC_KEY" }
              : {}),
          },
        );
        expect(status, stderr.text()).toBe(0);
        return JSON.parse(stdout.text());
      },
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test.each(["patch", "verify-fix"] as const)(
  "%s preserves consent and private-home exporters without copying inherited headers",
  async (command) => {
    await withStoredApiKey(
      command,
      async ({
        root,
        environment,
        ambientHome,
        sharedHome,
        repository,
        run,
      }) => {
        environment["SYNTHETIC_CONFIG_OBSERVATIONS"] = join(
          root,
          "native-config.jsonl",
        );
        const configPath = join(ambientHome, "config.toml");
        const privateOtel = {
          environment: "synthetic-shared",
          exporter: "none",
          log_user_prompt: false,
        };
        await writeCodexConfig(join(sharedHome, "config.toml"), {
          otel: privateOtel,
        });
        const telemetry = {
          analytics: { enabled: false },
          otel: {
            environment: "synthetic-selected",
            exporter: {
              "otlp-http": {
                endpoint: "https://telemetry.example.test/v1/logs",
                protocol: "json",
                headers: {
                  Authorization: "Bearer synthetic-selected-exporter",
                },
              },
            },
            log_user_prompt: false,
          },
          responses_api_metadata: {
            "team.tag": "selected",
            root_only: "root",
            selected_only: "selected",
          },
        };
        await writeCodexConfig(configPath, {
          analytics: { enabled: true },
          otel: {
            environment: "synthetic-root",
            exporter: {
              "otlp-http": {
                endpoint: "https://telemetry.example.test/v1/logs",
                protocol: "json",
                headers: { Authorization: "Bearer synthetic-root-exporter" },
              },
            },
          },
          responses_api_metadata: { "team.tag": "root", root_only: "root" },
          projects: { [repository]: { trust_level: "trusted" } },
          profile: "selected",
          profiles: { selected: telemetry },
        });
        // Compare actual native project precedence, including ignored telemetry
        // keys, instead of reimplementing which project settings Codex permits.
        await writeCodexConfig(join(repository, ".codex", "config.toml"), {
          analytics: { enabled: false },
          otel: { environment: "synthetic-project", exporter: "none" },
          responses_api_metadata: { "project.tag": "project" },
        });
        const inherited = await run({}, { inheritAnalytics: true });
        const records = await readOperationTelemetry(
          environment["CODEX_SECURITY_STATE_DIR"]!,
        );
        expect(records.events.map((event) => event.type)).toEqual([
          "attempt_started",
          "attempt_finished",
        ]);
        expect(records.events[1]).toMatchObject({
          command,
          outcome: "completed",
        });
        expect(inherited.requestMetadata).toMatchObject({
          codex_security_operation_id: records.events[0]!.operationId,
          codex_security_attempt_id: records.events[0]!.attemptId,
        });
        expect(inherited).toMatchObject({
          analytics: telemetry.analytics,
          otel: privateOtel,
          requestMetadata: telemetry.responses_api_metadata,
        });
        const launches = (
          await readFile(environment["SYNTHETIC_CONFIG_OBSERVATIONS"], "utf8")
        )
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line));
        expect(launches.length).toBeGreaterThanOrEqual(2);
        for (const launch of launches) {
          expect(launch.analytics).toEqual(telemetry.analytics);
          expect(launch.otel).toMatchObject(privateOtel);
          expect(JSON.stringify(launch.args)).not.toContain(
            "synthetic-selected-exporter",
          );
          expect(JSON.stringify(launch.args)).not.toContain(
            "synthetic-root-exporter",
          );
          expect(launch.metadata).toMatchObject(
            telemetry.responses_api_metadata,
          );
        }
        const explicit = {
          analytics: { enabled: false },
          otel: { environment: "synthetic-explicit", exporter: "none" },
          responses_api_metadata: {
            "team.tag": "explicit",
            codex_security_command: command,
          },
        };
        const configured = await run(explicit, { inheritAnalytics: true });
        expect(configured).toMatchObject({
          analytics: explicit.analytics,
          otel: { ...privateOtel, ...explicit.otel },
          requestMetadata: {
            ...telemetry.responses_api_metadata,
            ...explicit.responses_api_metadata,
          },
        });
        const shared = parseToml(
          await readFile(join(sharedHome, "config.toml"), "utf8"),
        );
        expect(shared["otel"]).toEqual(privateOtel);
        for (const key of ["analytics", "responses_api_metadata"])
          expect(shared).not.toHaveProperty(key);

        // A subsequent invocation must not retain the earlier ambient profile.
        await writeCodexConfig(configPath, {
          analytics: { enabled: false },
          otel: { environment: "synthetic-next", exporter: "none" },
        });
        const next = await run({}, { inheritAnalytics: true });
        expect(next.otel).toMatchObject(privateOtel);
        expect(next.requestMetadata ?? {}).not.toHaveProperty("selected_only");
      },
    );
  },
);

test("stored and API-key patches preserve consent while exporters follow their selected native home", async () => {
  await withStoredApiKey("patch", async ({ ambientHome, run }) => {
    await writeCodexConfig(join(ambientHome, "config.toml"), {
      analytics: { enabled: false },
      otel: {
        environment: "synthetic-auth-independent",
        exporter: "none",
        log_user_prompt: false,
      },
      responses_api_metadata: { "team.tag": "synthetic-ambient" },
    });
    const stored = await run({}, { inheritAnalytics: true });
    const apiKey = await run({}, { inheritAnalytics: true, auth: "api-key" });
    expect(stored.analytics).toEqual(apiKey.analytics);
    expect(stored.otel?.["environment"]).not.toBe("synthetic-auth-independent");
    expect(apiKey.otel?.["environment"]).toBe("synthetic-auth-independent");
    expect(stored.requestMetadata).toMatchObject({
      "team.tag": "synthetic-ambient",
    });
    expect(apiKey.requestMetadata).toMatchObject({
      "team.tag": "synthetic-ambient",
    });
    expect(stored.requestMetadata?.["codex_security_attempt_id"]).not.toBe(
      apiKey.requestMetadata?.["codex_security_attempt_id"],
    );
  });
});

test.each(
  (["patch", "verify-fix"] as const).flatMap((command) =>
    [true, false].map((daybreak) => [command, daybreak] as const),
  ),
)(
  "%s preserves ambient Daybreak %p with a stored API key",
  async (command, daybreak) => {
    await withStoredApiKey(
      command,
      async ({ ambientHome, sharedHome, run }) => {
        await writeCodexConfig(join(ambientHome, "config.toml"), { daybreak });
        await writeCodexConfig(join(sharedHome, "config.toml"), {
          daybreak: !daybreak,
        });
        expect(await run()).toMatchObject({
          daybreak,
          daybreakEnabled: daybreak ? true : null,
        });
      },
    );
  },
);

test.each(["patch", "verify-fix"] as const)(
  "%s preserves the Daybreak opt-out with an explicit toggle and a stored API key",
  async (command) => {
    await withStoredApiKey(command, async ({ ambientHome, run }) => {
      await writeCodexConfig(join(ambientHome, "config.toml"), {
        daybreak: false,
        features: { cli_daybreak: false },
      });
      expect(await run({ daybreak: true })).toMatchObject({
        daybreak: true,
        daybreakEnabled: true,
        daybreakFeatures: { cli_daybreak: false },
      });
    });
  },
);

test.each(["patch", "verify-fix"] as const)(
  "%s forwards wrapper-resolved ambient Daybreak profiles with a stored API key",
  async (command) => {
    await withStoredApiKey(command, async ({ ambientHome, run }) => {
      await writeCodexConfig(join(ambientHome, "config.toml"), {
        daybreak: false,
        features: { cli_daybreak: true },
        profile: "selected",
        profiles: {
          selected: { daybreak: true, features: disabledDaybreakFeatures },
        },
      });
      expect(await run()).toMatchObject({
        daybreak: true,
        daybreakEnabled: true,
        daybreakFeatures: disabledDaybreakFeatures,
      });
    });
  },
);

test.each(["patch", "verify-fix"] as const)(
  "%s clears removed ambient Daybreak settings on the next stored API-key launch",
  async (command) => {
    await withStoredApiKey(command, async ({ ambientHome, run }) => {
      const configPath = join(ambientHome, "config.toml");
      await writeCodexConfig(configPath, {});
      const baseline = await run();
      await writeCodexConfig(configPath, {
        daybreak: true,
        features: disabledDaybreakFeatures,
      });
      expect(await run()).toMatchObject({
        daybreak: true,
        daybreakEnabled: true,
        daybreakFeatures: disabledDaybreakFeatures,
      });
      await writeCodexConfig(configPath, {});
      const next = await run();
      expect({ ...next, requestMetadata: undefined }).toEqual({
        ...baseline,
        requestMetadata: undefined,
      });
      expect(next.requestMetadata?.["codex_security_attempt_id"]).not.toBe(
        baseline.requestMetadata?.["codex_security_attempt_id"],
      );
    });
  },
);

test.each(["patch", "verify-fix"] as const)(
  "%s preserves native project and explicit Daybreak precedence with a stored API key",
  async (command) => {
    await withStoredApiKey(
      command,
      async ({ ambientHome, repository, run }) => {
        await writeCodexConfig(join(ambientHome, "config.toml"), {
          daybreak: true,
          features: { cli_daybreak: true },
          projects: { [repository]: { trust_level: "trusted" } },
        });
        await writeCodexConfig(join(repository, ".codex", "config.toml"), {
          daybreak: false,
          features: { cli_daybreak: false },
        });
        expect(await run()).toMatchObject({
          daybreak: false,
          daybreakEnabled: null,
          daybreakFeatures: { cli_daybreak: false },
        });
        expect(await run({ daybreak: true })).toMatchObject({
          daybreak: true,
          daybreakEnabled: true,
          daybreakFeatures: { cli_daybreak: false },
        });
      },
    );
  },
);

test.each(["omitted", "omitted with changed gates", "explicit"] as const)(
  "stored API-key patches preserve %s settings for an active scan's later workers",
  async (settings) => {
    await withStoredApiKey(
      "patch",
      async ({
        root,
        environment,
        ambientHome,
        sharedHome,
        repository,
        run,
      }) => {
        await writeCodexConfig(join(ambientHome, "config.toml"), {});
        const scanConfig = join(root, "scan.toml");
        const workerConfig = join(root, "workers.toml");
        const workerRuntime: JsonObject =
          settings !== "explicit"
            ? {}
            : {
                daybreak: false,
                features: {
                  cli_daybreak: true,
                  api_key_cyber_access_programs: true,
                  api_key_model_discovery: true,
                },
                analytics: { enabled: false },
                otel: {
                  environment: "synthetic-worker",
                  exporter: "none",
                  log_user_prompt: false,
                },
                responses_api_metadata: { "synthetic.tag": "worker" },
              };
        await writeCodexConfig(scanConfig, {});
        await writeCodexConfig(workerConfig, { worker_runtime: workerRuntime });
        const prompt = join(root, "prompt.md");
        await writeFile(prompt, "Synthetic worker request.");
        const executor = new URL(
          "../../../plugins/codex-security/mcp-app/src/deep-scan/executor.ts",
          import.meta.url,
        );
        const catalog = join(root, "catalog.json");
        await writeFile(
          catalog,
          JSON.stringify({
            models: [
              {
                slug: "gpt-test",
                display_name: "Synthetic",
                base_instructions: "Synthetic instructions",
                supported_reasoning_levels: [],
                shell_type: "disabled",
                visibility: "list",
                supported_in_api: true,
                priority: 0,
                support_verbosity: false,
                truncation_policy: { mode: "tokens", limit: 10000 },
                experimental_supported_tools: [],
                available_access_programs: {
                  cyber: ["standard", "daybreak_red", "daybreak_blue"],
                },
              },
            ],
          }),
        );
        const child = spawn(
          process.execPath,
          [
            fileURLToPath(
              new URL(
                "./fixtures/stored-daybreak-workers.mjs",
                import.meta.url,
              ),
            ),
            fileURLToPath(executor),
            prompt,
          ],
          {
            cwd: repository,
            env: {
              ...environment,
              CODEX_HOME: sharedHome,
              CODEX_CLI_PATH: environment["SYNTHETIC_NATIVE_CODEX"],
              CODEX_API_KEY: "SYNTHETIC_KEY",
              CODEX_SECURITY_CONFIG_PATH: scanConfig,
              CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: workerConfig,
            },
            stdio: ["pipe", "pipe", "pipe"],
            windowsHide: true,
          },
        );
        const closed = once(child, "close");
        let stderr = "";
        child.stderr.on("data", (chunk) => {
          stderr += chunk;
        });
        const lines = createInterface({ input: child.stdout });
        const responses = lines[Symbol.asyncIterator]();
        const response = async () => {
          const next = await responses.next();
          expect(next.done, stderr).toBe(false);
          return JSON.parse(next.value!);
        };
        const worker = async (
          kind: "discovery" | "dedup",
          resumeThreadId?: string,
        ) => {
          child.stdin.write(JSON.stringify({ kind, resumeThreadId }) + "\n");
          return await response();
        };
        try {
          const { baseUrl } = await response();
          await writeCodexConfig(join(sharedHome, "config.toml"), {
            model_catalog_json: catalog,
            openai_base_url: baseUrl,
            cli_auth_credentials_store: "file",
            features: { plugins: false },
            analytics: { enabled: false },
            otel: { environment: "synthetic-shared", exporter: "none" },
          });
          // The first worker initializes the executor's per-scan snapshot.
          const { threadId, resumed, ...baseline } = await worker("discovery");
          expect(threadId).toBeString();
          expect(resumed).toBe(false);
          expect(baseline.program).toBe("standard");
          expect(baseline.daybreak).toBe(
            settings === "explicit" ? false : null,
          );
          expect(baseline.telemetry).toEqual({
            analyticsEnabled: false,
            environment:
              settings === "explicit" ? "synthetic-worker" : "synthetic-shared",
            metadataTag: settings === "explicit" ? "worker" : null,
          });
          if (settings === "explicit")
            expect(baseline.daybreakFeatures).toEqual(
              workerRuntime["features"],
            );
          const reducer = await worker("dedup");
          expect(reducer).toMatchObject({ ...baseline, resumed: false });
          const previousThreads = {
            discovery: threadId,
            dedup: reducer.threadId,
          };
          const features =
            settings === "omitted" ? undefined : disabledDaybreakFeatures;
          await writeCodexConfig(join(ambientHome, "config.toml"), {
            daybreak: true,
            ...(features === undefined ? {} : { features }),
            analytics: { enabled: false },
            otel: { environment: "synthetic-patch", exporter: "none" },
            responses_api_metadata: { "synthetic.tag": "patch" },
          });
          expect(await run()).toMatchObject({
            daybreak: true,
            ...(features === undefined ? {} : { daybreakFeatures: features }),
          });
          for (const kind of ["discovery", "dedup"] as const) {
            for (const resume of [false, true]) {
              const receipt = await worker(
                kind,
                resume ? previousThreads[kind] : undefined,
              );
              expect(receipt).toMatchObject({ ...baseline, resumed: resume });
              if (resume) expect(receipt.threadId).toBe(previousThreads[kind]);
            }
          }
        } finally {
          lines.close();
          child.stdin.end();
          child.kill();
          await closed;
        }
      },
    );
  },
);
