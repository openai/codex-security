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

const modelCatalog = fileURLToPath(
  new URL("./fixtures/native-skill-model-catalog.json", import.meta.url),
);

const nativeConfigArgs = [
  fileURLToPath(new URL("./fixtures/skill-native-config.mjs", import.meta.url)),
  "app-server",
  "--disable",
  "plugins",
  "--config",
  "analytics.enabled=false",
  "--config",
  `model_catalog_json=${inlineToml(modelCatalog)}`,
];

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
        nativeConfigArgs,
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
    run: (overrides?: JsonObject) => Promise<{
      daybreak: boolean | null;
      daybreakEnabled: boolean | null;
      daybreakFeatures: Record<string, boolean | null>;
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
      run: async (overrides = {}) => {
        const stdout = capture();
        const stderr = capture();
        const status = await runCodexSkillCommand(
          [
            ...nativeConfigArgs,
            ...Object.entries(overrides).flatMap(([key, value]) => [
              "--config",
              `${key}=${inlineToml(value)}`,
            ]),
          ],
          {
            command,
            auth: "auto",
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
          environment,
        );
        expect(status, stderr.text()).toBe(0);
        return JSON.parse(stdout.text());
      },
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test.each([
  ["patch", true],
  ["patch", false],
  ["verify-fix", true],
] as const)(
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

test("patch preserves the Daybreak opt-out with an explicit toggle and a stored API key", async () => {
  await withStoredApiKey("patch", async ({ ambientHome, run }) => {
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
});

test("patch forwards wrapper-resolved ambient Daybreak profiles with a stored API key", async () => {
  await withStoredApiKey("patch", async ({ ambientHome, run }) => {
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
});

test("patch clears removed ambient Daybreak settings on the next stored API-key launch", async () => {
  await withStoredApiKey("patch", async ({ ambientHome, run }) => {
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
    expect(await run()).toEqual(baseline);
  });
});

test("patch preserves native project and explicit Daybreak precedence with a stored API key", async () => {
  await withStoredApiKey("patch", async ({ ambientHome, repository, run }) => {
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
  });
});

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
              };
        await writeCodexConfig(scanConfig, {});
        await writeCodexConfig(workerConfig, { worker_runtime: workerRuntime });
        const prompt = join(root, "prompt.md");
        await writeFile(prompt, "Synthetic worker request.");
        const executor = new URL(
          "../../../plugins/codex-security/mcp-app/src/deep-scan/executor.ts",
          import.meta.url,
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
            model_catalog_json: modelCatalog,
            openai_base_url: baseUrl,
            cli_auth_credentials_store: "file",
            features: { plugins: false },
            analytics: { enabled: false },
          });
          // The first worker initializes the executor's per-scan snapshot.
          const { threadId, resumed, ...baseline } = await worker("discovery");
          expect(threadId).toBeString();
          expect(resumed).toBe(false);
          expect(baseline.program).toBe("standard");
          expect(baseline.daybreak).toBe(
            settings === "explicit" ? false : null,
          );
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
