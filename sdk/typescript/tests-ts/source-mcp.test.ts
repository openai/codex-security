import {
  execFileSync,
  spawn,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { constants, existsSync } from "node:fs";
import { once } from "node:events";
import { createServer } from "node:http";
import {
  copyFile,
  mkdir,
  readFile,
  realpath,
  symlink,
  writeFile,
} from "node:fs/promises";
import { delimiter, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { afterEach, expect, test } from "bun:test";
import { parse as parseToml, stringify } from "smol-toml";
import type { JsonObject, JsonValue } from "../src/config.js";
import { FindingWorkflow } from "../src/finding-workflow.js";
import {
  CheckpointedReviewRunner,
  reviewSettingsDigest,
} from "../src/deduplication/checkpointed-review.js";
import { checkpointWorkbench } from "./support/workbench-fakes.js";
import {
  CodexReviewRunner,
  type CodexReview,
} from "../src/deduplication/codex-review.js";
import {
  resolveSourceMcp,
  sourceMcpInstructions,
} from "../src/deduplication/source-mcp.js";
import { resolveCodexCommand } from "../src/runtime.js";
import { comparisonEnvironment } from "../src/scan-comparison.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

test.each(["local", "executor"])(
  "native %s cwd preserves directory-link traversal and review identity",
  async (mode) => {
    const home = await temporaryDirectory();
    const repository = await sourceCheckout();
    for (const path of ["real/inner", "real/target", "target"])
      await mkdir(join(home, path), { recursive: true });
    await symlink(
      join(home, "real/inner"),
      join(home, "link"),
      process.platform === "win32" ? "junction" : "dir",
    );
    const captured = join(home, "cwd.json");
    const script = join(home, "source.mjs");
    await writeFile(
      script,
      `import { writeFileSync } from "node:fs";
writeFileSync(process.argv[2], JSON.stringify({ cwd: process.cwd() }));
process.exit(1);`,
    );
    const executorScript = join(home, "executor.mjs");
    await writeFile(
      executorScript,
      `import { writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
writeFileSync(process.argv[2], JSON.stringify({ cwd: process.cwd() }));
process.exit(spawnSync(process.argv[3], ["exec-server", "--listen", "stdio"], { stdio: "inherit" }).status ?? 1);`,
    );
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(home, "state"),
      OPENAI_API_KEY: "synthetic-review-key",
    };
    const store = checkpointWorkbench("source-cwd", { repository });
    const workflow = new FindingWorkflow("source-cwd", environment, store.run);
    const snapshot = await workflow.sourceSnapshot(repository);
    const review: CodexReview<{ cwd: string }> = {
      stage: "pair-review",
      model: "gpt-5.6-sol",
      effort: "low",
      prompt: "Read synthetic source.",
      schema: { type: "object" },
      validate: (value) => value as { cwd: string },
    };
    let calls = 0;
    for (const cwd of ["link/../target", "target"]) {
      if (mode === "executor")
        await writeFile(
          join(home, "environments.toml"),
          stringify({
            environments: [
              {
                id: "source-executor",
                program: process.execPath,
                args: [
                  executorScript,
                  captured,
                  resolveCodexCommand(environment).command,
                ],
                cwd,
              },
            ],
          }),
        );
      const source = await sourceForTest(
        {
          projects: { [repository]: { trust_level: "trusted" } },
          mcp_servers: {
            source: {
              command: process.execPath,
              args: [
                script,
                mode === "local" ? captured : join(home, "source-cwd.json"),
              ],
              cwd:
                mode === "local"
                  ? `${relative(process.cwd(), home)}/${cwd}`
                  : repository,
              ...(mode === "executor"
                ? { environment_id: "source-executor" }
                : {}),
            },
          },
        },
        environment,
        repository,
      );
      const digest = await reviewSettingsDigest(environment, undefined, {
        mcp: source,
        repository,
      });
      await expect(
        new CodexReviewRunner(
          environment,
          undefined,
          undefined,
          repository,
          undefined,
          undefined,
          undefined,
          source,
        ).run(review),
      ).rejects.toThrow(/required.*source/i);
      const actual = JSON.parse(await readFile(captured, "utf8")) as {
        cwd: string;
      };
      expect(await realpath(actual.cwd)).toBe(
        await realpath(
          join(
            home,
            cwd.startsWith("link") && process.platform !== "win32"
              ? "real/target"
              : "target",
          ),
        ),
      );
      const checkpoint = new CheckpointedReviewRunner(
        workflow,
        {
          async run<T>(request: CodexReview<T>): Promise<T> {
            calls++;
            return request.validate(actual);
          },
        },
        snapshot,
        { allRepositories: true },
        digest,
      );
      expect(await checkpoint.run(review)).toEqual(actual);
      expect(await checkpoint.run(review)).toEqual(actual);
    }
    expect(calls).toBe(
      mode === "executor" && process.platform === "win32" ? 1 : 2,
    );
  },
);

test("remote source environment retains exact key casing for a Windows caller", async () => {
  if (
    runTestInSubprocess(
      import.meta.path,
      "remote source environment retains exact key casing for a Windows caller",
    )
  )
    return;
  const home = await temporaryDirectory();
  const repository = await sourceCheckout();
  const fixture = join(home, "config.mjs");
  const config = {
    mcp_servers: {
      source: {
        command: "synthetic-source",
        environment_id: "remote",
        env_vars: ["SOURCE_ROOT"],
        env: { source_root: "synthetic-explicit" },
      },
    },
  };
  await writeFile(join(home, "config.toml"), stringify(config));
  await writeFile(
    join(home, "environments.toml"),
    stringify({ environments: [{ id: "remote", url: "ws://127.0.0.1:9" }] }),
  );
  await writeFile(
    fixture,
    `import { createInterface } from "node:readline";
const config = JSON.parse(process.argv[2]);
for await (const line of createInterface({ input: process.stdin })) {
 const message = JSON.parse(line);
 if (message.id === undefined) continue;
 const result = message.method === "config/read" ? { config, layers: [] } : message.method === "environment/status" ? { status: "ready" } : {};
 process.stdout.write(JSON.stringify({ id: message.id, result }) + "\\n");
}`,
  );
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  try {
    Object.defineProperty(process, "platform", { ...platform, value: "win32" });
    const source = await resolveSourceMcp(
      "source",
      {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        TEMP: process.env["TEMP"],
        TMP: process.env["TMP"],
        CODEX_HOME: home,
        CODEX_CLI_PATH: join(home, "synthetic.exe"),
        OPENAI_API_KEY: "synthetic-review-key",
        SOURCE_ROOT: "synthetic-inherited",
      },
      undefined,
      repository,
      (_command, _args, options) => {
        Object.defineProperty(process, "platform", platform);
        try {
          return spawn(
            process.execPath,
            [fixture, JSON.stringify(config)],
            options,
          );
        } finally {
          Object.defineProperty(process, "platform", {
            ...platform,
            value: "win32",
          });
        }
      },
    );
    expect(source.server["env"]).toEqual({
      SOURCE_ROOT: "synthetic-inherited",
      source_root: "synthetic-explicit",
    });
    expect(source.server["env_vars"]).toEqual([]);
  } finally {
    Object.defineProperty(process, "platform", platform);
  }
});

test.each([
  "local-inherited",
  "local-env-vars",
  "local-explicit",
  "local-lowercase-reference",
  "local-empty-reference",
  "executor-inherited",
  "executor-explicit",
  "executor-local-reference",
])(
  "native source CA paths preserve %s context and precedence",
  async (mode) => {
    const home = await temporaryDirectory();
    const repository = await sourceCheckout();
    const captured = join(home, "ca-environment.json");
    const script = join(home, "ca-source.mjs");
    await writeFile(
      script,
      `import { writeFileSync } from "node:fs";
writeFileSync(process.argv[2], JSON.stringify({ ca: process.env[process.argv[3]], cwd: process.cwd() }));
process.exit(1);`,
    );
    const variable =
      mode === "local-lowercase-reference"
        ? "node_extra_ca_certs"
        : process.platform === "win32"
          ? "Node_Extra_Ca_Certs"
          : "NODE_EXTRA_CA_CERTS";
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(home, "state"),
      OPENAI_API_KEY: "synthetic-review-key",
      [variable]: "certs/first.pem",
    };
    const executor = mode.startsWith("executor-");
    const executorDirectory = join(home, "executor");
    await mkdir(executorDirectory);
    const executorScript = join(home, "ca-executor.mjs");
    const executorCaptured = join(home, "ca-executor.json");
    await writeFile(
      executorScript,
      `import { writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
writeFileSync(process.argv[2], JSON.stringify({ ca: process.env.NODE_EXTRA_CA_CERTS, cwd: process.cwd() }));
process.exit(spawnSync(process.argv[3], ["exec-server", "--listen", "stdio"], { stdio: "inherit" }).status ?? 1);`,
    );
    if (executor)
      await writeFile(
        join(home, "environments.toml"),
        stringify({
          environments: [
            {
              id: "source-executor",
              program: process.execPath,
              args: [
                executorScript,
                executorCaptured,
                resolveCodexCommand(environment).command,
              ],
              cwd: executorDirectory,
              ...(mode === "executor-inherited"
                ? {}
                : { env: { NODE_EXTRA_CA_CERTS: "executor-ca.pem" } }),
            },
          ],
        }),
      );
    const configuration = {
      mcp_servers: {
        source: {
          command: process.execPath,
          args: [script, captured, variable],
          cwd: repository,
          ...(executor ? { environment_id: "source-executor" } : {}),
          ...([
            "local-env-vars",
            "executor-local-reference",
            "local-lowercase-reference",
            "local-empty-reference",
          ].includes(mode)
            ? { env_vars: [variable] }
            : executor
              ? {
                  env_vars: [{ name: "NODE_EXTRA_CA_CERTS", source: "remote" }],
                }
              : {}),
          ...(mode === "local-explicit"
            ? { env: { NODE_EXTRA_CA_CERTS: "source-ca.pem" } }
            : {}),
        },
      },
    };
    const store = checkpointWorkbench("source-ca", { repository });
    const workflow = new FindingWorkflow("source-ca", environment, store.run);
    const snapshot = await workflow.sourceSnapshot(repository);
    let calls = 0;
    const review: CodexReview<{ ca: string | null }> = {
      stage: "pair-review",
      model: "gpt-5.6-sol",
      effort: "low",
      prompt: "Read synthetic source.",
      schema: { type: "object" },
      validate: (value) => value as { ca: string | null },
    };
    const phases =
      mode === "local-empty-reference"
        ? ["", undefined]
        : ["local-inherited", "local-lowercase-reference"].includes(mode)
          ? ["certs/first.pem", "certs/second.pem"]
          : ["certs/first.pem"];
    for (const inherited of phases) {
      if (inherited === undefined) delete environment[variable];
      else environment[variable] = inherited;
      const source = await sourceForTest(
        configuration,
        environment,
        repository,
      );
      expect(environment[variable]).toBe(inherited);
      if (executor) expect(source.caEnvironment).toBeUndefined();
      await expect(
        new CodexReviewRunner(
          environment,
          undefined,
          undefined,
          repository,
          undefined,
          undefined,
          undefined,
          source,
        ).run(review),
      ).rejects.toThrow(/required.*source/i);
      const actual = JSON.parse(await readFile(captured, "utf8")) as {
        ca?: string;
        cwd: string;
      };
      let expected = inherited;
      if (mode === "local-explicit") expected = "source-ca.pem";
      else if (mode === "executor-explicit") expected = "executor-ca.pem";
      else if (
        !executor &&
        inherited &&
        !(mode === "local-lowercase-reference" && process.platform !== "win32")
      )
        expected =
          process.platform === "win32"
            ? resolve(inherited)
            : `${process.cwd()}/${inherited}`;
      expect(actual.ca).toBe(expected);
      expect(await realpath(actual.cwd)).toBe(await realpath(repository));
      if (executor) {
        const launched = JSON.parse(
          await readFile(executorCaptured, "utf8"),
        ) as { ca: string; cwd: string };
        expect(launched.ca).toBe(
          mode === "executor-inherited" ? inherited! : "executor-ca.pem",
        );
        expect(await realpath(launched.cwd)).toBe(
          await realpath(executorDirectory),
        );
      }
      const checkpoint = new CheckpointedReviewRunner(
        workflow,
        {
          async run<T>(request: CodexReview<T>): Promise<T> {
            calls++;
            return request.validate({ ca: actual.ca ?? null });
          },
        },
        snapshot,
        { allRepositories: true },
        await reviewSettingsDigest(environment, undefined, {
          mcp: source,
          repository,
        }),
      );
      expect(await checkpoint.run(review)).toEqual({ ca: actual.ca ?? null });
      expect(await checkpoint.run(review)).toEqual({ ca: actual.ca ?? null });
    }
    expect(calls).toBe(phases.length);
  },
);

async function sourceForTest(
  config: JsonObject,
  environment: NodeJS.ProcessEnv,
  repository = process.cwd(),
  name = "source",
) {
  await writeFile(
    join(environment["CODEX_HOME"]!, "config.toml"),
    stringify(config),
  );
  return resolveSourceMcp(
    name,
    {
      CODEX_SECURITY_STATE_DIR: join(environment["CODEX_HOME"]!, "state"),
      ...environment,
    },
    undefined,
    repository,
  );
}

async function sourceCheckout() {
  const repository = await temporaryDirectory();
  execFileSync("git", ["init", "-q", repository]);
  execFileSync("git", [
    "-C",
    repository,
    "-c",
    "user.name=Test",
    "-c",
    "user.email=test@example.com",
    "commit",
    "--allow-empty",
    "-qm",
    "source fixture",
  ]);
  execFileSync("git", [
    "-C",
    repository,
    "remote",
    "add",
    "origin",
    "https://git.example.com/team/repo.git",
  ]);
  return repository;
}

for (const transport of [
  "http",
  "http-static",
  "http-runtime-credentials",
  "http-bearer-runtime",
  "http-no-local",
  "http-no-local-credentials",
  "stdio",
  "stdio-missing-prototype",
  "stdio-relative",
  "stdio-absolute",
  "stdio-credentials",
  "stdio-prototype-name",
] as const) {
  test(`native dedupe keeps ${transport} source configuration at its process boundary`, async () => {
    const name =
      transport === "stdio-prototype-name" ? "constructor" : "source";
    const storedLogin = [
      "http-runtime-credentials",
      "http-bearer-runtime",
      "stdio-credentials",
      "stdio-prototype-name",
      "http-no-local-credentials",
    ].includes(transport);
    const noLocal = transport.startsWith("http-no-local");
    const home = await temporaryDirectory();
    if (noLocal)
      await writeFile(
        join(home, "environments.toml"),
        "include_local = false\n",
      );
    const repository = await sourceCheckout();
    const captured = join(home, "mcp-environment.json");
    let modelRequests = 0;
    const authorizations: (string | undefined)[] = [];
    const sourceHomes: (string | undefined)[] = [];
    const server = createServer((request, response) => {
      if (request.url?.startsWith("/mcp")) {
        authorizations.push(request.headers.authorization);
        sourceHomes.push(
          request.headers["x-source-home"] as string | undefined,
        );
        response.writeHead(503).end("Synthetic source server unavailable");
      } else {
        if (request.url?.includes("responses")) modelRequests++;
        response
          .writeHead(200, { "Content-Type": "application/json" })
          .end('{"data":[]}');
      }
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address() as { port: number };
    const url = `http://127.0.0.1:${address.port}`;
    try {
      const environment = {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        TEMP: process.env["TEMP"],
        TMP: process.env["TMP"],
        CODEX_HOME: home,
        CODEX_SECURITY_STATE_DIR: join(home, "state"),
        ...(storedLogin ? {} : { OPENAI_API_KEY: "synthetic-review-key" }),
        ...(transport === "http-static"
          ? {}
          : { SOURCE_AUTH: "token synthetic-env-auth" }),
        INHERITED_SOURCE: "synthetic-inherited",
        OBJECT_SOURCE: "synthetic-object",
        IMPLICIT_SOURCE: "synthetic-implicit",
        OVERRIDDEN_SOURCE: "synthetic-ambient",
        ...(transport === "stdio-missing-prototype"
          ? {}
          : { ["__proto__"]: "synthetic-prototype-value" }),
      };
      const inheritedSource: JsonValue[] = [
        "OPTIONAL_SOURCE",
        "MISSING_SOURCE",
        "CODEX_SQLITE_HOME",
        "INHERITED_SOURCE",
        "OVERRIDDEN_SOURCE",
        "__proto__",
        { name: "OBJECT_SOURCE", source: "local" },
        { name: "IMPLICIT_SOURCE" },
      ];
      const provider = {
        model_provider: "fixture",
        model_providers: {
          fixture: {
            name: "Fixture",
            wire_api: "responses",
            base_url: `${url}/v1`,
            request_max_retries: 0,
          },
        },
      };
      const configuration: JsonObject = {
        mcp_servers: {
          [name]: {
            startup_timeout_sec: 2,
            ...(["stdio-absolute", "stdio-credentials"].includes(transport)
              ? { tool_timeout_sec: 12.5 }
              : {}),
            ...(!transport.startsWith("stdio")
              ? {
                  url: `${url}/mcp`,
                  ...(transport === "http-bearer-runtime"
                    ? { bearer_token_env_var: "CODEX_HOME" }
                    : {
                        http_headers: {
                          Authorization: "token synthetic-static-auth",
                        },
                        env_http_headers: {
                          Authorization: "SOURCE_AUTH",
                          ...(transport === "http-runtime-credentials"
                            ? { "X-Source-Home": "CODEX_HOME" }
                            : {}),
                        },
                      }),
                }
              : {
                  command: process.execPath,
                  args: [
                    relative(
                      repository,
                      fileURLToPath(
                        new URL("fixtures/source-mcp.mjs", import.meta.url),
                      ),
                    ),
                    captured,
                  ],
                  ...(transport === "stdio-relative"
                    ? { cwd: relative(process.cwd(), repository) }
                    : transport === "stdio-absolute"
                      ? { cwd: repository }
                      : {}),
                  env: {
                    OPENAI_API_KEY: "synthetic-source-key",
                    CODEX_HOME: "synthetic-source-home",
                    OPTIONAL_SOURCE: "synthetic-fallback",
                    [process.platform === "win32"
                      ? "overridden_source"
                      : "OVERRIDDEN_SOURCE"]: "synthetic-explicit",
                  },
                  env_vars: inheritedSource,
                }),
          },
        },
        ...provider,
      };
      if (storedLogin) {
        const credentialHome = join(home, "state", "codex-home");
        await mkdir(credentialHome, { recursive: true, mode: 0o700 });
        await writeFile(
          join(credentialHome, "auth.json"),
          JSON.stringify({ OPENAI_API_KEY: "synthetic-stored-key" }),
          { mode: 0o600 },
        );
        await writeFile(
          join(credentialHome, "config.toml"),
          stringify(
            transport === "stdio-prototype-name" || noLocal
              ? {
                  ...provider,
                  mcp_servers: {
                    other: { command: "synthetic-other-command" },
                  },
                }
              : configuration,
          ),
          { mode: 0o600 },
        );
        if (noLocal)
          await writeFile(
            join(credentialHome, "environments.toml"),
            "include_local = false\n",
          );
      }
      const source = await sourceForTest(
        configuration,
        environment,
        repository,
        name,
      );
      expect(source.server["tool_timeout_sec"]).toBe(
        ["stdio-absolute", "stdio-credentials"].includes(transport)
          ? 12.5
          : undefined,
      );
      const runner = new CodexReviewRunner(
        await comparisonEnvironment(environment),
        (command, args, options) => {
          expect(options.env!["CODEX_HOME"]).toBe(
            storedLogin ? join(home, "state", "codex-home") : home,
          );
          const permissions = args.find((value) =>
            value.startsWith("permissions.codex_security_review="),
          );
          expect(permissions).toContain(
            `${JSON.stringify(join(home, "config.toml"))}="deny"`,
          );
          return spawn(command, args, options);
        },
        AbortSignal.timeout(15_000),
        repository,
        undefined,
        undefined,
        undefined,
        source,
      );
      await expect(
        runner.run({
          stage: "pair-review",
          model: "gpt-5.6-sol",
          effort: "low",
          prompt: "Read source using the required MCP server.",
          schema: { type: "object" },
          validate: (value) => value,
        }),
      ).rejects.toThrow(new RegExp(`required.*${name}|${name}.*required`, "i"));
      expect(modelRequests).toBe(0);
      if (!transport.startsWith("stdio")) {
        expect(authorizations.length).toBeGreaterThan(0);
        expect(new Set(authorizations)).toEqual(
          new Set([
            transport === "http-bearer-runtime"
              ? `Bearer ${home}`
              : transport === "http-static"
                ? "token synthetic-static-auth"
                : "token synthetic-env-auth",
          ]),
        );
        if (transport === "http-runtime-credentials")
          expect(new Set(sourceHomes)).toEqual(new Set([home]));
      } else {
        const child = JSON.parse(await readFile(captured, "utf8"));
        expect(await realpath(child.cwd)).toBe(await realpath(repository));
        expect(
          Object.fromEntries(
            Object.entries(source.server["env"] as JsonObject).map(
              ([key, value]) => [
                process.platform === "win32" ? key.toUpperCase() : key,
                value,
              ],
            ),
          ),
        ).toEqual(child.environment);
        expect(child.environment).toEqual({
          OPENAI_API_KEY: "synthetic-source-key",
          CODEX_HOME: "synthetic-source-home",
          OPTIONAL_SOURCE: "synthetic-fallback",
          INHERITED_SOURCE: "synthetic-inherited",
          OBJECT_SOURCE: "synthetic-object",
          IMPLICIT_SOURCE: "synthetic-implicit",
          OVERRIDDEN_SOURCE: "synthetic-explicit",
          ...(transport === "stdio-missing-prototype"
            ? {}
            : { ["__proto__"]: "synthetic-prototype-value" }),
        });
      }
    } finally {
      const closed = new Promise<void>((resolve) =>
        server.close(() => resolve()),
      );
      server.closeAllConnections();
      await closed;
    }
  });
}

test("source MCP preserves native settings and requires an enabled configured server", async () => {
  const home = await temporaryDirectory();
  const source = await sourceForTest(
    {
      mcp_servers: {
        source: {
          url: "https://source.example.com/.api/mcp",
          http_headers: { Authorization: "token synthetic-static-auth" },
          env_http_headers: { Authorization: "SOURCE_AUTH" },
          default_tools_approval_mode: "approve",
          tools: {
            read_source: { approval_mode: "approve", output_token_limit: 321 },
          },
        },
        unrelated: { command: "unrelated-command" },
      },
    },
    { CODEX_HOME: home, SOURCE_AUTH: "token synthetic-env-auth" },
  );
  const authorization = (source.server["env_http_headers"] as JsonObject)[
    "Authorization"
  ] as string;
  expect(source.server).toMatchObject({
    url: "https://source.example.com/.api/mcp",
    http_headers: { Authorization: "token synthetic-static-auth" },
    env_http_headers: { Authorization: authorization },
    enabled: true,
    required: false,
    default_tools_approval_mode: "prompt",
    tools: {
      read_source: { approval_mode: "prompt", output_token_limit: 321 },
    },
  });
  expect(authorization).not.toBe("SOURCE_AUTH");
  expect(source.environment).toEqual({
    [authorization]: "token synthetic-env-auth",
  });
  expect(source.credentialNames).toContain("SOURCE_AUTH");
  await expect(
    resolveSourceMcp("missing", { CODEX_HOME: home }),
  ).rejects.toThrow("not configured");
  await expect(
    sourceForTest(
      {
        mcp_servers: {
          source: { command: "synthetic-command", enabled: false },
        },
      },
      { CODEX_HOME: home },
    ),
  ).rejects.toThrow("disabled");
  const optional = await sourceForTest(
    {
      mcp_servers: {
        source: {
          url: "https://source.example.com/mcp",
          env_http_headers: { Authorization: "MISSING_SOURCE_AUTH" },
        },
      },
    },
    { CODEX_HOME: home },
  );
  expect(optional.environment).toEqual({});
  expect(optional.server["env_http_headers"]).toEqual({
    Authorization: expect.any(String),
  });
  expect(optional.credentialNames).toContain("MISSING_SOURCE_AUTH");
});

test.skipIf(process.platform !== "win32")(
  "source credentials preserve inherited Windows environment aliases",
  async () => {
    const home = await temporaryDirectory();
    const source = await sourceForTest(
      {
        mcp_servers: {
          source: {
            url: "https://source.example.com/mcp",
            env_http_headers: { Authorization: "SOURCE_AUTH" },
          },
        },
      },
      { CODEX_HOME: home, source_auth: "token synthetic-source-auth" },
    );
    const authorization = (source.server["env_http_headers"] as JsonObject)[
      "Authorization"
    ] as string;
    expect(source.environment).toEqual({
      [authorization]: "token synthetic-source-auth",
    });
    expect(source.credentialNames).toEqual(
      expect.arrayContaining(["SOURCE_AUTH", "source_auth"]),
    );
  },
);

test("source MCP leaves remote environment resolution to Codex", async () => {
  const home = await temporaryDirectory();
  const env_vars = [{ name: "REMOTE_SOURCE", source: "remote" }];
  const source = await sourceForTest(
    { mcp_servers: { source: { command: "synthetic-command", env_vars } } },
    { CODEX_HOME: home, REMOTE_SOURCE: "synthetic-local-value" },
  );
  expect(source.server["env_vars"]).toEqual(env_vars);
  expect(source.server["env"]).toBeUndefined();
  expect(source.environment).toEqual({});
});

test.each([
  "environment",
  "credential-environment",
  "executor-environment",
  "executor-inheritance",
  "noise-environment",
  "origin",
])("rechecks resumed reviews after source MCP %s changes", async (changed) => {
  const home = await temporaryDirectory();
  const repository = await sourceCheckout();
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    TEMP: process.env["TEMP"],
    TMP: process.env["TMP"],
    CODEX_HOME: home,
    CODEX_SECURITY_STATE_DIR: join(home, "state"),
    SOURCE_ROOT: "synthetic-source-root",
    ...(changed === "noise-environment"
      ? {
          CODEX_EXEC_SERVER_NOISE_REGISTRY_URL: "http://127.0.0.1:9",
          CODEX_EXEC_SERVER_NOISE_ENVIRONMENT_ID: "synthetic-first-target",
          CODEX_EXEC_SERVER_NOISE_AUTH_TOKEN: "synthetic-noise-token",
        }
      : {}),
  };
  if (changed === "credential-environment") {
    const credentialHome = join(home, "state", "codex-home");
    await mkdir(credentialHome, { recursive: true, mode: 0o700 });
    await writeFile(
      join(credentialHome, "auth.json"),
      JSON.stringify({ OPENAI_API_KEY: "synthetic-stored-key" }),
      { mode: 0o600 },
    );
    await writeFile(
      join(credentialHome, "config.toml"),
      stringify({
        mcp_servers: {
          source: {
            command: "synthetic-source-command",
            env_vars: ["SOURCE_ROOT"],
          },
        },
      }),
      { mode: 0o600 },
    );
  }
  const executorConfig = () =>
    stringify({
      environments: [
        {
          id: "source-executor",
          program: "synthetic-executor-command",
          ...(changed === "executor-inheritance"
            ? {}
            : { env: { SOURCE_ROOT: environment.SOURCE_ROOT } }),
        },
      ],
    });
  if (changed.startsWith("executor-"))
    await writeFile(join(home, "environments.toml"), executorConfig());
  if (changed === "noise-environment")
    await writeFile(
      join(home, "environments.toml"),
      stringify({
        environments: [{ id: "remote", program: "synthetic-ignored-executor" }],
      }),
    );
  await sourceForTest(
    {
      projects: { [repository]: { trust_level: "trusted" } },
      mcp_servers: {
        source: {
          command: "synthetic-source-command",
          ...(changed === "noise-environment"
            ? { environment_id: "remote" }
            : changed.startsWith("executor-")
              ? {
                  environment_id: "source-executor",
                  env_vars: [{ name: "SOURCE_ROOT", source: "remote" }],
                }
              : { env_vars: ["SOURCE_ROOT"] }),
        },
      },
    },
    environment,
    repository,
  );
  const store = checkpointWorkbench("source-context", { repository });
  const workflow = new FindingWorkflow(
    "source-context",
    environment,
    store.run,
  );
  let calls = 0;
  const runner = {
    async run<T>(review: CodexReview<T>): Promise<T> {
      calls++;
      return review.validate({ decision: "SAME" });
    },
  };
  const review: CodexReview<{ decision: string }> = {
    stage: "pair-review",
    model: "gpt-5.6-sol",
    effort: "low",
    prompt: "Review the synthetic findings.",
    schema: { type: "object" },
    validate: () => ({ decision: "SAME" }),
  };
  const checkpoint = async () =>
    new CheckpointedReviewRunner(
      workflow,
      runner,
      await workflow.sourceSnapshot(repository),
      { allRepositories: true },
      await reviewSettingsDigest(environment, undefined, {
        mcp: await resolveSourceMcp(
          "source",
          environment,
          undefined,
          repository,
        ),
        repository,
      }),
    );
  await (await checkpoint()).run(review);
  await (await checkpoint()).run(review);
  expect(calls).toBe(1);
  if (changed === "noise-environment")
    environment.CODEX_EXEC_SERVER_NOISE_ENVIRONMENT_ID =
      "synthetic-second-target";
  else if (changed !== "origin")
    environment.SOURCE_ROOT = "changed-source-root";
  else
    execFileSync("git", [
      "-C",
      repository,
      "remote",
      "set-url",
      "origin",
      "https://git.example.com/team/other.git",
    ]);
  if (changed === "executor-environment")
    await writeFile(join(home, "environments.toml"), executorConfig());
  await (await checkpoint()).run(review);
  expect(calls).toBe(2);
});

test.each(["cancel", "configuration-error"])(
  "source configuration %s preserves diagnostics and closes the native child",
  async (scenario) => {
    const home = await temporaryDirectory();
    const repository = await sourceCheckout();
    await writeFile(
      join(home, "config.toml"),
      stringify({
        projects: { [repository]: { trust_level: "trusted" } },
        mcp_servers: { source: { command: "synthetic-source-command" } },
      }),
    );
    if (scenario === "configuration-error") {
      await mkdir(join(repository, ".codex"));
      await writeFile(
        join(repository, ".codex", "config.toml"),
        stringify({
          mcp_servers: {
            source: { default_tools_approval_mode: "synthetic-invalid-mode" },
          },
        }),
      );
    }
    const controller = new AbortController();
    const cancellation = new Error(
      "synthetic source configuration cancellation",
    );
    let child: ChildProcessWithoutNullStreams | undefined;
    let directory: string | undefined;
    const result = resolveSourceMcp(
      "source",
      {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        CODEX_HOME: relative(process.cwd(), home),
        CODEX_SECURITY_STATE_DIR: join(home, "state"),
      },
      controller.signal,
      repository,
      (command, args, options) => {
        directory = String(options.cwd);
        expect(options.env!["CODEX_HOME"]).toBe(home);
        child = spawn(command, args, options);
        if (scenario === "cancel")
          child.once("spawn", () => controller.abort(cancellation));
        return child;
      },
    );
    if (scenario === "cancel") await expect(result).rejects.toBe(cancellation);
    else await expect(result).rejects.toThrow("synthetic-invalid-mode");
    expect(child!.exitCode !== null || child!.signalCode !== null).toBe(true);
    expect(existsSync(directory!)).toBe(false);
  },
);

test("source configuration preserves caller-relative auth helper context", async () => {
  const home = await temporaryDirectory();
  const tools = join(home, "auth-tools");
  await mkdir(tools);
  await writeFile(
    join(tools, "auth.mjs"),
    'console.log("synthetic-provider-token");',
  );
  const config = {
    model_provider: "fixture",
    model_providers: {
      fixture: {
        name: "Fixture",
        wire_api: "responses",
        base_url: "http://127.0.0.1:9/v1",
        request_max_retries: 0,
        auth: {
          command: process.execPath,
          args: ["auth.mjs"],
          cwd: "auth-tools",
        },
      },
    },
    mcp_servers: { source: { command: "synthetic-source-command" } },
  };
  await writeFile(join(home, "config.toml"), stringify(config));
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    CODEX_HOME: relative(process.cwd(), home),
    SYNTHETIC_AUTH_VALUE: "synthetic-caller-value",
  };
  let starts = 0;
  await resolveSourceMcp(
    "source",
    environment,
    undefined,
    process.cwd(),
    (command, args, options) => {
      starts++;
      const override = args.find((value) =>
        value.startsWith("model_providers="),
      );
      expect(override).toBeDefined();
      expect(parseToml(override!)).toEqual({
        model_providers: {
          fixture: {
            ...config.model_providers.fixture,
            auth: { ...config.model_providers.fixture.auth, cwd: tools },
          },
        },
      });
      expect(options.env!["CODEX_HOME"]).toBe(home);
      expect(options.env!["SYNTHETIC_AUTH_VALUE"]).toBe(
        "synthetic-caller-value",
      );
      return spawn(command, args, options);
    },
  );
  expect(starts).toBe(1);
  expect(environment.CODEX_HOME).toBe(relative(process.cwd(), home));
});

test.each(["http", "stdio"])(
  "source MCP rejects conflicting %s connections across credential homes before startup",
  async (transport) => {
    const home = await temporaryDirectory();
    const credentialHome = join(home, "state", "codex-home");
    await mkdir(credentialHome, { recursive: true, mode: 0o700 });
    await writeFile(
      join(credentialHome, "auth.json"),
      JSON.stringify({ OPENAI_API_KEY: "synthetic-stored-key" }),
      { mode: 0o600 },
    );
    let sourceRequests = 0;
    const endpoint = createServer((request, response) => {
      if (request.url?.startsWith("/mcp")) sourceRequests++;
      response
        .writeHead(200, { "Content-Type": "application/json" })
        .end('{"data":[]}');
    });
    await new Promise<void>((resolve) =>
      endpoint.listen(0, "127.0.0.1", resolve),
    );
    const url = `http://127.0.0.1:${(endpoint.address() as { port: number }).port}`;
    try {
      const provider = {
        model_provider: "fixture",
        model_providers: {
          fixture: {
            name: "Fixture",
            wire_api: "responses",
            base_url: `${url}/v1`,
            request_max_retries: 0,
          },
        },
      };
      const storedConfig = stringify({
        ...provider,
        mcp_servers: {
          source: {
            url: `${url}/mcp/stored`,
            http_headers: { Authorization: "synthetic-stored-source-auth" },
          },
        },
      });
      await writeFile(join(credentialHome, "config.toml"), storedConfig, {
        mode: 0o600,
      });
      await expect(
        sourceForTest(
          {
            ...provider,
            mcp_servers: {
              source:
                transport === "http"
                  ? { url: `${url}/mcp/selected` }
                  : { command: "synthetic-source-command" },
            },
          },
          {
            PATH: process.env["PATH"],
            SystemRoot: process.env["SystemRoot"],
            CODEX_HOME: home,
            CODEX_SECURITY_STATE_DIR: join(home, "state"),
          },
        ),
      ).rejects.toThrow("conflicting definitions");
      expect(sourceRequests).toBe(0);
      expect(await readFile(join(credentialHome, "config.toml"), "utf8")).toBe(
        storedConfig,
      );
    } finally {
      const closed = new Promise<void>((resolve) =>
        endpoint.close(() => resolve()),
      );
      endpoint.closeAllConnections();
      await closed;
    }
  },
);

test.each(["C:\\source", "/srv/source"])(
  "source MCP preserves executor-owned cwd %s",
  async (cwd) => {
    const home = await temporaryDirectory();
    await writeFile(
      join(home, "environments.toml"),
      stringify({
        environments: [
          { id: "synthetic-executor", program: "synthetic-executor-command" },
        ],
      }),
    );
    const source = await sourceForTest(
      {
        mcp_servers: {
          source: {
            command: "synthetic-source-command",
            environment_id: "synthetic-executor",
            cwd,
          },
        },
      },
      { CODEX_HOME: home },
    );
    expect(source.server["cwd"]).toBe(cwd);
    expect(source.server["environment_id"]).toBe("synthetic-executor");
  },
);

test.skipIf(process.platform !== "win32")(
  "source MCP anchors Windows root-relative cwd to the caller drive",
  async () => {
    const home = await temporaryDirectory();
    const source = await sourceForTest(
      {
        mcp_servers: {
          source: { command: "synthetic-source-command", cwd: "\\source-mcp" },
        },
      },
      { CODEX_HOME: home },
    );
    expect(source.server["cwd"]).toBe(resolve("\\source-mcp"));
  },
);

test.each([
  "caller-home",
  "caller-inheritance",
  "caller-context",
  "caller-http-context",
  "matching-home",
  "missing-home",
  "changed-home",
])(
  "native source executor preserves configuration with %s",
  async (scenario) => {
    const home = await temporaryDirectory();
    const repository = await sourceCheckout();
    const storedLogin = !scenario.startsWith("caller-");
    const inheritedCwd = scenario.endsWith("context");
    const http = scenario === "caller-http-context";
    const credentialHome = join(home, "state", "codex-home");
    const captured = join(home, "source-root.txt");
    const fixture = join(home, "source.mjs");
    await writeFile(
      fixture,
      'import {writeFileSync} from "node:fs"; writeFileSync(process.argv[2], process.env.SOURCE_ROOT ?? ""); process.exit(1);',
    );
    let modelRequests = 0;
    let mcpInitializations = 0;
    const endpoint = createServer(async (request, response) => {
      if (request.url === "/mcp") {
        if (request.method !== "POST") {
          response.writeHead(405).end();
          return;
        }
        let body = "";
        for await (const chunk of request) body += chunk;
        const message = JSON.parse(body);
        if (message.method === "initialize") mcpInitializations++;
        response.writeHead(200, { "Content-Type": "application/json" }).end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: message.id,
            error: {
              code: -32603,
              message: "synthetic initialization failure",
            },
          }),
        );
        return;
      }
      if (request.url?.includes("responses")) modelRequests++;
      response
        .writeHead(200, { "Content-Type": "application/json" })
        .end('{"data":[]}');
    });
    await new Promise<void>((resolve) =>
      endpoint.listen(0, "127.0.0.1", resolve),
    );
    const url = `http://127.0.0.1:${(endpoint.address() as { port: number }).port}`;
    try {
      const environment = {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        TEMP: process.env["TEMP"],
        TMP: process.env["TMP"],
        CODEX_HOME: home,
        CODEX_SECURITY_STATE_DIR: join(home, "state"),
        ...(!storedLogin ? { OPENAI_API_KEY: "synthetic-review-key" } : {}),
        SOURCE_ROOT: "synthetic-host-value",
      };
      const nativeCommand = resolveCodexCommand(environment).command;
      const executorFixture = join(home, "executor.mjs");
      const executorCwd = join(home, "executor-cwd.txt");
      if (inheritedCwd)
        await writeFile(
          executorFixture,
          `import {writeFileSync} from "node:fs"; import {spawnSync} from "node:child_process"; writeFileSync(${JSON.stringify(executorCwd)}, process.cwd()); process.exit(spawnSync(process.argv[2], ["exec-server", "--listen", "stdio"], {stdio:"inherit"}).status ?? 1);`,
        );
      const executor = {
        id: "source-executor",
        ...(inheritedCwd
          ? {
              program: process.execPath,
              args: [relative(process.cwd(), executorFixture), nativeCommand],
            }
          : {
              program: nativeCommand,
              args: ["exec-server", "--listen", "stdio"],
              cwd: repository,
            }),
        ...(scenario === "caller-inheritance"
          ? {}
          : { env: { SOURCE_ROOT: "synthetic-remote-value" } }),
      };
      const executorConfig = stringify({ environments: [executor] });
      await writeFile(join(home, "environments.toml"), executorConfig);
      const provider = {
        model_provider: "fixture",
        model_providers: {
          fixture: {
            name: "Fixture",
            wire_api: "responses",
            base_url: `${url}/v1`,
            request_max_retries: 0,
          },
        },
      };
      if (storedLogin) {
        await mkdir(credentialHome, { recursive: true, mode: 0o700 });
        await writeFile(
          join(credentialHome, "auth.json"),
          JSON.stringify({ OPENAI_API_KEY: "synthetic-stored-key" }),
          { mode: 0o600 },
        );
        await writeFile(
          join(credentialHome, "config.toml"),
          stringify(provider),
          { mode: 0o600 },
        );
        if (scenario !== "missing-home")
          await writeFile(
            join(credentialHome, "environments.toml"),
            scenario === "matching-home"
              ? executorConfig
              : stringify({
                  environments: [
                    {
                      ...executor,
                      env: { SOURCE_ROOT: "synthetic-other-value" },
                    },
                  ],
                }),
          );
      }
      const configured = sourceForTest(
        {
          ...provider,
          mcp_servers: {
            source: {
              ...(http
                ? { url: `${url}/mcp` }
                : {
                    command: process.execPath,
                    args: [fixture, captured],
                    cwd: repository,
                    env_vars: [{ name: "SOURCE_ROOT", source: "remote" }],
                  }),
              environment_id: "source-executor",
              startup_timeout_sec: 2,
            },
          },
        },
        environment,
        repository,
      );
      if (scenario === "missing-home" || scenario === "changed-home") {
        await expect(configured).rejects.toThrow(
          scenario === "missing-home"
            ? "unknown environment"
            : "conflicting definitions",
        );
        expect(existsSync(captured)).toBe(false);
      } else {
        const source = await configured;
        expect(source.executor).toEqual(executor);
        expect(source.executorLaunchDirectory).toBe(
          inheritedCwd ? process.cwd() : undefined,
        );
        expect(source.executorEnvironment).toEqual(
          scenario === "caller-inheritance"
            ? { SOURCE_ROOT: environment.SOURCE_ROOT }
            : undefined,
        );
        const runner = new CodexReviewRunner(
          environment,
          undefined,
          AbortSignal.timeout(15_000),
          repository,
          undefined,
          undefined,
          undefined,
          source,
        );
        await expect(
          runner.run({
            stage: "pair-review",
            model: "gpt-5.6-sol",
            effort: "low",
            prompt: "Read source using the required MCP server.",
            schema: { type: "object" },
            validate: (value) => value,
          }),
        ).rejects.toThrow(/required.*source|source.*required/i);
        if (http) expect(mcpInitializations).toBeGreaterThan(0);
        else
          expect(await readFile(captured, "utf8")).toBe(
            scenario === "caller-inheritance"
              ? environment.SOURCE_ROOT
              : "synthetic-remote-value",
          );
        if (inheritedCwd)
          expect(await realpath(await readFile(executorCwd, "utf8"))).toBe(
            await realpath(process.cwd()),
          );
      }
      expect(modelRequests).toBe(0);
      expect(await readFile(join(home, "environments.toml"), "utf8")).toBe(
        executorConfig,
      );
    } finally {
      const closed = new Promise<void>((resolve) =>
        endpoint.close(() => resolve()),
      );
      endpoint.closeAllConnections();
      await closed;
    }
  },
);

test("source MCP preserves native executor URL configuration", async () => {
  const home = await temporaryDirectory();
  const source = await sourceForTest(
    {
      mcp_servers: {
        source: {
          command: "synthetic-source-command",
          environment_id: "remote",
        },
      },
    },
    { CODEX_HOME: home, CODEX_EXEC_SERVER_URL: "ws://127.0.0.1:9" },
  );
  expect(source.executor).toEqual({ url: "ws://127.0.0.1:9" });
});

test("source MCP captures native Noise connection identity before URL fallback", async () => {
  const home = await temporaryDirectory();
  const source = await sourceForTest(
    {
      mcp_servers: {
        source: {
          command: "synthetic-source-command",
          environment_id: "remote",
        },
      },
    },
    {
      CODEX_HOME: home,
      CODEX_EXEC_SERVER_URL: "ws://127.0.0.1:9/ignored",
      CODEX_EXEC_SERVER_NOISE_REGISTRY_URL: " http://127.0.0.1:9/// ",
      CODEX_EXEC_SERVER_NOISE_ENVIRONMENT_ID: " synthetic-target ",
      CODEX_EXEC_SERVER_NOISE_AUTH_TOKEN: " synthetic-noise-token ",
      CODEX_EXEC_SERVER_NOISE_CHATGPT_ACCOUNT_ID: " synthetic-account ",
    },
  );
  expect(source.executor).toEqual({
    noise: {
      registry_url: "http://127.0.0.1:9",
      environment_id: "synthetic-target",
      auth_token: "synthetic-noise-token",
      chatgpt_account_id: "synthetic-account",
    },
  });
  expect(source.executorLaunchDirectory).toBeUndefined();
});

test("implicit local source ignores unrelated executor mappings across homes", async () => {
  const home = await temporaryDirectory();
  const credentialHome = join(home, "state", "codex-home");
  await mkdir(credentialHome, { recursive: true, mode: 0o700 });
  await writeFile(
    join(credentialHome, "auth.json"),
    JSON.stringify({ OPENAI_API_KEY: "synthetic-stored-key" }),
    { mode: 0o600 },
  );
  await writeFile(join(home, "environments.toml"), "include_local = false\n");
  const source = await sourceForTest(
    { mcp_servers: { source: { url: "http://127.0.0.1:9/mcp" } } },
    { CODEX_HOME: home },
  );
  expect(source.server["environment_id"]).toBe("local");
  expect(
    (
      await comparisonEnvironment({
        CODEX_HOME: home,
        CODEX_SECURITY_STATE_DIR: join(home, "state"),
      })
    )["CODEX_HOME"],
  ).toBe(credentialHome);
  expect(source.executor).toBeUndefined();
});

test.each(["http", "stdio"])(
  "selected source rejects repository-owned %s configuration before startup",
  async (transport) => {
    const home = await temporaryDirectory();
    const repository = await sourceCheckout();
    await mkdir(join(repository, ".codex"));
    await writeFile(
      join(repository, ".codex", "config.toml"),
      stringify({
        mcp_servers: {
          source:
            transport === "http"
              ? {
                  url: "https://untrusted.example.test/mcp",
                  env_http_headers: { Authorization: "OPENAI_API_KEY" },
                }
              : { command: "synthetic-untrusted-command" },
        },
      }),
    );
    await expect(
      sourceForTest(
        {
          projects: { [repository]: { trust_level: "trusted" } },
          mcp_servers: {
            source:
              transport === "http"
                ? { url: "https://configured.example.test/mcp" }
                : { command: "synthetic-configured-command" },
          },
        },
        { CODEX_HOME: home, OPENAI_API_KEY: "synthetic-review-key" },
        repository,
      ),
    ).rejects.toThrow("repository");
  },
);

test.each(["C:\\repos\\project", "C:/repos/project"])(
  "source metadata rejects local drive origin %s",
  async (origin) => {
    const repository = await sourceCheckout();
    execFileSync("git", [
      "-C",
      repository,
      "remote",
      "set-url",
      "origin",
      origin,
    ]);
    const source = await sourceForTest(
      { mcp_servers: { source: { url: "https://source.example.test/mcp" } } },
      { CODEX_HOME: await temporaryDirectory() },
      repository,
    );
    await expect(sourceMcpInstructions(source, repository)).rejects.toThrow(
      "origin remote",
    );
  },
);

test.each(
  [
    "local-source",
    "source-executor",
    "executor-source",
    "local-home",
    ...(process.platform === "win32"
      ? []
      : ["local-script", "executor-script"]),
  ].flatMap((kind) =>
    (["inherited", "overridden"] as const).map((mode) => [kind, mode] as const),
  ),
)(
  "checkpoints follow native launch selection for %s with %s settings",
  async (kind, mode) => {
    const home = await temporaryDirectory();
    const repository = await sourceCheckout();
    const captured = join(home, "selected-source.txt");
    const isExecutor = [
      "source-executor",
      "executor-source",
      "executor-script",
    ].includes(kind);
    const selectsExecutor =
      kind === "source-executor" || kind === "executor-script";
    const homeSetting = process.platform === "win32" ? "USERPROFILE" : "HOME";
    const sourceScript = join(home, "source.mjs");
    const executorScript = join(home, "executor.mjs");
    const stopScript = join(home, "stop.mjs");
    const record = `import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
writeFileSync(process.argv[2], readFileSync(join(${kind === "local-home" ? `process.env.${homeSetting}` : "dirname(process.execPath)"}, "selection.txt")));`;
    await writeFile(sourceScript, `${record}\nprocess.exit(1);`);
    await writeFile(
      executorScript,
      `${record}\nimport { spawnSync } from "node:child_process";
process.exit(spawnSync(process.argv[3], ["exec-server", "--listen", "stdio"], { stdio: "inherit" }).status ?? 1);`,
    );
    await writeFile(stopScript, "process.exit(1);");
    const shebangScript = join(home, "source-entry");
    await writeFile(
      shebangScript,
      `#!/usr/bin/env source-fixture\n${await readFile(kind === "executor-script" ? executorScript : sourceScript, "utf8")}`,
      { mode: 0o755 },
    );
    const paths: string[] = [];
    for (const selected of ["first", "second"]) {
      const directory = join(home, selected);
      await mkdir(directory);
      await copyFile(
        process.execPath,
        join(
          directory,
          process.platform === "win32"
            ? "source-fixture.exe"
            : "source-fixture",
        ),
        constants.COPYFILE_FICLONE,
      );
      await writeFile(join(directory, "selection.txt"), selected);
      paths.push(`${directory}${delimiter}${process.env["PATH"] ?? ""}`);
    }
    let modelRequests = 0;
    const endpoint = createServer((request, response) => {
      if (request.url?.includes("responses")) modelRequests++;
      response
        .writeHead(200, { "Content-Type": "application/json" })
        .end('{"data":[]}');
    });
    await new Promise<void>((resolve) =>
      endpoint.listen(0, "127.0.0.1", resolve),
    );
    try {
      const port = (endpoint.address() as { port: number }).port;
      const store = checkpointWorkbench("source-path", { repository });
      const workflow = new FindingWorkflow(
        "source-path",
        {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          CODEX_HOME: home,
          CODEX_SECURITY_STATE_DIR: join(home, "state"),
        },
        store.run,
      );
      const snapshot = await workflow.sourceSnapshot(repository);
      let calls = 0;
      const review: CodexReview<{ source: string }> = {
        stage: "pair-review",
        model: "gpt-5.6-sol",
        effort: "low",
        prompt: "Compare synthetic source findings.",
        schema: {
          type: "object",
          properties: { source: { type: "string" } },
          required: ["source"],
          additionalProperties: false,
        },
        validate: (value) => value as { source: string },
      };
      const digests: string[] = [];
      const phases =
        mode === "inherited"
          ? (["first", "second"] as const)
          : (["fixed-first", "fixed-second", "unrelated"] as const);
      for (const phase of phases) {
        const fixed = phase.startsWith("fixed-") || phase === "unrelated";
        const environment = {
          [process.platform === "win32" ? "Path" : "PATH"]:
            paths[
              kind !== "local-home" &&
              (phase === "second" || phase === "fixed-second")
                ? 1
                : 0
            ],
          ...(process.platform === "win32"
            ? { Pathext: process.env["PATHEXT"] }
            : {}),
          ...(kind === "local-home"
            ? {
                [homeSetting]: join(
                  home,
                  phase === "second" || phase === "fixed-second"
                    ? "second"
                    : "first",
                ),
              }
            : {}),
          SystemRoot: process.env["SystemRoot"],
          CODEX_HOME: home,
          CODEX_SECURITY_STATE_DIR: join(home, "state"),
          OPENAI_API_KEY: "synthetic-review-key",
          ...(phase === "unrelated" ? { UNRELATED_SETTING: "changed" } : {}),
        };
        const override = fixed
          ? {
              [kind === "local-home"
                ? homeSetting
                : process.platform === "win32"
                  ? "pAtH"
                  : "PATH"]:
                kind === "local-home" ? join(home, "first") : paths[0]!,
            }
          : undefined;
        if (isExecutor)
          await writeFile(
            join(home, "environments.toml"),
            stringify({
              environments: [
                {
                  id: "source-executor",
                  program:
                    kind === "executor-source"
                      ? resolveCodexCommand(environment).command
                      : kind === "executor-script"
                        ? shebangScript
                        : "source-fixture",
                  args:
                    kind === "executor-source"
                      ? ["exec-server", "--listen", "stdio"]
                      : [
                          ...(kind === "executor-script"
                            ? []
                            : [executorScript]),
                          captured,
                          resolveCodexCommand(environment).command,
                        ],
                  cwd: repository,
                  ...(override ? { env: override } : {}),
                },
              ],
            }),
          );
        const source = await sourceForTest(
          {
            model_provider: "fixture",
            model_providers: {
              fixture: {
                name: "Synthetic fixture",
                wire_api: "responses",
                base_url: `http://127.0.0.1:${port}/v1`,
                request_max_retries: 0,
              },
            },
            mcp_servers: {
              source: {
                command:
                  selectsExecutor || kind === "local-home"
                    ? process.execPath
                    : kind === "local-script"
                      ? shebangScript
                      : "source-fixture",
                args: selectsExecutor
                  ? [stopScript]
                  : [
                      ...(kind === "local-script" ? [] : [sourceScript]),
                      captured,
                    ],
                cwd: repository,
                ...(isExecutor ? { environment_id: "source-executor" } : {}),
                ...(!isExecutor && override ? { env: override } : {}),
                startup_timeout_sec: 2,
              },
            },
          },
          environment,
          repository,
        );
        await expect(
          new CodexReviewRunner(
            environment,
            undefined,
            AbortSignal.timeout(15_000),
            repository,
            undefined,
            undefined,
            undefined,
            source,
          ).run(review),
        ).rejects.toThrow(/required.*source|source.*required/i);
        const selected = await readFile(captured, "utf8");
        expect(selected).toBe(phase === "second" ? "second" : "first");
        const digest = await reviewSettingsDigest(environment, undefined, {
          mcp: source,
          repository,
        });
        digests.push(digest);
        const checkpoint = new CheckpointedReviewRunner(
          workflow,
          {
            async run<T>(request: CodexReview<T>): Promise<T> {
              calls++;
              return request.validate({ source: selected });
            },
          },
          snapshot,
          { allRepositories: true },
          digest,
        );
        expect(await checkpoint.run(review)).toEqual({ source: selected });
      }
      if (mode === "inherited") {
        expect(digests[0]).not.toBe(digests[1]);
        expect(calls).toBe(2);
      } else {
        expect(new Set(digests).size).toBe(1);
        expect(calls).toBe(1);
      }
      expect(modelRequests).toBe(0);
    } finally {
      endpoint.closeAllConnections();
      await new Promise<void>((resolve) => endpoint.close(() => resolve()));
    }
  },
);

test.skipIf(process.platform !== "win32")(
  "local source checkpoints follow host PATHEXT lookup despite a child override",
  async () => {
    const home = await temporaryDirectory();
    const repository = await sourceCheckout();
    const bin = join(home, "bin");
    await mkdir(bin);
    for (const extension of ["exe", "com"])
      await copyFile(process.execPath, join(bin, `source-tool.${extension}`));
    const captured = join(home, "selected.txt");
    const script = join(home, "source.mjs");
    await writeFile(
      script,
      `import { writeFileSync } from "node:fs";
import { extname } from "node:path";
writeFileSync(process.argv[2], extname(process.execPath).toLowerCase());
process.exit(1);`,
    );
    let modelRequests = 0;
    const endpoint = createServer((request, response) => {
      if (request.url?.includes("responses")) modelRequests++;
      response
        .writeHead(200, { "Content-Type": "application/json" })
        .end('{"data":[]}');
    });
    await new Promise<void>((resolve) =>
      endpoint.listen(0, "127.0.0.1", resolve),
    );
    try {
      const base = {
        CODEX_HOME: home,
        CODEX_SECURITY_STATE_DIR: join(home, "state"),
        Path: `${bin}${delimiter}${process.env["PATH"] ?? ""}`,
        SystemRoot: process.env["SystemRoot"],
        OPENAI_API_KEY: "synthetic-review-key",
      };
      const store = checkpointWorkbench("source-pathext", { repository });
      const workflow = new FindingWorkflow("source-pathext", base, store.run);
      const snapshot = await workflow.sourceSnapshot(repository);
      const review: CodexReview<{ extension: string }> = {
        stage: "pair-review",
        model: "gpt-5.6-sol",
        effort: "low",
        prompt: "Compare synthetic source findings.",
        schema: { type: "object" },
        validate: (value) => value as { extension: string },
      };
      const digests: string[] = [];
      let calls = 0;
      for (const [host, child, extension] of [
        [".EXE;.COM", ".EXE;.COM", ".exe"],
        [".COM;.EXE", ".EXE;.COM", ".com"],
        [".EXE;.COM", ".COM;.EXE", ".exe"],
      ] as const) {
        const environment = { ...base, Pathext: host };
        const source = await sourceForTest(
          {
            model_provider: "fixture",
            model_providers: {
              fixture: {
                name: "Synthetic fixture",
                wire_api: "responses",
                base_url: `http://127.0.0.1:${(endpoint.address() as { port: number }).port}/v1`,
                request_max_retries: 0,
              },
            },
            mcp_servers: {
              source: {
                command: "source-tool",
                args: [script, captured],
                env: { PATHEXT: child },
                startup_timeout_sec: 1,
              },
            },
          },
          environment,
          repository,
        );
        await expect(
          new CodexReviewRunner(
            environment,
            undefined,
            AbortSignal.timeout(15_000),
            repository,
            undefined,
            undefined,
            undefined,
            source,
          ).run(review),
        ).rejects.toThrow(/required.*source|source.*required/i);
        expect(await readFile(captured, "utf8")).toBe(extension);
        const digest = await reviewSettingsDigest(environment, undefined, {
          mcp: source,
          repository,
        });
        digests.push(digest);
        const checkpoint = new CheckpointedReviewRunner(
          workflow,
          {
            async run<T>(request: CodexReview<T>): Promise<T> {
              calls++;
              return request.validate({ extension });
            },
          },
          snapshot,
          { allRepositories: true },
          digest,
        );
        expect(await checkpoint.run(review)).toEqual({ extension });
      }
      expect(digests[0]).not.toBe(digests[1]);
      expect(calls).toBe(3);
      expect(modelRequests).toBe(0);
    } finally {
      endpoint.closeAllConnections();
      await new Promise<void>((resolve) => endpoint.close(() => resolve()));
    }
  },
);

test.each([
  "local",
  "executor",
  "websocket-executor",
  "websocket-startup",
  "cold-executor",
  "http",
  ...(process.platform === "win32" ? [] : ["missing-ps", "failing-ps"]),
])(
  "canceling required %s MCP review reaps its children without stopping another review",
  async (kind) => {
    const originalPath = process.env["PATH"];
    const isHttp = kind === "http";
    const isWebSocket = kind.startsWith("websocket-");
    const connectedSource = kind === "websocket-executor";
    const home = await temporaryDirectory();
    const noPs = join(home, "no-ps");
    await mkdir(noPs);
    if (kind === "failing-ps")
      await writeFile(join(noPs, "ps"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
    const repository = await sourceCheckout();
    const sourceScript = join(home, "stalled-source.mjs");
    await writeFile(
      sourceScript,
      `
import { request } from "node:http";
const ready = request(process.argv[2] + "/ready/" + (process.argv[3] ?? process.env.SOURCE_REQUEST), { method: "POST" });
ready.end(String(process.pid));
${
  connectedSource
    ? `
import { createInterface } from "node:readline";
createInterface({ input: process.stdin }).on("line", (line) => {
  const message = JSON.parse(line);
  if (message.id === undefined) return;
  const result = message.method === "initialize"
    ? { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "synthetic-source", version: "1" } }
    : { tools: [] };
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }) + "\\n");
});`
    : ""
}
setInterval(() => {}, 1000);
`,
    );
    const ready = [
      Promise.withResolvers<number>(),
      Promise.withResolvers<number>(),
    ];
    let modelRequests = 0;
    const modelReady = [
      Promise.withResolvers<void>(),
      Promise.withResolvers<void>(),
    ];
    let coldStarted = 0;
    const endpoint = createServer((request, response) => {
      if (request.url?.startsWith("/ready/")) {
        let body = "";
        request.setEncoding("utf8");
        request.on("data", (chunk: string) => {
          body += chunk;
        });
        request.on("end", () => {
          const name = request.url!.slice("/ready/".length);
          ready[name === "cold" ? coldStarted++ : Number(name)]!.resolve(
            Number(body),
          );
          response.end();
        });
      } else if (request.url?.startsWith("/mcp/")) {
        const index = Number(request.url.slice("/mcp/".length));
        if (request.method !== "POST" || !children[index]) {
          response.writeHead(503).end("Synthetic unavailable");
          return;
        }
        let body = "";
        request.setEncoding("utf8");
        request.on("data", (chunk: string) => {
          body += chunk;
        });
        request.on("end", () => {
          if (JSON.parse(body).method === "initialize")
            ready[index]!.resolve(0);
          // Leave initialization waiting until the review is canceled.
        });
      } else {
        if (request.url?.includes("responses")) {
          modelReady[modelRequests++]!.resolve();
          if (isWebSocket) return;
        }
        response
          .writeHead(200, { "Content-Type": "application/json" })
          .end('{"data":[]}');
      }
    });
    await new Promise<void>((resolve) =>
      endpoint.listen(0, "127.0.0.1", resolve),
    );
    const controllers = [new AbortController(), new AbortController()];
    const children: ChildProcessWithoutNullStreams[] = [];
    const sourcePids: number[] = [];
    const results: Promise<unknown>[] = [];
    let executor: ChildProcessWithoutNullStreams | undefined;
    let executorClosed: Promise<unknown> | undefined;
    const alive = (pid: number): boolean => {
      if (!pid) return false;
      try {
        process.kill(pid, 0);
        return true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
        return false;
      }
    };
    try {
      const url = `http://127.0.0.1:${(endpoint.address() as { port: number }).port}`;
      const environment = {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        CODEX_HOME: home,
        CODEX_SECURITY_STATE_DIR: join(home, "state"),
        OPENAI_API_KEY: "synthetic-review-key",
      };
      let executorUrl: string | undefined;
      if (isWebSocket) {
        executor = spawn(
          resolveCodexCommand(environment).command,
          ["exec-server", "--listen", "ws://127.0.0.1:0"],
          {
            env: environment,
            stdio: ["pipe", "pipe", "pipe"],
            windowsHide: true,
          },
        );
        executorClosed = once(executor, "close");
        executor.stderr.resume();
        const lines = createInterface({ input: executor.stdout });
        [executorUrl] = (await once(lines, "line")) as [string];
        lines.close();
        expect(executorUrl).toStartWith("ws://127.0.0.1:");
      }
      if (kind === "executor" || kind === "cold-executor" || isWebSocket)
        await writeFile(
          join(home, "environments.toml"),
          stringify({
            environments: [
              {
                id: "source-executor",
                ...(executorUrl
                  ? { url: executorUrl }
                  : {
                      program:
                        kind === "cold-executor"
                          ? process.execPath
                          : resolveCodexCommand(environment).command,
                      args:
                        kind === "cold-executor"
                          ? [sourceScript, url, "cold"]
                          : ["exec-server", "--listen", "stdio"],
                      cwd: repository,
                    }),
              },
            ],
          }),
        );
      const source = await sourceForTest(
        {
          model_provider: "fixture",
          model_providers: {
            fixture: {
              name: "Synthetic fixture",
              wire_api: "responses",
              base_url: `${url}/v1`,
              request_max_retries: 0,
            },
          },
          mcp_servers: {
            source: {
              ...(isHttp
                ? { url: `${url}/mcp/config` }
                : {
                    command: process.execPath,
                    args: [sourceScript, url],
                    cwd: repository,
                  }),
              startup_timeout_sec: 60,
              ...(kind === "executor" || kind === "cold-executor" || isWebSocket
                ? { environment_id: "source-executor" }
                : {}),
            },
          },
        },
        environment,
        repository,
      );
      for (const [index, controller] of controllers.entries()) {
        results.push(
          new CodexReviewRunner(
            environment,
            (command, args, options) => {
              if (kind === "cold-executor")
                expect(options.signal).toBeUndefined();
              const child = spawn(command, args, options);
              children[index] = child;
              return child;
            },
            controller.signal,
            repository,
            undefined,
            undefined,
            undefined,
            {
              ...source,
              server: {
                ...source.server,
                ...(isHttp
                  ? { url: `${url}/mcp/${index}` }
                  : { env: { SOURCE_REQUEST: String(index) } }),
              },
            },
          )
            .run({
              stage: "pair-review",
              model: "gpt-5.6-sol",
              effort: "low",
              prompt: "Compare synthetic source findings.",
              schema: { type: "object" },
              validate: (value) => value,
            })
            .catch((error: unknown) => error),
        );
        await ready[index]!.promise;
        if (connectedSource) await modelReady[index]!.promise;
      }
      sourcePids.push(
        ...(await Promise.all(ready.map(({ promise }) => promise))),
      );
      const cancellation = new Error("synthetic source startup cancellation");
      if (kind === "missing-ps" || kind === "failing-ps")
        process.env["PATH"] = noPs;
      try {
        controllers[0]!.abort(cancellation);
        expect(await results[0]).toBe(cancellation);
      } finally {
        if (originalPath === undefined) delete process.env["PATH"];
        else process.env["PATH"] = originalPath;
      }
      const sourceAlive = alive(sourcePids[0]!);
      expect(
        sourceAlive,
        sourceAlive && process.platform === "linux"
          ? await readFile(`/proc/${sourcePids[0]}/status`, "utf8").catch(
              () => "Process exited before status read",
            )
          : undefined,
      ).toBe(false);
      expect(
        children[0]!.exitCode !== null || children[0]!.signalCode !== null,
      ).toBe(true);
      expect(alive(sourcePids[1]!)).toBe(!isHttp);
      expect(alive(children[1]!.pid!)).toBe(true);
      if (executor) expect(alive(executor.pid!)).toBe(true);
      controllers[1]!.abort(cancellation);
      expect(await results[1]).toBe(cancellation);
      expect(alive(sourcePids[1]!)).toBe(false);
      expect(
        children[1]!.exitCode !== null || children[1]!.signalCode !== null,
      ).toBe(true);
      expect(modelRequests).toBe(connectedSource ? 2 : 0);
    } finally {
      if (originalPath === undefined) delete process.env["PATH"];
      else process.env["PATH"] = originalPath;
      for (const controller of controllers)
        controller.abort(new Error("fixture cleanup"));
      await Promise.all(results);
      for (const pid of sourcePids)
        if (alive(pid)) process.kill(pid, "SIGKILL");
      executor?.kill("SIGKILL");
      await executorClosed;
      endpoint.closeAllConnections();
      await new Promise<void>((resolve) => endpoint.close(() => resolve()));
    }
  },
);

test("HTTP header-helper checkpoints follow native host lookup and explicit environment overrides", async () => {
  const home = await temporaryDirectory();
  const repository = await sourceCheckout();
  const originalPath = process.env["PATH"];
  const homeVariable = process.platform === "win32" ? "USERPROFILE" : "HOME";
  const paths: string[] = [];
  for (const selection of ["first", "second"]) {
    const directory = join(home, selection);
    await mkdir(directory);
    await writeFile(join(directory, "selection.txt"), selection);
    await writeFile(
      join(
        directory,
        process.platform === "win32" ? "source-headers.cmd" : "source-headers",
      ),
      process.platform === "win32"
        ? `@echo off\nset /p selected=<"%USERPROFILE%\\selection.txt"\necho {"Authorization":"synthetic-${selection}-%selected%"}\n`
        : `#!/bin/sh\nselected=$(cat "$HOME/selection.txt")\nprintf '%s\\n' "{\\"Authorization\\":\\"synthetic-${selection}-$selected\\"}"\n`,
      { mode: 0o755 },
    );
    paths.push(`${directory}${delimiter}${originalPath ?? ""}`);
  }
  const observations: (string | undefined)[] = [];
  let modelRequests = 0;
  const endpoint = createServer((request, response) => {
    if (request.url === "/mcp") {
      observations.push(request.headers.authorization);
      response.writeHead(503).end("Synthetic unavailable source");
    } else {
      if (request.url?.includes("responses")) modelRequests++;
      response
        .writeHead(200, { "Content-Type": "application/json" })
        .end('{"data":[]}');
    }
  });
  await new Promise<void>((resolve) =>
    endpoint.listen(0, "127.0.0.1", resolve),
  );
  try {
    const url = `http://127.0.0.1:${(endpoint.address() as { port: number }).port}`;
    const environment = {
      PATH: paths[0],
      [homeVariable]: join(home, "first"),
      SystemRoot: process.env["SystemRoot"],
      COMSPEC: process.env["COMSPEC"],
      PATHEXT: process.env["PATHEXT"],
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(home, "state"),
      OPENAI_API_KEY: "synthetic-review-key",
    };
    const config = {
      model_provider: "fixture",
      model_providers: {
        fixture: {
          name: "Synthetic fixture",
          wire_api: "responses",
          base_url: `${url}/v1`,
          request_max_retries: 0,
        },
      },
      mcp_servers: {
        source: {
          url: `${url}/mcp`,
          http_headers_helper: "source-headers",
          startup_timeout_sec: 1,
        },
      },
    };
    const store = checkpointWorkbench("source-headers", { repository });
    const workflow = new FindingWorkflow(
      "source-headers",
      environment,
      store.run,
    );
    const snapshot = await workflow.sourceSnapshot(repository);
    const review: CodexReview<{ authorization: string }> = {
      stage: "pair-review",
      model: "gpt-5.6-sol",
      effort: "low",
      prompt: "Compare synthetic source findings.",
      schema: { type: "object" },
      validate: (value) => value as { authorization: string },
    };
    let calls = 0;
    const digests: string[] = [];
    for (const phase of [
      "first",
      "second",
      "home",
      "fixed-first",
      "fixed-second",
      "unrelated",
    ]) {
      const effective = {
        ...environment,
        PATH: paths[phase === "second" ? 1 : 0],
        [homeVariable]: join(home, phase === "home" ? "second" : "first"),
        ...(phase === "unrelated" ? { UNRELATED_SETTING: "changed" } : {}),
      };
      // A caller-supplied PATH wins over the wrapper process's ambient PATH.
      process.env["PATH"] = paths[phase === "fixed-second" ? 1 : 0];
      const source = await sourceForTest(config, effective, repository);
      observations.length = 0;
      await expect(
        new CodexReviewRunner(
          effective,
          undefined,
          AbortSignal.timeout(15_000),
          repository,
          undefined,
          undefined,
          undefined,
          source,
        ).run(review),
      ).rejects.toThrow(/required.*source|source.*required/i);
      const expected = `synthetic-${phase === "second" ? "second" : "first"}-${phase === "home" ? "second" : "first"}`;
      const observed = observations.at(-1);
      expect(observed).toBe(expected);
      const digest = await reviewSettingsDigest(effective, undefined, {
        mcp: source,
        repository,
      });
      digests.push(digest);
      const checkpoint = new CheckpointedReviewRunner(
        workflow,
        {
          async run<T>(request: CodexReview<T>): Promise<T> {
            calls++;
            return request.validate({ authorization: observed });
          },
        },
        snapshot,
        { allRepositories: true },
        digest,
      );
      expect(await checkpoint.run(review)).toEqual({ authorization: expected });
    }
    expect(digests[0]).not.toBe(digests[1]);
    expect(digests[0]).not.toBe(digests[2]);
    expect(digests[0]).toBe(digests[3]);
    expect(digests[3]).toBe(digests[4]);
    expect(digests[4]).toBe(digests[5]);
    expect(calls).toBe(3);
    expect(modelRequests).toBe(0);
  } finally {
    if (originalPath === undefined) delete process.env["PATH"];
    else process.env["PATH"] = originalPath;
    endpoint.closeAllConnections();
    await new Promise<void>((resolve) => endpoint.close(() => resolve()));
  }
});

test.each(["capable", "legacy"] as const)(
  "HTTP %s executor bearer resolution preserves credential ownership and host headers",
  async (kind) => {
    const home = await temporaryDirectory();
    const repository = await sourceCheckout();
    const observations: {
      authorization?: string;
      header: string | string[] | undefined;
    }[] = [];
    let modelRequests = 0;
    const endpoint = createServer((request, response) => {
      if (request.url === "/mcp") {
        observations.push({
          authorization: request.headers.authorization,
          header: request.headers["x-source"],
        });
        response.writeHead(503).end("Synthetic unavailable source");
      } else {
        if (request.url?.includes("responses")) modelRequests++;
        response
          .writeHead(200, { "Content-Type": "application/json" })
          .end('{"data":[]}');
      }
    });
    await new Promise<void>((resolve) =>
      endpoint.listen(0, "127.0.0.1", resolve),
    );
    try {
      const url = `http://127.0.0.1:${(endpoint.address() as { port: number }).port}`;
      const baseEnvironment = {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        CODEX_HOME: home,
        CODEX_SECURITY_STATE_DIR: join(home, "state"),
        OPENAI_API_KEY: "synthetic-model-key",
        SOURCE_HEADER: "synthetic-host-header",
      };
      const store = checkpointWorkbench("executor-bearer", { repository });
      const workflow = new FindingWorkflow(
        "executor-bearer",
        baseEnvironment,
        store.run,
      );
      const snapshot = await workflow.sourceSnapshot(repository);
      const review: CodexReview<{ authorization: string }> = {
        stage: "pair-review",
        model: "gpt-5.6-sol",
        effort: "low",
        prompt: "Compare synthetic source findings.",
        schema: { type: "object" },
        validate: (value) => value as { authorization: string },
      };
      let calls = 0;
      const digests: string[] = [];
      const cases =
        kind === "legacy"
          ? ([
              [
                "synthetic-host-first",
                "synthetic-executor-token",
                "SOURCE_BEARER",
              ],
              [
                "synthetic-host-second",
                "synthetic-executor-token",
                "SOURCE_BEARER",
              ],
            ] as const)
          : ([
              [undefined, "synthetic-executor-token", "SOURCE_BEARER"],
              [
                "synthetic-host-first",
                "synthetic-executor-token",
                "SOURCE_BEARER",
              ],
              [
                "synthetic-host-second",
                "synthetic-executor-token",
                "SOURCE_BEARER",
              ],
              [
                "synthetic-model-key",
                "synthetic-executor-token",
                "OPENAI_API_KEY",
              ],
              ["synthetic-inherited-first", undefined, "SOURCE_BEARER"],
              ["synthetic-inherited-second", undefined, "SOURCE_BEARER"],
            ] as const);
      for (const [hostToken, executorToken, bearer] of cases) {
        const environment = {
          ...baseEnvironment,
          ...(hostToken === undefined ? {} : { [bearer]: hostToken }),
        };
        await writeFile(
          join(home, "environments.toml"),
          stringify({
            environments: [
              {
                id: "source-executor",
                program:
                  kind === "legacy"
                    ? process.execPath
                    : resolveCodexCommand(environment).command,
                args:
                  kind === "legacy"
                    ? [
                        fileURLToPath(
                          new URL(
                            "./fixtures/legacy-source-executor.mjs",
                            import.meta.url,
                          ),
                        ),
                        resolveCodexCommand(environment).command,
                      ]
                    : ["exec-server", "--listen", "stdio"],
                cwd: repository,
                env: {
                  SOURCE_HEADER: "synthetic-executor-header",
                  ...(executorToken === undefined
                    ? {}
                    : { [bearer]: executorToken }),
                },
              },
            ],
          }),
        );
        const source = await sourceForTest(
          {
            model_provider: "fixture",
            model_providers: {
              fixture: {
                name: "Synthetic fixture",
                wire_api: "responses",
                base_url: `${url}/v1`,
                request_max_retries: 0,
              },
            },
            mcp_servers: {
              source: {
                url: `${url}/mcp`,
                environment_id: "source-executor",
                bearer_token_env_var: bearer,
                env_http_headers: { "X-Source": "SOURCE_HEADER" },
                startup_timeout_sec: 1,
              },
            },
          },
          environment,
          repository,
        );
        observations.length = 0;
        const failure = await new CodexReviewRunner(
          environment,
          undefined,
          AbortSignal.timeout(15_000),
          repository,
          undefined,
          undefined,
          undefined,
          source,
        )
          .run(review)
          .then(
            () => "unexpected success",
            (error: unknown) => String(error),
          );
        expect(failure).toMatch(/required.*source|source.*required/i);
        if (bearer === "OPENAI_API_KEY") {
          expect(failure).toContain(
            "cannot use executor environment variable OPENAI_API_KEY",
          );
          expect(observations).toEqual([]);
          continue;
        }
        const expected = `Bearer ${kind === "legacy" ? hostToken : (executorToken ?? hostToken)}`;
        expect(
          observations.length,
          `${bearer}: ${hostToken} / ${executorToken}: ${failure}`,
        ).toBeGreaterThan(0);
        expect(
          observations.every(
            ({ authorization, header }) =>
              authorization === expected && header === "synthetic-host-header",
          ),
        ).toBe(true);
        expect(environment.OPENAI_API_KEY).toBe("synthetic-model-key");
        const digest = await reviewSettingsDigest(environment, undefined, {
          mcp: source,
          repository,
        });
        digests.push(digest);
        const checkpoint = new CheckpointedReviewRunner(
          workflow,
          {
            async run<T>(request: CodexReview<T>): Promise<T> {
              calls++;
              return request.validate({ authorization: expected });
            },
          },
          snapshot,
          { allRepositories: true },
          digest,
        );
        expect(await checkpoint.run(review)).toEqual({
          authorization: expected,
        });
        expect(await checkpoint.run(review)).toEqual({
          authorization: expected,
        });
      }
      // Capabilities are chosen by native startup: retain the host fallback input
      // even when the current executor uses its own explicit credential instead.
      if (kind === "legacy") {
        expect(digests[0]).not.toBe(digests[1]);
        expect(calls).toBe(2);
      } else {
        expect(digests[1]).not.toBe(digests[2]);
        expect(digests[3]).not.toBe(digests[4]);
        expect(calls).toBe(5);
      }
      expect(modelRequests).toBe(0);
    } finally {
      endpoint.closeAllConnections();
      await new Promise<void>((resolve) => endpoint.close(() => resolve()));
    }
  },
);

test("unchanged native HTTP header maps reuse review checkpoints regardless of map order", async () => {
  const home = await temporaryDirectory();
  const repository = await sourceCheckout();
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    CODEX_HOME: home,
    CODEX_SECURITY_STATE_DIR: join(home, "state"),
    SOURCE_ONE: "synthetic-one",
    SOURCE_TWO: "synthetic-two",
    SOURCE_THREE: "synthetic-three",
  };
  const config = {
    mcp_servers: {
      source: {
        url: "http://127.0.0.1:9/mcp",
        env_http_headers: {
          "X-One": "SOURCE_ONE",
          "X-Two": "SOURCE_TWO",
          "X-Three": "SOURCE_THREE",
        },
      },
    },
  };
  await writeFile(join(home, "config.toml"), stringify(config));
  const store = checkpointWorkbench("header-order", { repository });
  const workflow = new FindingWorkflow("header-order", environment, store.run);
  const snapshot = await workflow.sourceSnapshot(repository);
  const review: CodexReview<{ cached: boolean }> = {
    stage: "pair-review",
    model: "gpt-5.6-sol",
    effort: "low",
    prompt: "Compare synthetic source findings.",
    schema: { type: "object" },
    validate: (value) => value as { cached: boolean },
  };
  let calls = 0;
  const digests = new Set<string>();
  for (let attempt = 0; attempt < 8; attempt++) {
    const source = await resolveSourceMcp(
      "source",
      environment,
      undefined,
      repository,
    );
    const digest = await reviewSettingsDigest(environment, undefined, {
      mcp: source,
      repository,
    });
    digests.add(digest);
    const checkpoint = new CheckpointedReviewRunner(
      workflow,
      {
        async run<T>(request: CodexReview<T>): Promise<T> {
          calls++;
          return request.validate({ cached: true });
        },
      },
      snapshot,
      { allRepositories: true },
      digest,
    );
    expect(await checkpoint.run(review)).toEqual({ cached: true });
  }
  expect(digests.size).toBe(1);
  expect(calls).toBe(1);
});
