import { execFileSync } from "node:child_process";
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
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import type { JsonObject } from "../src/config.js";
import { AuthenticationRequiredError } from "../src/errors.js";
import { readModelCatalog, type CatalogModel } from "../src/model-catalog.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

const models: CatalogModel[] = [
  {
    id: "gpt-5.4",
    model: "gpt-5.4",
    hidden: true,
    upgrade: "gpt-5.5",
    upgradeInfo: { model: "gpt-5.5" },
    defaultReasoningEffort: "medium",
    supportedReasoningEfforts: [
      { reasoningEffort: "medium" },
      { reasoningEffort: "xhigh" },
    ],
  },
  {
    id: "gpt-5.5",
    model: "gpt-5.5",
    hidden: false,
    defaultReasoningEffort: "medium",
    supportedReasoningEfforts: [
      { reasoningEffort: "medium" },
      { reasoningEffort: "xhigh" },
    ],
  },
];

async function fakeCodex(mode = "catalog") {
  const directory = await mkdtemp(join(tmpdir(), "codex-model-catalog-"));
  temporaryDirectories.push(directory);
  const script = join(directory, "codex.mjs");
  const transcript = join(directory, "requests.jsonl");
  const codexHome = join(directory, "prepared home");
  await mkdir(codexHome);
  await writeFile(
    script,
    `
import { appendFileSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import { createInterface } from "node:readline";
const mode = ${JSON.stringify(mode)};
const models = ${JSON.stringify(models)};
const transcript = ${JSON.stringify(transcript)};
writeFileSync(transcript, JSON.stringify({
  args: [basename(process.argv[1]), ...process.argv.slice(2)],
  codexHome: process.env.CODEX_HOME,
  cwd: process.cwd(),
}) + "\\n");
if (mode === "exit") process.exit(1);
const send = (message) => process.stdout.write(JSON.stringify(message) + "\\n");
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  appendFileSync(transcript, JSON.stringify(request) + "\\n");
  if (request.method === "initialized") continue;
  if (request.method === "getAuthStatus") {
    send({ id: request.id, result: { authMethod: mode === "signed-out" ? null
      : mode === "header-auth" ? "headers" : mode === "stored-api-key" ? "apiKey" : "chatgpt",
      authToken: null, requiresOpenaiAuth: true } });
  } else if (request.method === "account/read") {
    send({ id: request.id, result: { account: mode === "signed-out" || mode === "header-auth" || mode === "expired-chatgpt"
      ? null : { type: mode === "stored-api-key" ? "apiKey" : "chatgpt" }, requiresOpenaiAuth: true } });
  } else if (request.method === "model/list") {
    if (mode === "error") {
      send({ id: request.id, error: { code: -32603, message: "Catalog unavailable" } });
    } else if (mode === "malformed") {
      process.stdout.write("not json\\n");
    } else if (mode === "invalid") {
      send({ id: request.id, result: {} });
    } else if (mode === "cursor-cycle") {
      send({ id: request.id, result: { data: [], nextCursor:
        request.params.cursor === "next-page" ? "other-page" : "next-page" } });
    } else {
      send({ method: "account/updated", params: {} });
      send({ id: request.id, result: request.params.cursor
        ? { data: [models[1]], nextCursor: null }
        : { data: [models[0]], nextCursor: "next-page" } });
    }
  } else {
    send({ id: request.id, result: {} });
  }
}
process.exit(0);
`,
  );
  return {
    command: {
      command: execFileSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      }).trim(),
    },
    environment: {
      ...process.env,
      CODEX_HOME: codexHome,
      NODE_OPTIONS: `--import=${pathToFileURL(script).href}`,
    },
    async requests() {
      return (await readFile(transcript, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
    },
  };
}

describe("Codex model catalog", () => {
  test("initializes, reads all pages, and preserves catalog metadata", async () => {
    const fake = await fakeCodex();
    expect(await readModelCatalog(fake.command, fake.environment)).toEqual(
      models,
    );
    const [process, ...requests] = await fake.requests();
    expect(process).toEqual({
      args: ["app-server", "--stdio"],
      codexHome: fake.environment.CODEX_HOME,
      cwd: await realpath(fake.environment.CODEX_HOME),
    });
    expect(requests.map((request) => request.method)).toEqual([
      "initialize",
      "initialized",
      "getAuthStatus",
      "account/read",
      "model/list",
      "model/list",
    ]);
    expect(requests[2].params).toEqual({
      includeToken: false,
      refreshToken: false,
    });
    expect(requests[3].params).toEqual({ refreshToken: false });
    expect(requests[4].params).toEqual({ includeHidden: true });
    expect(requests[5].params).toEqual({
      includeHidden: true,
      cursor: "next-page",
    });
  });

  test.each(["stored-api-key", "signed-out", "header-auth"])(
    "does not claim account availability for %s credentials",
    async (mode) => {
      const fake = await fakeCodex(mode);
      await expect(
        readModelCatalog(fake.command, fake.environment),
      ).rejects.toThrow("Account-specific model availability");
      const [, ...requests] = await fake.requests();
      expect(requests.map((request) => request.method)).toEqual([
        "initialize",
        "initialized",
        "getAuthStatus",
        "account/read",
      ]);
    },
  );

  test("surfaces a native ChatGPT authentication failure before loading catalog advice", async () => {
    const fake = await fakeCodex("expired-chatgpt");
    await expect(
      readModelCatalog(fake.command, fake.environment),
    ).rejects.toBeInstanceOf(AuthenticationRequiredError);
    const [, ...requests] = await fake.requests();
    expect(requests.map((request) => request.method)).toEqual([
      "initialize",
      "initialized",
      "getAuthStatus",
      "account/read",
    ]);
  });

  test("authenticates API keys through stdin using only ephemeral storage", async () => {
    const fake = await fakeCodex();
    await readModelCatalog(fake.command, fake.environment, {
      apiKey: "synthetic-catalog-key",
    });
    const [process, ...requests] = await fake.requests();
    expect(process.args).toEqual([
      "app-server",
      "--stdio",
      "--config",
      'cli_auth_credentials_store="ephemeral"',
    ]);
    expect(requests.map((request) => request.method)).toEqual([
      "initialize",
      "initialized",
      "account/login/start",
      "model/list",
      "model/list",
    ]);
    expect(requests[2].params).toEqual({
      type: "apiKey",
      apiKey: "synthetic-catalog-key",
    });
  });

  test("passes effective settings as TOML overrides without changing the shared home", async () => {
    const fake = await fakeCodex();
    const config: JsonObject = {
      model: "gpt-5.4",
      model_reasoning_effort: "medium",
      profile: "review",
      profiles: {
        review: { model: "gpt-5.5", model_reasoning_effort: "xhigh" },
        "review.extra": { model: "gpt-5.4" },
      },
      openai_base_url: "https://provider.example.test/v1",
      model_catalog_json: 'C:\\Synthetic Workspace\\models "scan".json',
      projects: {
        "C:\\Synthetic Workspace\\source": { trust_level: "trusted" },
      },
      cli_auth_credentials_store: "file",
    };
    const savedConfig = 'profile = "saved"\n';
    const savedPath = join(fake.environment.CODEX_HOME, "config.toml");
    await writeFile(savedPath, savedConfig);
    expect(
      await readModelCatalog(fake.command, fake.environment, {
        config,
        apiKey: "synthetic-catalog-key",
      }),
    ).toEqual(models);
    const [process] = await fake.requests();
    const args = process.args as string[];
    const overrides = args.filter(
      (_value, index) => args[index - 1] === "--config",
    );
    expect(overrides).toContain('model="gpt-5.4"');
    expect(overrides.some((value) => value.startsWith("profiles="))).toBe(true);
    expect(
      Object.assign(
        {},
        ...overrides.slice(0, -1).map((value) => parseToml(value)),
      ),
    ).toEqual(config);
    expect(overrides.at(-1)).toBe('cli_auth_credentials_store="ephemeral"');
    expect(args.join("\n")).not.toContain("synthetic-catalog-key");
    expect(await readFile(savedPath, "utf8")).toBe(savedConfig);
  });

  test("rejects pagination cycles without repeatedly requesting the same page", async () => {
    const fake = await fakeCodex("cursor-cycle");
    await expect(
      readModelCatalog(fake.command, fake.environment),
    ).rejects.toThrow("repeated model catalog cursor");
    const [, ...requests] = await fake.requests();
    expect(
      requests
        .filter((request) => request.method === "model/list")
        .map((request) => request.params.cursor),
    ).toEqual([undefined, "next-page", "other-page"]);
  });

  test.each([
    ["exit", "Codex exited"],
    ["error", "Catalog unavailable"],
    ["malformed", "malformed model catalog JSON"],
    ["invalid", "invalid model catalog"],
  ])("reports %s and closes the subprocess", async (mode, message) => {
    const fake = await fakeCodex(mode);
    await expect(
      readModelCatalog(fake.command, fake.environment),
    ).rejects.toThrow(message);
  });

  test("preserves cancellation before launching Codex", async () => {
    const reason = new Error("Canceled catalog lookup");
    await expect(
      readModelCatalog(
        { command: join(tmpdir(), "unused-codex") },
        {},
        { signal: AbortSignal.abort(reason) },
      ),
    ).rejects.toBe(reason);
  });
});
