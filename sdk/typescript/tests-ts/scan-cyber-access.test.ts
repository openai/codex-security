import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, expect, spyOn, test } from "bun:test";
import { resolveBundledCodexExecutable } from "../src/codex-sdk-environment.js";
import { planComponents } from "../src/component-plan.js";
import type { JsonObject } from "../src/config.js";
import { resolveScanCyberAccessProgram } from "../src/scan-cyber-access.js";
import * as runtime from "../src/runtime.js";
import catalogFixture from "./fixtures/native-skill-model-catalog.json" with { type: "json" };
import { writeJson } from "./support/json.js";
import { chatGptTokens } from "./support/chatgpt-credentials.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures("scan-cyber-");
const endpoint = "http://127.0.0.1:1";
const homeSettings = `chatgpt_base_url="${endpoint}"\nopenai_base_url="${endpoint}/v1"\n`;
const savedLogin = { auth_mode: "chatgpt", tokens: chatGptTokens };
const stored = { environment: { CODEX_API_KEY: "" } };
let home: string;
let catalog: string;

beforeEach(async () => {
  home = await temporaryDirectory();
  catalog = join(home, "catalog.json");
  const base = catalogFixture.models[0]!;
  const model = (slug: string, cyber?: string[]) => ({
    ...base,
    slug,
    available_access_programs: cyber && { cyber },
  });
  await writeJson(join(home, "auth.json"), savedLogin);
  await writeFile(join(home, "config.toml"), homeSettings);
  await writeJson(catalog, {
    models: [
      base,
      { ...model("standard", ["daybreak_red"]), priority: 10 },
      model("standard", ["daybreak_red", "standard"]),
      model("red", ["daybreak_red"]),
      { ...model("chatgpt-only", ["daybreak_red"]), supported_in_api: false },
      model("no-metadata"),
    ],
  });
});
afterEach(cleanup);

function keyEnvironment() {
  return {
    PATH: process.env["PATH"] ?? "",
    ...(process.env["SystemRoot"] && { SystemRoot: process.env["SystemRoot"] }),
    HOME: home,
    USERPROFILE: home,
    CODEX_HOME: home,
    CODEX_API_KEY: "synthetic-scan-key",
  };
}

type SelectorOptions = Pick<
  Parameters<typeof resolveScanCyberAccessProgram>[0],
  "command" | "environment"
>;
function select(
  model: string,
  config: JsonObject = {},
  options: Partial<SelectorOptions> = {},
) {
  return resolveScanCyberAccessProgram({
    cwd: home,
    command: options.command ?? { command: resolveBundledCodexExecutable() },
    environment: { ...keyEnvironment(), ...options.environment },
    model,
    config: {
      model_catalog_json: catalog,
      cli_auth_credentials_store: "file",
      openai_base_url: endpoint + "/v1",
      chatgpt_base_url: endpoint,
      analytics: { enabled: false },
      ...config,
    },
    signal: new AbortController().signal,
  });
}

test("bundled scans use available model programs even with remote discovery disabled", async () => {
  const offline = {
    features: { api_key_model_discovery: false },
    model_catalog_json: "catalog.json",
  };
  expect(await select("gpt-test", offline)).toBe("daybreak_blue");
  expect(await select("standard", offline)).toBe("standard");
  await expect(select("red", offline)).rejects.toThrow(
    "--cyber-access-program daybreak_red",
  );
  for (const model of ["chatgpt-only", "no-metadata", "absent"])
    expect(await select(model, offline)).toBe("standard");
  await expect(select("chatgpt-only", offline, stored)).rejects.toThrow(
    "requires Daybreak Red",
  );
  expect(
    await select("gpt-test", { ...offline, model_catalog_json: null }),
  ).toBe("standard");
  await expect(
    select("gpt-test", { model_catalog_json: "missing.json" }),
  ).rejects.toThrow(/os error 2|ENOENT/i);
});

test("the API-key forwarding gate is scoped to the selected credentials", async () => {
  const disabled = { "features.api_key_cyber_access_programs": false };
  expect(await select("gpt-test", disabled)).toBeUndefined();
  expect(await select("gpt-test", disabled, stored)).toBe("daybreak_blue");
  expect(
    await select("gpt-test", {
      features: { api_key_cyber_access_programs: true },
      ...disabled,
    }),
  ).toBe("daybreak_blue");
});

test("native catalog routing follows the scan's selected identity", async () => {
  const route = {
    model_catalog_json: null,
    "model_providers.openai.model_catalog_url": endpoint + "/private-catalog",
  };
  await expect(select("gpt-test", route)).rejects.toThrow(
    "must use an allowed ChatGPT host",
  );
  await expect(
    select(
      "red",
      {
        model_catalog_json: null,
        "model_providers.openai.model_catalog_url":
          "https://chatgpt.com/custom/models",
      },
      stored,
    ),
  ).rejects.toThrow("Set the catalog URL in the native Codex home");

  await writeFile(
    join(home, "config.toml"),
    homeSettings + `model_catalog_json=${JSON.stringify(catalog)}\n`,
  );
  for (const credentials of [stored, {}])
    expect(await select("gpt-test", route, credentials)).toBe("daybreak_blue");
  expect(await select("chatgpt-only", route)).toBe("standard");
  expect(await Bun.file(join(home, "auth.json")).json()).toEqual(savedLogin);
  await writeJson(join(home, "auth.json"), {
    auth_mode: "apikey",
    OPENAI_API_KEY: "synthetic-stored-key",
  });
  await expect(select("red", route, stored)).rejects.toThrow(
    "requires Daybreak Red",
  );
});

test("the remote catalog subprocess uses only the project key and its private route", async () => {
  const route = "https://chatgpt.com/custom/models";
  using probe = spyOn(runtime, "runCodexCommand").mockImplementation(
    async (command, args, env) => {
      expect(env["CODEX_API_KEY"]).toBe("synthetic-scan-key");
      expect(env["OPENAI_API_KEY"]).toBeUndefined();
      const keyHome = env["CODEX_HOME"]!;
      expect(keyHome).not.toBe(home);
      expect(await Bun.file(join(keyHome, "auth.json")).exists()).toBe(false);
      const config = Bun.TOML.parse(
        await Bun.file(join(keyHome, "config.toml")).text(),
      );
      expect(config).toMatchObject({
        model_providers: { openai: { model_catalog_url: route } },
      });
      expect((command.args ?? []).join(" ")).not.toContain(route);
      expect(args).toEqual(["debug", "models"]);
      return {
        success: true,
        exitCode: 0,
        stderr: "",
        stdout: JSON.stringify(catalogFixture),
      };
    },
  );
  expect(
    await select(
      "gpt-test",
      {
        model_catalog_json: null,
        model_providers: { openai: { model_catalog_url: route } },
      },
      { environment: { OPENAI_API_KEY: "unused-ambient-key" } },
    ),
  ).toBe("daybreak_blue");
  expect(probe).toHaveBeenCalledTimes(1);
});

test("catalog reads and component planning use the saved login for workspace policy", async () => {
  const account = "synthetic-workspace";
  const claims = Buffer.from(
    JSON.stringify({
      sub: "synthetic-user",
      "https://api.openai.com/auth": {
        chatgpt_user_id: "synthetic-user",
        chatgpt_account_id: account,
        chatgpt_plan_type: "enterprise",
      },
    }),
  ).toString("base64url");
  const login = JSON.stringify({
    auth_mode: "chatgpt",
    last_refresh: new Date().toISOString(),
    tokens: {
      ...chatGptTokens,
      account_id: account,
      id_token: `eyJhbGciOiJub25lIn0.${claims}.c2ln`,
    },
  });
  let servedPolicy = false;
  const paths: string[] = [];
  const projectRequests: [string, string | null][] = [];
  const policy = {
    id: "managed",
    name: "Disabled Daybreak",
    contents: "[features]\ncli_daybreak=false\n",
  };
  using server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const path = new URL(request.url).pathname;
      paths.push(path);
      if (path.startsWith("/project/")) {
        projectRequests.push([path, request.headers.get("authorization")]);
        return Response.json(
          { error: { message: "synthetic inference" } },
          { status: 400 },
        );
      }
      if (path !== "/backend-api/wham/config/bundle")
        return new Response(null, { status: 404 });
      if (
        request.headers.get("authorization") !==
          `Bearer ${chatGptTokens.access_token}` ||
        request.headers.get("chatgpt-account-id") !== account
      )
        return new Response(null, { status: 403 });
      servedPolicy = true;
      return Response.json({
        requirements_toml: { enterprise_managed: [policy] },
      });
    },
  });
  const origin = server.url.origin;
  await writeFile(
    join(home, "config.toml"),
    `chatgpt_base_url="${origin}/backend-api"\nopenai_base_url="${origin}/v1"\n[features]\nplugins=true\n`,
  );
  expect(await select("gpt-test", { chatgpt_base_url: origin }, stored)).toBe(
    "daybreak_blue",
  );
  await writeFile(join(home, "auth.json"), login, { mode: 0o600 });
  expect(
    await select("gpt-test", {
      chatgpt_base_url: origin + "/project",
      openai_base_url: origin + "/project/v1",
    }),
  ).toBeUndefined();
  expect(servedPolicy).toBe(true);
  expect(paths.some((path) => path.startsWith("/project"))).toBe(false);
  expect(paths.filter((path) => path.includes("/plugins/"))).toEqual([]);
  const repository = await temporaryDirectory();
  execFileSync("git", ["init", "-q", repository]);
  await writeFile(join(repository, "source.ts"), "export {};\n");
  await expect(
    planComponents(repository, {
      auth: "api-key",
      config: {
        codexOverrides: {
          model: "gpt-test",
          chatgpt_base_url: origin + "/project",
          openai_base_url: origin + "/project/v1",
          model_providers: {
            extra: { name: "Synthetic", wire_api: "responses" },
          },
        },
      },
      environment: keyEnvironment(),
    }),
  ).rejects.toThrow("synthetic inference");
  expect(projectRequests).toContainEqual([
    "/project/v1/responses",
    "Bearer synthetic-scan-key",
  ]);
  for (const [, authorization] of projectRequests)
    expect(authorization).toBe("Bearer synthetic-scan-key");
  expect(await readFile(join(home, "auth.json"), "utf8")).toBe(login);
});

test("native preferences and non-OpenAI authentication bypass automatic selection", async () => {
  const nativePreferences: JsonObject[] = [
    { daybreak: false },
    { daybreak: true },
    { model_provider: "custom" },
    { "features.cli_daybreak": false },
  ];
  for (const config of nativePreferences)
    expect(await select("red", config)).toBeUndefined();
  for (const name of [
    "OPENAI_FEDERATION_RULE_ID",
    "OPENAI_IDENTITY_TOKEN_FILE",
  ]) {
    expect(
      await select("red", {}, { environment: { [name]: "workload" } }),
    ).toBeUndefined();
  }
});

test("custom executables and launch arguments skip discovery", async () => {
  for (const command of [
    { command: "nonexistent-catalog-launcher" },
    { command: resolveBundledCodexExecutable(), args: ["--invalid-for-codex"] },
  ]) {
    expect(await select("red", {}, { command })).toBeUndefined();
  }
});
