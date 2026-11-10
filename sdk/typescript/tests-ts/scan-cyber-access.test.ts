import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, spyOn, test } from "bun:test";
import { resolveBundledCodexExecutable } from "../src/codex-sdk-environment.js";
import type { JsonObject } from "../src/config.js";
import { resolveScanCyberAccessProgram } from "../src/scan-cyber-access.js";
import * as runtime from "../src/runtime.js";
import { chatGptTokens } from "./support/chatgpt-credentials.js";

const loopback = "http://127.0.0.1:1";
const savedLogin = JSON.stringify({
  auth_mode: "chatgpt",
  tokens: chatGptTokens,
});
const privateUrl = "http://127.0.0.1:1/private-catalog";
const privateRoute = {
  model_providers: { openai: { model_catalog_url: privateUrl } },
};
let home: string;
let catalog: string;

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "scan-cyber-access-"));
  catalog = join(home, "catalog.json");
  const fixture = JSON.parse(
    await readFile(
      new URL("./fixtures/native-skill-model-catalog.json", import.meta.url),
      "utf8",
    ),
  ).models[0];
  const model = (slug: string, cyber?: string[]) => ({
    ...fixture,
    slug,
    available_access_programs: cyber && { cyber },
  });
  await Promise.all([
    writeFile(join(home, "auth.json"), savedLogin, { mode: 0o600 }),
    writeFile(
      join(home, "config.toml"),
      `chatgpt_base_url="${loopback}"\nopenai_base_url="${loopback}/v1"\n`,
    ),
    writeFile(
      catalog,
      JSON.stringify({
        models: [
          model("blue-and-red", ["standard", "daybreak_red", "daybreak_blue"]),
          model("standard-and-red", ["daybreak_red", "standard"]),
          model("red-only", ["daybreak_red"]),
          model("missing-metadata"),
        ],
      }),
    ),
  ]);
});

afterEach(async () => {
  await rm(home, { recursive: true, force: true });
});

type SelectorOptions = Pick<
  Parameters<typeof resolveScanCyberAccessProgram>[0],
  "command" | "program" | "environment"
>;

function select(
  model: string,
  config: JsonObject = {},
  options: Partial<SelectorOptions> = {},
) {
  return resolveScanCyberAccessProgram({
    cwd: home,
    command: options.command ?? { command: resolveBundledCodexExecutable() },
    environment: {
      PATH: process.env["PATH"] ?? "",
      ...(process.env["SystemRoot"] && {
        SystemRoot: process.env["SystemRoot"],
      }),
      HOME: home,
      USERPROFILE: home,
      CODEX_HOME: home,
      CODEX_API_KEY: "synthetic-scan-key",
      ...options.environment,
    },
    model,
    config: {
      model_catalog_json: catalog,
      cli_auth_credentials_store: "file",
      openai_base_url: loopback + "/v1",
      chatgpt_base_url: loopback,
      analytics: { enabled: false },
      ...config,
    },
    signal: new AbortController().signal,
    program: options.program,
  });
}

test("bundled scans select from the requested model's advertised programs", async () => {
  expect(
    await select("blue-and-red", { model_catalog_json: "catalog.json" }),
  ).toBe("daybreak_blue");
  expect(await select("standard-and-red")).toBe("standard");
  await expect(select("red-only")).rejects.toThrow(
    "--cyber-access-program daybreak_red",
  );
  expect(await select("missing-metadata")).toBe("standard");
  expect(await select("absent-model")).toBe("standard");
  await expect(
    select("blue-and-red", { model_catalog_json: "missing.json" }),
  ).rejects.toThrow(/os error 2|ENOENT/i);
});

test("model discovery and access-program forwarding follow their own native gates", async () => {
  const offline = { features: { api_key_model_discovery: false } };
  expect(await select("blue-and-red", offline)).toBe("daybreak_blue");
  await expect(select("red-only", offline)).rejects.toThrow(
    "requires Daybreak Red",
  );
  expect(
    await select("blue-and-red", { ...offline, model_catalog_json: null }),
  ).toBe("standard");

  expect(
    await select("blue-and-red", { features: { cli_daybreak: false } }),
  ).toBeUndefined();
  const disabled = { features: { api_key_cyber_access_programs: false } };
  expect(await select("blue-and-red", disabled)).toBeUndefined();
  expect(
    await select("blue-and-red", {
      "features.api_key_cyber_access_programs": false,
    }),
  ).toBeUndefined();
  expect(
    await select("blue-and-red", {
      features: { api_key_cyber_access_programs: true },
      "features.api_key_cyber_access_programs": false,
    }),
  ).toBe("daybreak_blue");
  expect(
    await select("blue-and-red", disabled, {
      environment: { CODEX_API_KEY: "" },
    }),
  ).toBe("daybreak_blue");
});

test("project keys and stored logins follow their own catalog routes", async () => {
  for (const route of [
    privateRoute,
    { "model_providers.openai.model_catalog_url": privateUrl },
  ]) {
    await expect(
      select("blue-and-red", { ...route, model_catalog_json: null }),
    ).rejects.toThrow("must use an allowed ChatGPT host");
  }
  const stored = { environment: { CODEX_API_KEY: "" } };
  expect(
    await select(
      "blue-and-red",
      { ...privateRoute, model_catalog_json: null },
      stored,
    ),
  ).toBe("standard");

  const configuredUrl = "https://chatgpt.com/backend-api/codex/models";
  await writeFile(
    join(home, "config.toml"),
    `chatgpt_base_url="${loopback}"\nmodel_catalog_json=${JSON.stringify(catalog)}\n[model_providers.openai]\nmodel_catalog_url=${JSON.stringify(configuredUrl)}\n`,
  );
  expect(
    await select(
      "blue-and-red",
      {
        model_catalog_json: null,
        model_providers: { openai: { model_catalog_url: configuredUrl } },
      },
      stored,
    ),
  ).toBe("daybreak_blue");
  expect(await select("blue-and-red", { model_catalog_json: null })).toBe(
    "daybreak_blue",
  );
  expect(await readFile(join(home, "auth.json"), "utf8")).toBe(savedLogin);

  const storedKey = JSON.stringify({
    auth_mode: "apikey",
    OPENAI_API_KEY: "synthetic-stored-key",
  });
  await writeFile(join(home, "auth.json"), storedKey, { mode: 0o600 });
  const offline = {
    ...privateRoute,
    model_catalog_json: null,
    features: { api_key_model_discovery: false },
  };
  expect(await select("blue-and-red", offline, stored)).toBe("daybreak_blue");
  await expect(select("red-only", offline, stored)).rejects.toThrow(
    "requires Daybreak Red",
  );
  expect(await readFile(join(home, "auth.json"), "utf8")).toBe(storedKey);
});

test("the remote catalog subprocess uses only the project key and its private route", async () => {
  const route = "https://chatgpt.com/custom/models";
  const run = runtime.runCodexCommand;
  using probe = spyOn(runtime, "runCodexCommand").mockImplementation(
    async (...inputs) => {
      const [command, args, env] = inputs;
      if (args.at(-1) !== "models") return run(...inputs);
      expect(env["CODEX_API_KEY"]).toBe("synthetic-scan-key");
      expect(env["OPENAI_API_KEY"]).toBeUndefined();
      const keyHome = env["CODEX_HOME"]!;
      expect(keyHome).not.toBe(home);
      await expect(readFile(join(keyHome, "auth.json"))).rejects.toMatchObject({
        code: "ENOENT",
      });
      const config = Bun.TOML.parse(
        await readFile(join(keyHome, "config.toml"), "utf8"),
      );
      expect(config).toMatchObject({
        model_providers: { openai: { model_catalog_url: route } },
      });
      expect([...(command.args ?? []), ...args].join(" ")).not.toContain(route);
      return {
        success: true,
        exitCode: 0,
        stderr: "",
        stdout: await readFile(catalog, "utf8"),
      };
    },
  );
  expect(
    await select(
      "blue-and-red",
      {
        model_catalog_json: null,
        model_providers: { openai: { model_catalog_url: route } },
      },
      { environment: { OPENAI_API_KEY: "unused-ambient-key" } },
    ),
  ).toBe("daybreak_blue");
  expect(probe).toHaveBeenCalled();
});

test("managed policy uses the saved login on its own endpoint and disables Blue for a project key", async () => {
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
  const requests: Request[] = [];
  const policyPath = "/backend-api/wham/config/bundle";
  const endpoint = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      requests.push(request);
      if (new URL(request.url).pathname !== policyPath)
        return new Response(null, { status: 404 });
      return Response.json({
        requirements_toml: {
          enterprise_managed: [
            {
              id: "managed-feature",
              name: "Disabled Daybreak",
              contents: "[features]\ncli_daybreak=false\n",
            },
          ],
        },
      });
    },
  });
  try {
    const origin = endpoint.url.origin;
    await writeFile(join(home, "auth.json"), login, { mode: 0o600 });
    await writeFile(
      join(home, "config.toml"),
      `chatgpt_base_url="${origin}/backend-api"\n`,
    );
    expect(
      await select("blue-and-red", {
        chatgpt_base_url: origin + "/project",
        openai_base_url: origin + "/project/v1",
      }),
    ).toBeUndefined();
    const paths = requests.map((request) => new URL(request.url).pathname);
    expect(paths).toContain(policyPath);
    expect(paths.some((path) => path.startsWith("/project"))).toBe(false);
    for (const request of requests.filter(
      (entry) => new URL(entry.url).pathname === policyPath,
    )) {
      expect(request.headers.get("authorization")).toBe(
        `Bearer ${chatGptTokens.access_token}`,
      );
      expect(request.headers.get("chatgpt-account-id")).toBe(account);
    }
    expect(await readFile(join(home, "auth.json"), "utf8")).toBe(login);
  } finally {
    await endpoint.stop(true);
  }
});

test("native preferences and non-OpenAI authentication bypass automatic selection", async () => {
  const nativePreferences: JsonObject[] = [
    { daybreak: false },
    { daybreak: true },
    { model_provider: "custom" },
  ];
  for (const config of nativePreferences) {
    expect(await select("red-only", config)).toBeUndefined();
  }
  for (const name of [
    "OPENAI_FEDERATION_RULE_ID",
    "OPENAI_IDENTITY_TOKEN_FILE",
  ]) {
    expect(
      await select("red-only", {}, { environment: { [name]: "workload" } }),
    ).toBeUndefined();
  }
  for (const program of [
    "standard",
    "daybreak_blue",
    "daybreak_red",
  ] as const) {
    expect(await select("red-only", { daybreak: false }, { program })).toBe(
      program,
    );
  }
});

test("custom executables and launch arguments skip discovery", async () => {
  for (const command of [
    { command: "nonexistent-catalog-launcher" },
    { command: resolveBundledCodexExecutable(), args: ["--invalid-for-codex"] },
  ]) {
    expect(await select("red-only", {}, { command })).toBeUndefined();
    expect(
      await select("red-only", {}, { command, program: "daybreak_red" }),
    ).toBe("daybreak_red");
  }
});
