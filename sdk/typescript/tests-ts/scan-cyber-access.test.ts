import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { expect, test } from "bun:test";
import { resolveBundledCodexExecutable } from "../src/codex-sdk-environment.js";
import { projectTrustKey } from "../src/config.js";
import { resolveScanCyberAccessProgram } from "../src/scan-cyber-access.js";
import type { JsonObject } from "../src/config.js";
import { withoutOpenAiApiKeys } from "../src/auth.js";
import { chatGptTokens } from "./support/chatgpt-credentials.js";

test.each([
  "stored login",
  "project key",
  "key-selected OpenAI provider",
  "explicit file",
  "mixed workspace",
  "pinned route",
] as const)(
  "an opaque launcher's credential-dependent static catalog respects the scan's %s",
  async (mode) => {
    const root = await mkdtemp(join(tmpdir(), "scan-saved-catalog-"));
    let alternateRequests = 0;
    const alternate =
      mode === "key-selected OpenAI provider"
        ? Bun.serve({
            hostname: "127.0.0.1",
            port: 0,
            fetch() {
              alternateRequests++;
              return new Response(null, { status: 404 });
            },
          })
        : undefined;
    try {
      const home = join(root, "home");
      const target = join(root, "target");
      await Promise.all([mkdir(home), mkdir(target)]);
      if (mode === "stored login" || mode === "mixed workspace")
        await writeFile(
          join(home, "auth.json"),
          JSON.stringify(
            mode === "mixed workspace"
              ? { auth_mode: "chatgpt", tokens: chatGptTokens }
              : {
                  auth_mode: "apikey",
                  OPENAI_API_KEY: "synthetic-saved-key",
                },
          ),
          { mode: 0o600 },
        );
      await writeFile(
        join(home, "config.toml"),
        'cli_auth_credentials_store="file"\nchatgpt_base_url="http://127.0.0.1:1"\nopenai_base_url="http://127.0.0.1:1/v1"\n[features]\napi_key_model_discovery=false\n',
      );
      const fixture = JSON.parse(
        await readFile(
          new URL(
            "./fixtures/native-skill-model-catalog.json",
            import.meta.url,
          ),
          "utf8",
        ),
      ).models[0];
      const models = (signedIn: boolean, prefix = "") => ({
        models: ["blue", "red"].map((color) => ({
          ...fixture,
          slug: prefix + color,
          available_access_programs: {
            cyber: [
              (color === "blue") === signedIn
                ? "daybreak_blue"
                : "daybreak_red",
            ],
          },
        })),
      });
      const authenticated = join(root, "signed-in.json");
      const signedOut = join(root, "signed-out.json");
      const explicit = join(root, "explicit.json");
      await writeFile(authenticated, JSON.stringify(models(true)));
      await writeFile(signedOut, JSON.stringify(models(false)));
      if (mode === "explicit file")
        await writeFile(explicit, JSON.stringify(models(true, "caller-")));
      const launcher = join(root, "launcher.mjs");
      const calls = join(root, "calls.jsonl");
      const signedOutProvider = alternate
        ? [
            "-c",
            `model_providers.custom={name="Synthetic",wire_api="responses",env_key="CODEX_API_KEY",base_url=${JSON.stringify(alternate.url.origin + "/custom/v1")}}`,
            "-c",
            'model_provider="custom"',
          ]
        : [];
      await writeFile(
        launcher,
        `
      import { appendFileSync, existsSync } from "node:fs";
      import { join } from "node:path";
      import { spawnSync } from "node:child_process";
      const saved = existsSync(join(process.env.CODEX_HOME, "auth.json"));
      const key = process.env.CODEX_API_KEY !== undefined;
      appendFileSync(${JSON.stringify(calls)}, JSON.stringify({home:process.env.CODEX_HOME, saved, key, bundled:process.argv.includes("--bundled"), other:!!(process.env.OPENAI_API_KEY || process.env.CODEX_ACCESS_TOKEN)})+"\\n");
      const file = (saved || process.env.CODEX_API_KEY === "synthetic-project-key")
        ? ${JSON.stringify(authenticated)} : ${JSON.stringify(signedOut)};
      const result = spawnSync(${JSON.stringify(resolveBundledCodexExecutable())},
        [...(key ? [] : ${JSON.stringify(signedOutProvider)}), "-c", "model_catalog_json=" + JSON.stringify(file), ...process.argv.slice(2)],
        { stdio: "inherit" });
      process.exit(result.status ?? 1);
    `,
      );
      const select = (model: string, launcherCwd: string, file = explicit) =>
        resolveScanCyberAccessProgram({
          command: { command: process.execPath, args: [launcher] },
          cwd: target,
          launcherCwd,
          environment: {
            PATH: process.env["PATH"] ?? "",
            ...(process.env["SystemRoot"] && {
              SystemRoot: process.env["SystemRoot"],
            }),
            CODEX_HOME: home,
            HOME: home,
            USERPROFILE: home,
            ...(mode !== "stored login" && {
              CODEX_API_KEY: "synthetic-project-key",
              OPENAI_API_KEY: "synthetic-unrelated-key",
            }),
            ...(mode === "mixed workspace" && {
              CODEX_ACCESS_TOKEN: "synthetic-other-token",
            }),
          },
          config: {
            analytics: { enabled: false },
            ...(mode === "explicit file" && { model_catalog_json: file }),
            ...(mode === "pinned route" && {
              "model_providers.openai.model_catalog_url":
                "https://chatgpt.com/fixture/models",
            }),
          },
          model,
          credentialType: "api_key",
          signal: new AbortController().signal,
        });
      const guarded = mode === "mixed workspace" || mode === "pinned route";
      for (const cwd of mode === "stored login" ? [target, root] : [target]) {
        if (guarded) {
          expect(await select("blue", cwd)).toBe("standard");
          expect(await select("red", cwd)).toBe("standard");
          continue;
        }
        expect(
          await select(mode === "explicit file" ? "caller-blue" : "blue", cwd),
        ).toBe("daybreak_blue");
        await expect(
          select(mode === "explicit file" ? "caller-red" : "red", cwd),
        ).rejects.toThrow("--cyber-access-program daybreak_red");
      }
      if (mode === "explicit file") {
        await expect(
          select("caller-blue", target, join(root, "missing.json")),
        ).rejects.toThrow(/os error 2|ENOENT/i);
      }
      if (mode !== "stored login") {
        const launches = (await readFile(calls, "utf8"))
          .trim()
          .split("\n")
          .map(
            (line) =>
              JSON.parse(line) as {
                home: string;
                saved: boolean;
                key: boolean;
                bundled: boolean;
                other: boolean;
              },
          );
        expect(
          launches.every(
            (entry) => entry.home !== home && !entry.saved && !entry.other,
          ),
        ).toBe(true);
        expect(launches.some((entry) => entry.key)).toBe(
          mode === "project key" ||
            mode === "explicit file" ||
            mode === "key-selected OpenAI provider",
        );
        expect(launches.some((entry) => entry.key && entry.bundled)).toBe(
          false,
        );
      }
      if (alternate) expect(alternateRequests).toBe(0);
    } finally {
      await alternate?.stop(true);
      await rm(root, { recursive: true, force: true });
    }
  },
);

test.each([
  ["daybreak=false", undefined],
  ["daybreak=true", undefined],
  ["daybreak=false only while signed out", "daybreak_blue"],
  ["features.cli_daybreak=false only while signed out", "daybreak_blue"],
  ["features.cli_daybreak=false", undefined],
  ["features.api_key_cyber_access_programs=false", undefined],
  ['forced_login_method="chatgpt"', undefined],
  ['forced_login_method="api"', "daybreak_blue"],
  ['model="key-selected"', "daybreak_blue"],
  ['appended model="key-selected"', "standard"],
  ["features.api_key_model_discovery=false", "standard"],
] as const)(
  "a project-key launcher honors its native %s setting",
  async (setting, expected) => {
    const home = await mkdtemp(join(tmpdir(), "scan-key-preference-"));
    const requests: string[] = [];
    const endpoint = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        requests.push(new URL(request.url).pathname);
        return new Response(null, { status: 404 });
      },
    });
    try {
      const target = join(home, "target");
      await mkdir(target);
      await writeFile(
        join(home, "config.toml"),
        `cli_auth_credentials_store="file"\nchatgpt_base_url=${JSON.stringify(endpoint.url.origin)}\nopenai_base_url=${JSON.stringify(endpoint.url.origin + "/v1")}\n[features]\napi_key_model_discovery=true\n`,
      );
      const fixture = fileURLToPath(
        new URL("./fixtures/native-skill-model-catalog.json", import.meta.url),
      );
      let catalog = fixture;
      const signedOutOptOut = setting.endsWith(" only while signed out");
      const appendedModel = setting === 'appended model="key-selected"';
      if (
        setting === "daybreak=true" ||
        setting === 'model="key-selected"' ||
        appendedModel ||
        signedOutOptOut
      ) {
        const custom = JSON.parse(await readFile(fixture, "utf8"));
        if (setting === "daybreak=true")
          custom.models[0].available_access_programs.cyber = ["daybreak_red"];
        else if (signedOutOptOut)
          custom.models.push({
            ...custom.models[0],
            slug: "key-red",
            available_access_programs: { cyber: ["daybreak_red"] },
          });
        else
          custom.models.push({
            ...custom.models[0],
            slug: "key-selected",
            available_access_programs: { cyber: ["standard"] },
          });
        catalog = join(home, "custom-models.json");
        await writeFile(catalog, JSON.stringify(custom));
      }
      const discoveryOff = setting === "features.api_key_model_discovery=false";
      const keyedFlags =
        appendedModel || signedOutOptOut ? [] : ["-c", setting];
      if (!discoveryOff)
        keyedFlags.push("-c", "model_catalog_json=" + JSON.stringify(catalog));
      const receipts = join(home, "invocations.jsonl");
      const launcher = join(home, "launcher.mjs");
      await writeFile(
        launcher,
        `
      import { appendFileSync, existsSync } from "node:fs";
      import { join } from "node:path";
      import { spawnSync } from "node:child_process";
      const key = process.env.CODEX_API_KEY === "synthetic-project-key";
      appendFileSync(${JSON.stringify(receipts)}, JSON.stringify({key,home:process.env.CODEX_HOME,auth:existsSync(join(process.env.CODEX_HOME, "auth.json")),other:!!(process.env.OPENAI_API_KEY || process.env.CODEX_ACCESS_TOKEN)})+"\\n");
      const flags = key ? ${JSON.stringify(keyedFlags)} : ${JSON.stringify(signedOutOptOut ? ["-c", setting.split(" ")[0]] : [])};
      const suffix = key && ${appendedModel} ? ["-c", 'model="key-selected"'] : [];
      const result = spawnSync(${JSON.stringify(resolveBundledCodexExecutable())}, [...flags, ...process.argv.slice(2), ...suffix], {stdio:"inherit"});
      process.exit(result.status ?? 1);
    `,
      );
      const select = (callerFile?: string, overrides: JsonObject = {}) =>
        resolveScanCyberAccessProgram({
          command: { command: process.execPath, args: [launcher] },
          cwd: target,
          launcherCwd: target,
          environment: {
            PATH: process.env["PATH"] ?? "",
            ...(process.env["SystemRoot"] && {
              SystemRoot: process.env["SystemRoot"],
            }),
            HOME: home,
            USERPROFILE: home,
            CODEX_HOME: home,
            CODEX_API_KEY: "synthetic-project-key",
            OPENAI_API_KEY: "synthetic-unrelated-key",
          },
          model:
            typeof overrides["model"] === "string"
              ? overrides["model"]
              : "gpt-test",
          config: {
            analytics: { enabled: false },
            ...(callerFile && { model_catalog_json: callerFile }),
            ...overrides,
          },
          signal: new AbortController().signal,
        });
      expect(await select()).toBe(expected);
      if (signedOutOptOut)
        await expect(select(undefined, { model: "key-red" })).rejects.toThrow(
          "requires Daybreak Red",
        );
      expect(await select(catalog)).toBe(
        discoveryOff ? "daybreak_blue" : expected,
      );
      if (setting === "features.api_key_cyber_access_programs=false")
        expect(
          await select(undefined, {
            features: { api_key_cyber_access_programs: true },
          }),
        ).toBe("daybreak_blue");
      if (setting === 'forced_login_method="chatgpt"')
        expect(await select(undefined, { forced_login_method: "api" })).toBe(
          "daybreak_blue",
        );
      expect(requests.filter((path) => path.includes("/models"))).toEqual([]);
      const calls = (await readFile(receipts, "utf8"))
        .trim()
        .split("\n")
        .map(
          (line) =>
            JSON.parse(line) as {
              key: boolean;
              home: string;
              auth: boolean;
              other: boolean;
            },
        );
      expect(calls.some((call) => call.key)).toBe(true);
      expect(
        calls.every((call) => call.home !== home && !call.auth && !call.other),
      ).toBe(true);
    } finally {
      await endpoint.stop(true);
      await rm(home, { recursive: true, force: true });
    }
  },
);

test("selects only Blue or Standard with the scan's API key and leaves the saved login intact", async () => {
  const root = await mkdtemp(join(tmpdir(), "scan-cyber-access-"));
  try {
    const auth = join(root, "auth.json");
    const previousLogin = JSON.stringify({
      auth_mode: "chatgpt",
      tokens: chatGptTokens,
    });
    // Keep the stored workspace on its own local route while testing scan overrides.
    await writeFile(
      join(root, "config.toml"),
      'chatgpt_base_url="http://127.0.0.1:1"\nopenai_base_url="http://127.0.0.1:1/v1"\n',
    );
    await writeFile(auth, previousLogin, { mode: 0o600 });
    const catalog = join(root, "catalog.json");
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
    await writeFile(
      catalog,
      JSON.stringify({
        models: [
          model("blue-and-red", ["standard", "daybreak_red", "daybreak_blue"]),
          model("standard-and-red", ["standard", "daybreak_red"]),
          model("red-only", ["daybreak_red"]),
          model("missing-metadata"),
        ],
      }),
    );
    const options = {
      cwd: root,
      command: { command: resolveBundledCodexExecutable() },
      signal: new AbortController().signal,
      environment: {
        PATH: process.env["PATH"] ?? "",
        ...(process.env["SystemRoot"] && {
          SystemRoot: process.env["SystemRoot"],
        }),
        HOME: root,
        USERPROFILE: root,
        CODEX_HOME: root,
        CODEX_API_KEY: "synthetic-scan-key",
      },
      config: {
        model_catalog_json: catalog,
        openai_base_url: "http://127.0.0.1:1/v1",
        chatgpt_base_url: "http://127.0.0.1:1",
        analytics: { enabled: false },
      },
    };
    const select = (model: string, config: JsonObject = {}) =>
      resolveScanCyberAccessProgram({
        ...options,
        model,
        config: { ...options.config, ...config },
      });
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
      select("blue-and-red", {
        model_catalog_json: "missing-explicit-catalog.json",
      }),
    ).rejects.toThrow(/os error 2|ENOENT/i);
    const staticCatalogOnly = { features: { api_key_model_discovery: false } };
    expect(await select("blue-and-red", staticCatalogOnly)).toBe(
      "daybreak_blue",
    );
    await expect(select("red-only", staticCatalogOnly)).rejects.toThrow(
      "--cyber-access-program daybreak_red",
    );
    expect(
      await select("blue-and-red", {
        ...staticCatalogOnly,
        model_catalog_json: null,
      }),
    ).toBe("standard");
    expect(
      await select("blue-and-red", {
        features: { api_key_cyber_access_programs: false },
      }),
    ).toBeUndefined();
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
      await select("blue-and-red", { features: { cli_daybreak: false } }),
    ).toBeUndefined();
    // A saved ChatGPT login can use Blue even if API-key forwarding is disabled.
    expect(
      await resolveScanCyberAccessProgram({
        ...options,
        model: "blue-and-red",
        environment: withoutOpenAiApiKeys(options.environment),
        config: {
          ...options.config,
          cli_auth_credentials_store: "file",
          features: { api_key_cyber_access_programs: false },
        },
      }),
    ).toBe("daybreak_blue");
    // Native rejects loopback for the built-in provider. This fails only if
    // the probe actually loads the same private catalog URL as exec.
    const privateRoute = {
      model_providers: {
        openai: { model_catalog_url: "http://127.0.0.1:1/private-catalog" },
      },
    };
    await expect(
      select("blue-and-red", { ...privateRoute, model_catalog_json: null }),
    ).rejects.toThrow("must use an allowed ChatGPT host");
    await expect(
      select("blue-and-red", {
        "model_providers.openai.model_catalog_url":
          privateRoute.model_providers.openai.model_catalog_url,
        model_catalog_json: null,
      }),
    ).rejects.toThrow("must use an allowed ChatGPT host");
    expect(
      await resolveScanCyberAccessProgram({
        ...options,
        model: "blue-and-red",
        environment: withoutOpenAiApiKeys(options.environment),
        config: {
          ...privateRoute,
          cli_auth_credentials_store: "file",
          chatgpt_base_url: "http://127.0.0.1:1",
        },
      }),
    ).toBe("standard");
    // A stored login can use private routing that its native home already loads.
    const configuredUrl = "https://chatgpt.com/backend-api/codex/models";
    await writeFile(
      join(root, "config.toml"),
      `model_catalog_json=${JSON.stringify(catalog)}\n[model_providers.openai]\nmodel_catalog_url=${JSON.stringify(configuredUrl)}\n`,
    );
    expect(
      await resolveScanCyberAccessProgram({
        ...options,
        model: "blue-and-red",
        environment: withoutOpenAiApiKeys(options.environment),
        config: {
          cli_auth_credentials_store: "file",
          chatgpt_base_url: "http://127.0.0.1:1",
          model_providers: { openai: { model_catalog_url: configuredUrl } },
        },
      }),
    ).toBe("daybreak_blue");
    // An API-key scan can inherit a static catalog from its original home.
    await writeFile(
      join(root, "config.toml"),
      `model_catalog_json=${JSON.stringify(catalog)}\nchatgpt_base_url="http://127.0.0.1:1"\n`,
    );
    expect(
      await resolveScanCyberAccessProgram({
        ...options,
        model: "blue-and-red",
        config: {
          chatgpt_base_url: options.config.chatgpt_base_url,
          openai_base_url: options.config.openai_base_url,
        },
      }),
    ).toBe("daybreak_blue");
    expect(await readFile(auth, "utf8")).toBe(previousLogin);

    // Stored API keys also use the home catalog when remote discovery is off,
    // even if the scan requested a different remote catalog.
    const storedKey = JSON.stringify({
      auth_mode: "apikey",
      OPENAI_API_KEY: "synthetic-stored-key",
    });
    await writeFile(auth, storedKey, { mode: 0o600 });
    const selectWithStoredKey = (model: string) =>
      resolveScanCyberAccessProgram({
        ...options,
        model,
        environment: withoutOpenAiApiKeys(options.environment),
        config: {
          ...privateRoute,
          ...staticCatalogOnly,
          cli_auth_credentials_store: "file",
          openai_base_url: options.config.openai_base_url,
        },
      });
    expect(await selectWithStoredKey("blue-and-red")).toBe("daybreak_blue");
    await expect(selectWithStoredKey("red-only")).rejects.toThrow(
      "--cyber-access-program daybreak_red",
    );
    expect(await readFile(auth, "utf8")).toBe(storedKey);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an API-key scan's identity endpoint never receives the saved workspace credentials", async () => {
  const home = await mkdtemp(join(tmpdir(), "scan-catalog-routing-"));
  const account = "synthetic-saved-account";
  const received: Array<string | null> = [];
  const paths: string[] = [];
  const scanEndpoint = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      paths.push(new URL(request.url).pathname);
      received.push(
        request.headers.get("authorization"),
        request.headers.get("chatgpt-account-id"),
      );
      return new Response(null, { status: 404 });
    },
  });
  try {
    await writeFile(
      join(home, "config.toml"),
      'chatgpt_base_url="http://127.0.0.1:1"\n',
    );
    await writeFile(
      join(home, "auth.json"),
      JSON.stringify({
        auth_mode: "chatgpt",
        tokens: { ...chatGptTokens, account_id: account },
      }),
      { mode: 0o600 },
    );
    const binary = resolveBundledCodexExecutable();
    const options = {
      cwd: home,
      launcherCwd: home,
      environment: {
        PATH: process.env["PATH"] ?? "",
        ...(process.env["SystemRoot"] && {
          SystemRoot: process.env["SystemRoot"],
        }),
        HOME: home,
        USERPROFILE: home,
        CODEX_HOME: home,
        CODEX_API_KEY: "synthetic-scan-key",
      },
      model: "gpt-test",
      signal: new AbortController().signal,
    };
    const fixture = fileURLToPath(
      new URL("./fixtures/native-skill-model-catalog.json", import.meta.url),
    );
    const program = await resolveScanCyberAccessProgram({
      ...options,
      command: { command: binary },
      config: {
        chatgpt_base_url: scanEndpoint.url.origin,
        openai_base_url: scanEndpoint.url.origin + "/v1",
        model_catalog_json: fixture,
        analytics: { enabled: false },
      },
    });
    expect(program).toBe("daybreak_blue");
    const injectedEndpoint = `chatgpt_base_url=${JSON.stringify(scanEndpoint.url.origin)}`;
    const wrapper = join(home, "launch.mjs");
    const calls = join(home, "launcher-calls.jsonl");
    const launcherCwd = join(home, "invocation");
    await mkdir(launcherCwd);
    await writeFile(
      wrapper,
      `import {spawnSync} from "node:child_process";
import {appendFileSync, existsSync} from "node:fs";
import {join} from "node:path";
appendFileSync(${JSON.stringify(calls)}, JSON.stringify({phase:process.argv.slice(3), originalHome:process.env.CODEX_HOME === ${JSON.stringify(home)}, auth:existsSync(join(process.env.CODEX_HOME,"auth.json")), credentials:["CODEX_ACCESS_TOKEN","CODEX_API_KEY","OPENAI_API_KEY"].some(key=>process.env[key] !== undefined)})+"\\n");
const inject = process.argv[2] === "always" || process.env.CODEX_HOME === ${JSON.stringify(home)};
const result = spawnSync(${JSON.stringify(binary)}, [...(inject ? ["-c", ${JSON.stringify(injectedEndpoint)}] : []), ...process.argv.slice(3)], {stdio:"inherit"});
process.exit(result.status ?? 1);`,
    );
    const fromLauncher = (config: JsonObject, mode = "always") =>
      resolveScanCyberAccessProgram({
        ...options,
        launcherCwd,
        environment: {
          ...options.environment,
          CODEX_ACCESS_TOKEN: "synthetic-personal-token",
          OPENAI_API_KEY: "synthetic-ambient-key",
        },
        command: { command: process.execPath, args: [wrapper, mode] },
        config: { ...config, analytics: { enabled: false } },
      });
    expect(await fromLauncher({})).toBe("standard");
    expect(
      await fromLauncher({
        features: { api_key_cyber_access_programs: false },
      }),
    ).toBeUndefined();
    const redFile = join(home, "red-only.json");
    const catalog = JSON.parse(await readFile(fixture, "utf8"));
    catalog.models[0].available_access_programs.cyber = ["daybreak_red"];
    await writeFile(redFile, JSON.stringify(catalog));
    await expect(fromLauncher({ model_catalog_json: redFile })).rejects.toThrow(
      "--cyber-access-program daybreak_red",
    );
    expect(
      await fromLauncher({ model_catalog_json: fixture }, "original-home"),
    ).toBe("standard");
    await expect(
      fromLauncher({ model_catalog_json: redFile }, "original-home"),
    ).rejects.toThrow("--cyber-access-program daybreak_red");
    const setHomeCatalog = (path: string) =>
      writeFile(
        join(home, "config.toml"),
        `model_catalog_json=${JSON.stringify(path)}\nchatgpt_base_url="http://127.0.0.1:1"\n`,
      );
    await setHomeCatalog(fixture);
    expect(await fromLauncher({}, "original-home")).toBe("standard");
    await setHomeCatalog(redFile);
    expect(await fromLauncher({}, "original-home")).toBe("standard");
    const launches = (await readFile(calls, "utf8"))
      .trim()
      .split("\n")
      .map(
        (line) =>
          JSON.parse(line) as {
            phase: string[];
            originalHome: boolean;
            auth: boolean;
            credentials: boolean;
          },
      );
    expect(launches.some((entry) => entry.phase.includes("--help"))).toBe(true);
    expect(launches.some((entry) => entry.phase.includes("debug"))).toBe(true);
    expect(
      launches.every(
        (entry) => !entry.originalHome && !entry.auth && !entry.credentials,
      ),
    ).toBe(true);
  } finally {
    await scanEndpoint.stop(true);
    await rm(home, { recursive: true, force: true });
    expect(received).not.toContain(account);
    expect(received).not.toContain(`Bearer ${chatGptTokens.access_token}`);
    expect(paths.filter((path) => path.endsWith("/models"))).toEqual([]);
    expect(
      paths.filter(
        (path) => path.includes("/accounts/") || path.includes("workspace"),
      ),
    ).toEqual([]);
  }
});

test("explicit programs, native Daybreak settings, and other providers bypass discovery", async () => {
  const options = {
    cwd: "",
    environment: {},
    config: {},
    model: "model",
    command: { command: "unused-catalog-probe" },
    signal: new AbortController().signal,
  };
  for (const program of [
    "standard",
    "daybreak_blue",
    "daybreak_red",
  ] as const) {
    expect(await resolveScanCyberAccessProgram({ ...options, program })).toBe(
      program,
    );
  }
  for (const marker of [
    "OPENAI_FEDERATION_RULE_ID",
    "OPENAI_IDENTITY_TOKEN_FILE",
  ]) {
    expect(
      await resolveScanCyberAccessProgram({
        ...options,
        environment: {
          [marker]: "synthetic-workload",
          CODEX_API_KEY: "unused-key",
        },
      }),
    ).toBeUndefined();
  }
  const bypass: JsonObject[] = [
    { daybreak: true },
    { daybreak: false },
    { model_provider: "amazon-bedrock" },
    { model_provider: "custom" },
  ];
  for (const config of bypass) {
    expect(
      await resolveScanCyberAccessProgram({
        ...options,
        config,
      }),
    ).toBeUndefined();
  }
});

interface CatalogPolicy {
  config?: JsonObject;
  savedAccount?: "chatgpt" | "apiKey" | null;
  startupConfig?: JsonObject;
  neutralStartupConfig?: JsonObject;
  features?: JsonObject;
  requirements?: JsonObject;
  rpcErrors?: Record<string, { code: number; message: string }>;
  layers?: JsonObject[];
  startupLayers?: JsonObject[];
  targetLoginPolicy?: {
    selector: string;
    features: JsonObject;
    requirements: JsonObject;
  };
}

async function probeWithWorkspacePolicy(
  policy: CatalogPolicy,
  config: JsonObject = {},
  options: {
    launcher?: "legacy" | "modern" | "external";
    originator?: string;
    storedLogin?: boolean;
    credentialType?: "chatgpt" | "api_key";
    requiresHome?: "file error" | "silent" | "invalid config";
    signal?: AbortSignal;
    analyticsDefault?: boolean;
    injectedCatalog?: boolean | "relative" | "target-only";
    launcherOverrides?: string[] | ((launcherCwd: string) => string[]);
    keyedLauncherCatalog?: string;
    originalHomeEndpoint?: boolean;
    launcherDiscovery?: boolean;
    nativeProfile?: boolean;
    homeConfig?: string;
    homeCatalog?: boolean;
  } = {},
) {
  const home = await realpath(
    await mkdtemp(join(tmpdir(), "scan-catalog-policy-")),
  );
  try {
    const launcherCwd = options.launcher ? join(home, "invocation") : home;
    const launcherOverrides =
      typeof options.launcherOverrides === "function"
        ? options.launcherOverrides(launcherCwd)
        : (options.launcherOverrides ?? []);
    if (launcherCwd !== home) await mkdir(launcherCwd);
    const launcher = join(launcherCwd, "policy.mjs");
    let executable = process.execPath;
    if (options.launcher === "external") {
      executable = join(launcherCwd, basename(process.execPath));
      await copyFile(process.execPath, executable);
      await mkdir(join(home, "codex-path"));
    }
    const calls = join(home, "calls.jsonl");
    await writeFile(calls, "");
    if (options.requiresHome)
      await writeFile(join(home, "required-launcher-settings"), "synthetic");
    if (options.homeConfig || options.homeCatalog)
      await writeFile(
        join(home, "config.toml"),
        [
          ...(options.homeCatalog
            ? [
                `model_catalog_json=${JSON.stringify(join(home, "scan-catalog.json"))}`,
              ]
            : []),
          options.homeConfig ?? "",
        ].join("\n"),
        {
          mode: 0o600,
        },
      );
    if (policy.savedAccount) {
      const auth =
        policy.savedAccount === "chatgpt"
          ? { auth_mode: "chatgpt", tokens: chatGptTokens }
          : { auth_mode: "apikey", OPENAI_API_KEY: "synthetic-saved-key" };
      await writeFile(join(home, "auth.json"), JSON.stringify(auth), {
        mode: 0o600,
      });
    }
    const injectedFile = join(home, "launcher-models.json");
    if (options.injectedCatalog === "relative") {
      await writeFile(
        join(launcherCwd, "launcher-models.json"),
        JSON.stringify({
          models: [
            {
              slug: "launcher-blue",
              available_access_programs: { cyber: ["daybreak_red"] },
            },
          ],
        }),
      );
    }
    if (options.injectedCatalog)
      await writeFile(
        injectedFile,
        JSON.stringify({
          models: [
            {
              slug: "launcher-blue",
              available_access_programs: { cyber: ["daybreak_blue"] },
            },
            {
              slug: "launcher-red",
              available_access_programs: { cyber: ["daybreak_red"] },
            },
          ],
        }),
      );
    if (
      options.homeCatalog ||
      config["model_catalog_json"] === "scan-catalog.json"
    ) {
      const fixture = JSON.parse(
        await readFile(
          new URL(
            "./fixtures/native-skill-model-catalog.json",
            import.meta.url,
          ),
          "utf8",
        ),
      );
      fixture.models.push({
        ...fixture.models[0],
        slug: "gpt-red-only",
        available_access_programs: { cyber: ["daybreak_red"] },
      });
      fixture.models.push({
        ...fixture.models[0],
        slug: "gpt-standard-only",
        available_access_programs: { cyber: ["standard"] },
      });
      await writeFile(join(home, "scan-catalog.json"), JSON.stringify(fixture));
    }
    await writeFile(
      launcher,
      String.raw`#!${process.execPath}
      import { appendFileSync, existsSync, readFileSync } from "node:fs";
      import { join, resolve } from "node:path";
      import { createInterface } from "node:readline";
      import { fileURLToPath } from "node:url";
      const policy = ${JSON.stringify(policy)};
      const args = process.argv.slice(2);
      if (${Boolean(options.originalHomeEndpoint)} && process.env.CODEX_HOME === ${JSON.stringify(home)}) args.unshift("-c",'chatgpt_base_url="https://identity.example.test"');
      if (${Boolean(options.analyticsDefault)} && args.includes("app-server")) args.push("--analytics-default-enabled");
      const keyedCatalog = ${JSON.stringify(options.keyedLauncherCatalog ?? null)};
      if (process.env.CODEX_API_KEY && keyedCatalog) args.unshift("-c","model_providers.openai.model_catalog_url="+JSON.stringify(keyedCatalog));
      args.unshift(...${JSON.stringify(launcherOverrides.flatMap((value) => ["-c", value]))});
      if (${options.launcherDiscovery !== undefined}) args.unshift("-c","features.api_key_model_discovery="+${Boolean(options.launcherDiscovery)});
      if (${Boolean(options.injectedCatalog)}) args.unshift("-c","model_catalog_json="+JSON.stringify(${JSON.stringify(typeof options.injectedCatalog === "string" ? "launcher-models.json" : injectedFile)}));
      if (policy.targetLoginPolicy && (args.includes(policy.targetLoginPolicy.selector) || process.env.CODEX_HOME !== ${JSON.stringify(home)})) {
        policy.config.features = policy.targetLoginPolicy.features;
        policy.requirements = policy.targetLoginPolicy.requirements;
        policy.startupConfig = {};
      }
      const home = process.env.CODEX_HOME;
      const lockPath = join(${JSON.stringify(home)}, ".codex-security-preflight", ".codex-security-scan.lock", "owner.json");
      const record = entry => appendFileSync(${JSON.stringify(calls)}, JSON.stringify({
        home, ...entry, cwd:process.cwd(), path:process.env.PATH, sqliteHome:process.env.CODEX_SQLITE_HOME, lockHeld:existsSync(lockPath), originator:process.env.CODEX_INTERNAL_ORIGINATOR_OVERRIDE,
        authFile:existsSync(join(home,"auth.json")), credentialEnv:Object.keys(process.env).filter(key => ["CODEX_API_KEY","OPENAI_API_KEY","CODEX_ACCESS_TOKEN"].includes(key.toUpperCase())),
      }) + "\n");
      const configFile = join(home, "config.toml");
      if (${Boolean(options.requiresHome)} && !existsSync(join(home,"required-launcher-settings"))) {
        record({action:"missing-launcher-settings",home,args});
        if (${options.requiresHome === "file error"}) console.error("required launcher settings: No such file or directory");
        if (${options.requiresHome === "invalid config"}) console.error("Invalid Codex config: expected a TOML boolean for daybreak");
        process.exit(1);
      }
      const snapshot = existsSync(configFile) ? readFileSync(configFile, "utf8") : "";
      const models = [
        {slug:"requested-model", available_access_programs:{cyber:["daybreak_red"]}},
        {slug:"workspace-model", available_access_programs:{cyber:["standard","daybreak_blue"]}},
      ];
      if (args.includes("--help")) {
        record({action:"help", args});
        console.log(${JSON.stringify(options.launcher === "legacy" ? "Usage: codex app-server --stdio" : "  --cd <DIR>")});
      } else if (${options.launcher === "legacy"} && args.includes("--cd")) {
        console.error("Unknown option --cd");
        process.exit(2);
      } else if (args.includes("debug") && args.includes("models")) {
        const bundled = args.includes("--bundled");
        record({action:bundled ? "bundled-catalog" : "key-catalog", home, args, snapshot, key:process.env.CODEX_API_KEY});
        const settings = Bun.TOML.parse(snapshot);
        const override = args.findLast(arg => arg.startsWith("model_catalog_json="));
        const staticFile = !bundled && (override ? JSON.parse(override.slice("model_catalog_json=".length)) : settings.model_catalog_json);
        const discoveryArg = args.findLast(arg => arg.startsWith("features.api_key_model_discovery=") || arg.startsWith("features="));
        const discovery = discoveryArg ? Bun.TOML.parse(discoveryArg).features.api_key_model_discovery !== false : settings.features?.api_key_model_discovery !== false;
        const providerArg = args.findLast(arg => arg.startsWith("model_provider="));
        const provider = providerArg ? Bun.TOML.parse(providerArg).model_provider : (settings.model_provider ?? "openai");
        if (!bundled && provider !== "openai" && !settings.model_providers?.[provider] && !args.some(arg => arg.startsWith("model_providers."+provider+"="))) throw new Error("Unknown provider: " + provider);
        const route = args.findLast(arg => arg.startsWith("model_providers.openai.model_catalog_url="));
        if (!bundled && !staticFile && discovery) record({action:"catalog-http", home, provider, route:route ? JSON.parse(route.slice(route.indexOf("=")+1)) : settings.model_providers?.openai?.model_catalog_url, key:provider === "openai" ? process.env.CODEX_API_KEY : undefined});
        console.log(staticFile ? readFileSync(staticFile, "utf8") : JSON.stringify({models:bundled || (discovery && provider === "openai") ? models : []}));
      } else {
        const consent = args.findLast(arg => arg.startsWith("analytics=") || arg.startsWith("analytics.enabled="));
        const analyticsEnabled = (consent && Bun.TOML.parse(consent).analytics?.enabled) ?? Bun.TOML.parse(snapshot).analytics?.enabled ?? args.includes("--analytics-default-enabled");
        record({action:"app-server", home, args, snapshot, analyticsEnabled, key:process.env.CODEX_API_KEY});
        const features = {cli_daybreak:true,api_key_cyber_access_programs:true,api_key_model_discovery:true,...policy.features};
        const homeConfig = Bun.TOML.parse(snapshot);
        const httpFeatures = {...homeConfig.features};
        const homeFile = policy.layers?.find(layer => !layer.disabledReason && layer.config?.model_catalog_json)?.config.model_catalog_json;
        const config = { ...homeConfig, features:httpFeatures, model_catalog_json:homeFile ?? homeConfig.model_catalog_json, ...policy.config };
        const session = {};
        for (const arg of args) {
          if (arg.startsWith("features=")) {
            for (const key of Object.keys(httpFeatures)) delete httpFeatures[key];
            Object.assign(httpFeatures,Bun.TOML.parse(arg).features);
          }
          const match = /^features\.(cli_daybreak|api_key_cyber_access_programs|api_key_model_discovery|respect_system_proxy|system_proxy_fallback)=(true|false)$/.exec(arg);
          if (match) httpFeatures[match[1]] = match[2] === "true";
          if (arg.startsWith("model_catalog_json=")) session.model_catalog_json = JSON.parse(arg.slice("model_catalog_json=".length));
          if (arg.startsWith("model_provider=")) session.model_provider = JSON.parse(arg.slice("model_provider=".length));
          if (arg.startsWith("forced_login_method=")) session.forced_login_method = JSON.parse(arg.slice("forced_login_method=".length));
          if (arg.startsWith("daybreak=")) session.daybreak = JSON.parse(arg.slice("daybreak=".length));
          if (arg.startsWith("chatgpt_base_url=")) session.chatgpt_base_url = JSON.parse(arg.slice("chatgpt_base_url=".length));
          if (arg.startsWith("model_providers.") || arg.startsWith("model_providers=")) Object.assign(session.model_providers ??= {},Bun.TOML.parse(arg).model_providers);
        }
        Object.assign(config,session);
        if (policy.requirements?.modelProviders?.openai) config.model_providers = {...config.model_providers,openai:policy.requirements.modelProviders.openai};
        if (${options.injectedCatalog === "target-only"} && config.model_catalog_json && !existsSync(resolve(config.model_catalog_json))) {
          console.error("Error: No such file or directory (os error 2)");
          process.exit(1);
        }
        if (policy.requirements?.modelCatalogJson) config.model_catalog_json = fileURLToPath(policy.requirements.modelCatalogJson);
        if (policy.requirements?.modelProvider) config.model_provider = policy.requirements.modelProvider;
        if (session.model_provider && session.model_provider !== "openai" && config.model_provider === session.model_provider &&
            !homeConfig.model_providers?.[session.model_provider] && !session.model_providers?.[session.model_provider]) {
          console.error("Error: Model provider \x60" + session.model_provider + "\x60 not found");
          process.exit(1);
        }
        const savedAccount = policy.savedAccount === undefined ? "chatgpt" : existsSync(join(home,"auth.json")) ? policy.savedAccount : null;
        const neutral = args.includes("project_root_markers=[]") && args.some(arg => arg.startsWith("projects") && arg.includes("untrusted"));
        const startup = args.includes("--cd") || neutral ? config : {...config,...policy.startupConfig};
        const loginArg = args.findLast(arg => arg.startsWith("forced_login_method="));
        const forcedLogin = loginArg ? JSON.parse(loginArg.slice("forced_login_method=".length)) : startup.forced_login_method;
        const account = savedAccount && (!forcedLogin || forcedLogin === (savedAccount === "apiKey" ? "api" : savedAccount)) ? {type:savedAccount} : null;
        const results = {
          initialize:{},
          "config/read":{config,layers:policy.layers ?? []},
          "experimentalFeature/list":{data:Object.entries(features).map(([name,enabled])=>({name,enabled}))},
          "configRequirements/read":{requirements:policy.requirements ?? {}},
          ...(${Boolean(options.storedLogin)} && {
            "account/read":{account},
            "model/list":{data:[{model:"workspace-model",availableAccessPrograms:{cyber:["daybreakBlue"]}}]},
          }),
        };
        for await (const line of createInterface({input:process.stdin})) {
          const request = JSON.parse(line);
          if (!("id" in request)) continue;
          if (request.method === "config/read") {
            record({action:request.method, home, configCwd:request.params.cwd});
            const startup = request.params.cwd === process.cwd();
            const scoped = {...session};
            if (scoped.model_catalog_json) scoped.model_catalog_json = resolve(request.params.cwd,scoped.model_catalog_json);
            const layers = [...((startup && !neutral ? policy.startupLayers : undefined) ?? policy.layers ?? [])];
            if (Object.keys(homeConfig).length && !layers.some(layer => layer.name.type === "user")) layers.push({name:{type:"user"}, config:homeConfig});
            const sessionLayer = layers.find(layer => layer.name.type === "sessionFlags");
            results["config/read"] = {
              config:startup ? {...config,...(neutral ? policy.neutralStartupConfig : policy.startupConfig)} : config,
              layers:[{name:{type:"sessionFlags"},config:{...sessionLayer?.config,...scoped}},...layers.filter(layer => layer !== sessionLayer)],
            };
          }
          if (request.method === "account/read") record({action:request.method, home, account});
          if (request.method === "model/list") {
            const configCwd = args.includes("--cd") ? args[args.indexOf("--cd") + 1] : process.cwd();
            const catalog = config.model_catalog_json && resolve(configCwd, config.model_catalog_json);
            record({action:request.method, catalog});
            if (catalog) {
              const rows = JSON.parse(readFileSync(catalog, "utf8")).models;
              results["model/list"] = {data:rows.map(row => ({
                model:row.slug,
                availableAccessPrograms:{cyber:row.available_access_programs?.cyber.map(value => value.replace(/_(.)/g, (_, letter) => letter.toUpperCase()))},
              }))};
            }
          }
          if (!(request.method in results)) {
            console.error("Unexpected policy RPC: " + request.method);
            process.exit(3);
          }
          const rpcError = policy.rpcErrors?.[request.method];
          if (rpcError) {
            record({action:request.method + "-error"});
            console.log(JSON.stringify({id:request.id,error:rpcError}));
          } else {
            console.log(JSON.stringify({id:request.id,result:results[request.method]}));
          }
        }
      }
    `,
      { mode: 0o700 },
    );
    const program = await resolveScanCyberAccessProgram({
      command:
        options.launcher === "modern" && process.platform !== "win32"
          ? { command: "./policy.mjs" }
          : {
              command: executable,
              args: [options.launcher ? "./policy.mjs" : launcher],
            },
      cwd: home,
      launcherCwd,
      environment: {
        CODEX_HOME: home,
        ...(options.originalHomeEndpoint &&
          policy.savedAccount &&
          !options.storedLogin && {
            OPENAI_API_KEY: "synthetic-ambient-key",
            CODEX_ACCESS_TOKEN: "synthetic-ambient-token",
          }),
        ...(options.launcher === "external" && { PATH: launcherCwd }),
        ...(!options.storedLogin && { CODEX_API_KEY: "synthetic-key" }),
        ...(options.originator && {
          CODEX_INTERNAL_ORIGINATOR_OVERRIDE: options.originator,
        }),
      },
      config,
      model:
        typeof config["model"] === "string"
          ? config["model"]
          : "requested-model",
      nativeProfile: options.nativeProfile,
      credentialType: options.credentialType,
      signal: options.signal ?? new AbortController().signal,
    });
    const observations = (await readFile(calls, "utf8"))
      .trim()
      .split("\n")
      .filter(Boolean)
      .map(
        (line) =>
          JSON.parse(line) as {
            action: string;
            account?: { type: string } | null;
            analyticsEnabled?: boolean;
            cwd: string;
            path?: string;
            sqliteHome?: string;
            configCwd?: string;
            catalog?: string;
            route?: string;
            provider?: string;
            home: string;
            args: string[];
            snapshot: string;
            key?: string;
            originator?: string;
            lockHeld: boolean;
            credentialEnv: string[];
            authFile: boolean;
          },
      );
    return { program, home, launcherCwd, observations };
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}

test.each([
  [true, "standard"],
  [false, undefined],
] as const)(
  "a launcher without the requirements RPC uses native forwarding (%p) without catalog access",
  async (forwarding, expected) => {
    const result = await probeWithWorkspacePolicy({
      config: { features: { api_key_cyber_access_programs: forwarding } },
      features: {
        cli_daybreak: true,
        api_key_cyber_access_programs: forwarding,
      },
      rpcErrors: {
        "configRequirements/read": {
          code: -32601,
          message: "Method not found",
        },
      },
    });
    expect(result.program).toBe(expected);
    expect(
      result.observations.some(({ action }) =>
        ["model/list", "catalog-http", "key-catalog"].includes(action),
      ),
    ).toBe(false);
  },
);

test("a catalog requirements access error retains its original diagnostic", async () => {
  await expect(
    probeWithWorkspacePolicy({
      rpcErrors: {
        "configRequirements/read": {
          code: -32003,
          message: "synthetic requirements access denied",
        },
      },
    }),
  ).rejects.toThrow("synthetic requirements access denied");
});

test("explicit target feature gates work with a missing optional RPC", async () => {
  const missing = { code: -32601, message: "Method not found" };
  const disabled = await probeWithWorkspacePolicy(
    { rpcErrors: { "experimentalFeature/list": missing } },
    { features: { cli_daybreak: false } },
  );
  expect(disabled.program).toBeUndefined();
  expect(
    disabled.observations.some(
      ({ action }) => action.endsWith("-error") || action === "catalog-http",
    ),
  ).toBe(false);
  for (const enabled of [true, false]) {
    const scoped = await probeWithWorkspacePolicy({
      config: {
        features: {
          cli_daybreak: enabled,
          api_key_cyber_access_programs: enabled,
        },
      },
      features: {
        cli_daybreak: !enabled,
        api_key_cyber_access_programs: !enabled,
      },
      rpcErrors: { "configRequirements/read": missing },
    });
    expect(scoped.program).toBe(enabled ? "standard" : undefined);
    expect(
      scoped.observations.some(({ action }) => action === "catalog-http"),
    ).toBe(false);
  }
});

test("a denied model/list RPC retains its native diagnostic while an unavailable method uses Standard", async () => {
  const lookup = (code: number) =>
    probeWithWorkspacePolicy(
      {
        savedAccount: "chatgpt",
        rpcErrors: {
          "model/list": { code, message: "synthetic catalog lookup denied" },
        },
      },
      {},
      { storedLogin: true },
    );
  await expect(lookup(-32003)).rejects.toThrow(
    "synthetic catalog lookup denied",
  );
  expect((await lookup(-32601)).program).toBe("standard");
});

test.each([true, false])(
  "explicit native daybreak=%p skips optional catalog RPCs",
  async (daybreak) => {
    const missing = { code: -32601, message: "Method not found" };
    const result = await probeWithWorkspacePolicy(
      {
        config: { daybreak },
        savedAccount: "chatgpt",
        rpcErrors: {
          "experimentalFeature/list": missing,
          "configRequirements/read": missing,
        },
      },
      {},
      { storedLogin: true },
    );
    expect(result.program).toBeUndefined();
    expect(
      result.observations.some(
        ({ action }) => action.endsWith("-error") || action === "model/list",
      ),
    ).toBe(false);
  },
);

test.each(["experimentalFeature/list", "configRequirements/read"])(
  "a project-key launcher retains its own Daybreak setting when %s is unavailable",
  async (method) => {
    const result = await probeWithWorkspacePolicy({
      config: { daybreak: false },
      rpcErrors: { [method]: { code: -32601, message: "Method not found" } },
    });
    expect(result.program).toBeUndefined();
    expect(
      result.observations.some(({ action }) =>
        ["key-catalog", "model/list", "catalog-http"].includes(action),
      ),
    ).toBe(false);
  },
);

test("a matching native launcher opt-out skips feature listing while an unconfigured scan preserves its denial", async () => {
  const policy = {
    rpcErrors: {
      "experimentalFeature/list": {
        code: -32003,
        message: "synthetic policy read denied",
      },
    },
  };
  const optedOut = await probeWithWorkspacePolicy(
    policy,
    {},
    { launcherOverrides: ["daybreak=false"] },
  );
  expect(optedOut.program).toBeUndefined();
  expect(
    optedOut.observations.some(
      ({ action }) => action.endsWith("-error") || action === "model/list",
    ),
  ).toBe(false);
  await expect(probeWithWorkspacePolicy(policy)).rejects.toThrow(
    "synthetic policy read denied",
  );
});

test("an external catalog launcher keeps the scan's vetted PATH", async () => {
  const result = await probeWithWorkspacePolicy(
    { config: { model: "workspace-model" } },
    {},
    { launcher: "external" },
  );
  expect(result.program).toBe("daybreak_blue");
  expect(
    result.observations.some((entry) => entry.action === "key-catalog"),
  ).toBe(true);
  expect(new Set(result.observations.map((entry) => entry.path))).toEqual(
    new Set([result.launcherCwd]),
  );
});

test.each([
  ["disabled feature", { features: { cli_daybreak: false } }, undefined],
  [
    "workspace Daybreak disable",
    { config: { features: { cli_daybreak: false } } },
    undefined,
  ],
  [
    "workspace API-key forwarding disable",
    { config: { features: { api_key_cyber_access_programs: false } } },
    undefined,
  ],
  [
    "workspace system proxy",
    { requirements: { featureRequirements: { respect_system_proxy: true } } },
    "standard",
  ],
  [
    "workspace proxy fallback disable",
    { requirements: { featureRequirements: { system_proxy_fallback: false } } },
    "standard",
  ],
  ["explicit workspace choice", { config: { daybreak: false } }, undefined],
  [
    "managed provider",
    { requirements: { modelProvider: "custom" } },
    undefined,
  ],
  [
    "forced workspace login",
    { requirements: { allowedLoginMethods: ["chatgpt"] } },
    undefined,
  ],
  [
    "managed identity endpoint",
    { requirements: { chatgptBaseUrl: "https://example.test/" } },
    "standard",
  ],
  [
    "network restriction",
    {
      requirements: {
        application: { network: { enabled: true, domains: {} } },
      },
    },
    "standard",
  ],
  ["residency", { requirements: { enforceResidency: "us" } }, "standard"],
  [
    "workspace network layer",
    {
      layers: [
        {
          name: {
            type: "enterpriseManaged",
            name: "Synthetic policy",
            id: "fixture",
          },
          config: { network: { enabled: true } },
        },
      ],
    },
    "standard",
  ],
] as const)(
  "%s is respected before an environment key is used",
  async (_name, policy, expected) => {
    const result = await probeWithWorkspacePolicy(policy as CatalogPolicy);
    expect(result.program).toBe(expected);
    expect(
      result.observations.some((entry) => entry.action === "key-catalog"),
    ).toBe(false);
  },
);

test.each(["nested", "dotted"])(
  "workspace requirements take precedence over a %s cli_daybreak setting",
  async (spelling) => {
    const features = { cli_daybreak: false };
    const scanConfig: JsonObject =
      spelling === "nested" ? { features } : { "features.cli_daybreak": false };
    const config = { model: "workspace-model", features };
    const requirements = { featureRequirements: { cli_daybreak: true } };
    expect(
      (await probeWithWorkspacePolicy({ config, requirements }, scanConfig))
        .program,
    ).toBe("daybreak_blue");
    expect(
      (await probeWithWorkspacePolicy({ config }, scanConfig)).program,
    ).toBeUndefined();
  },
);

test("an opaque launcher can provide a local catalog with remote discovery disabled", async () => {
  const select = (model: string, injectedCatalog: boolean) =>
    probeWithWorkspacePolicy(
      {
        config: { model, features: { api_key_model_discovery: false } },
      },
      {},
      { injectedCatalog },
    );
  for (const injected of [true, false]) {
    const result = await select("launcher-blue", injected);
    expect(result.program).toBe(injected ? "daybreak_blue" : "standard");
    const key = result.observations.find(
      (entry) => entry.action === "key-catalog",
    );
    expect(Boolean(key)).toBe(injected);
    if (key) {
      expect(key.args).toContain(
        `model_catalog_json=${JSON.stringify(join(result.home, "launcher-models.json"))}`,
      );
      expect(key.args).toContain("features.api_key_model_discovery=false");
      expect(key.args).toContain('cli_auth_credentials_store="ephemeral"');
      expect(key.credentialEnv).toEqual(["CODEX_API_KEY"]);
      expect(key.home).not.toBe(result.home);
      expect(key.authFile).toBe(false);
    }
    expect(
      result.observations.every(
        (entry) => entry.home !== result.home && !entry.authFile,
      ),
    ).toBe(true);
    expect(
      result.observations.some((entry) => entry.action === "catalog-http"),
    ).toBe(false);
  }
  await expect(select("launcher-red", true)).rejects.toThrow(
    "--cyber-access-program daybreak_red",
  );
});

test("a launcher's relative catalog resolves in the scan directory before credentials are loaded", async () => {
  const select = (model: string) =>
    probeWithWorkspacePolicy(
      { config: { model, features: { api_key_model_discovery: false } } },
      {},
      { launcher: "legacy", injectedCatalog: "relative" },
    );
  const result = await select("launcher-blue");
  expect(result.program).toBe("daybreak_blue");
  const metadata = result.observations.find(
    (entry) => entry.action === "app-server",
  )!;
  expect(metadata.home).not.toBe(result.home);
  expect(metadata.authFile).toBe(false);
  expect(metadata.credentialEnv).toEqual([]);
  expect(metadata.args).toContain('cli_auth_credentials_store="ephemeral"');
  expect(
    result.observations.some((entry) => entry.action === "catalog-http"),
  ).toBe(false);
  await expect(select("launcher-red")).rejects.toThrow(
    "--cyber-access-program daybreak_red",
  );
});

test("an older launcher whose relative catalog is missing at startup falls back without credentials", async () => {
  const select = (config: JsonObject) =>
    probeWithWorkspacePolicy({ config: { model: "launcher-blue" } }, config, {
      launcher: "legacy",
      injectedCatalog: "target-only",
    });
  const result = await select({});
  expect(result.program).toBe("standard");
  const starts = result.observations.filter(
    (entry) => entry.action === "app-server",
  );
  expect(starts.length).toBeGreaterThanOrEqual(2);
  expect(new Set(starts.map((entry) => entry.home)).size).toBe(1);
  expect(
    starts.every(
      (entry) =>
        entry.home !== result.home &&
        !entry.authFile &&
        entry.credentialEnv.length === 0,
    ),
  ).toBe(true);
  expect(
    result.observations.some((entry) =>
      ["key-catalog", "model/list", "catalog-http", "account/read"].includes(
        entry.action,
      ),
    ),
  ).toBe(false);
  expect(
    (await select({ features: { api_key_cyber_access_programs: false } }))
      .program,
  ).toBeUndefined();
  await expect(
    select({ model_catalog_json: "explicitly-missing.json" }),
  ).rejects.toThrow("No such file or directory");
});

test.each([
  ["chatgpt", "unset", "standard"],
  ["api_key", "unset", undefined],
  ["chatgpt", "true", undefined],
  ["api_key", "false", undefined],
] as const)(
  "a masked catalog respects the known %s login and native daybreak setting %s",
  async (credentialType, daybreak, expected) => {
    const homeConfig = [
      ...(daybreak === "unset" ? [] : [`daybreak=${daybreak}`]),
      "[features]",
      "cli_daybreak=true",
      `api_key_cyber_access_programs=${daybreak !== "unset"}`,
    ].join("\n");
    const select = (config: JsonObject) =>
      probeWithWorkspacePolicy(
        { savedAccount: credentialType === "chatgpt" ? "chatgpt" : "apiKey" },
        config,
        {
          homeConfig,
          credentialType,
          storedLogin: true,
          launcher: "legacy",
          injectedCatalog: "target-only",
        },
      );
    const result = await select({});
    expect(result.program).toBe(expected);
    if (daybreak === "unset")
      expect(
        (await select({ features: { api_key_cyber_access_programs: false } }))
          .program,
      ).toBe(expected);
    const reads = result.observations.filter(
      (entry) => entry.action !== "help",
    );
    expect(
      reads.some((entry) => entry.authFile && entry.home === result.home),
    ).toBe(true);
    expect(
      reads.some(
        (entry) =>
          (entry.authFile && entry.home !== result.home) ||
          entry.credentialEnv.length ||
          ["model/list", "key-catalog", "catalog-http"].includes(entry.action),
      ),
    ).toBe(false);
  },
);

test.each(["file error", "silent"] as const)(
  "an opaque launcher that depends on its original home falls back without loading credentials (%s)",
  async (requiresHome) => {
    const select = (config: JsonObject, signal?: AbortSignal) =>
      probeWithWorkspacePolicy({ savedAccount: "chatgpt" }, config, {
        requiresHome,
        signal,
      });
    const result = await select({});
    expect(result.program).toBe("standard");
    expect(result.observations.length).toBeGreaterThanOrEqual(2);
    expect(
      result.observations.every(
        (entry) =>
          entry.action === "missing-launcher-settings" &&
          entry.home !== result.home &&
          !entry.authFile &&
          !entry.credentialEnv.length,
      ),
    ).toBe(true);
    await expect(
      select({ model_catalog_json: "explicitly-missing.json" }),
    ).rejects.toThrow();
    expect(
      (await select({ model_catalog_json: "scan-catalog.json" })).program,
    ).toBe("standard");
    await expect(
      select({}, AbortSignal.abort(new Error("cancelled catalog lookup"))),
    ).rejects.toThrow("cancelled catalog lookup");
  },
);

test("a launcher that reports an invalid native config keeps its diagnostic", async () => {
  await expect(
    probeWithWorkspacePolicy({}, {}, { requiresHome: "invalid config" }),
  ).rejects.toThrow(
    "Invalid Codex config: expected a TOML boolean for daybreak",
  );
});

test.each(["saved ChatGPT", "empty file store", "ephemeral store"])(
  "an opaque API-key launcher that changes route only in the original home respects %s",
  async (mode) => {
    const mixed = mode === "saved ChatGPT";
    const select = (model: string, local = true) =>
      probeWithWorkspacePolicy(
        { savedAccount: mixed ? "chatgpt" : null, config: { model } },
        { model },
        {
          homeConfig: `cli_auth_credentials_store="${mode === "ephemeral store" ? "ephemeral" : "file"}"\n`,
          launcher: "legacy",
          originalHomeEndpoint: true,
          homeCatalog: local,
        },
      );
    const blue = await select("gpt-test");
    expect(blue.program).toBe(mixed ? "standard" : "daybreak_blue");
    expect(blue.observations.length).toBeGreaterThan(0);
    expect(
      blue.observations.every(
        (entry) =>
          entry.home !== blue.home &&
          !entry.authFile &&
          !entry.credentialEnv.includes("CODEX_ACCESS_TOKEN"),
      ),
    ).toBe(true);
    if (mixed) {
      expect(
        blue.observations.every((entry) => !entry.credentialEnv.length),
      ).toBe(true);
      const unknown = await select("absent", false);
      expect(unknown.program).toBe("standard");
      expect(
        unknown.observations.every(
          (entry) =>
            entry.home !== unknown.home &&
            !entry.authFile &&
            !entry.credentialEnv.length &&
            entry.action !== "catalog-http",
        ),
      ).toBe(true);
    }
    if (mixed) expect((await select("gpt-red-only")).program).toBe("standard");
    else
      await expect(select("gpt-red-only")).rejects.toThrow(
        "--cyber-access-program daybreak_red",
      );
  },
);

test("stored catalog routing follows the SDK or native profile override order", async () => {
  const url = "https://chatgpt.com/selected/models";
  const other = "https://chatgpt.com/other/models";
  const literal = { "model_providers.openai.model_catalog_url": url };
  const sibling = { "model_providers.openai": { wire_api: "responses" } };
  const empty = { "model_providers.openai": {} };
  const replacement = {
    "model_providers.openai": { model_catalog_url: other },
  };
  // Native scan configuration is TOML-normalized: scalar keys precede tables.
  for (const [overrides, nativeProfile, expected] of [
    [{ ...literal, ...sibling }, false, url],
    [{ ...sibling, ...literal }, false, url],
    [{ ...literal, ...sibling }, true, undefined],
    [{ ...sibling, ...literal }, true, undefined],
    [{ ...literal, ...empty }, false, undefined],
    [{ ...empty, ...literal }, false, undefined],
    [{ ...literal, ...replacement }, false, other],
    [{ ...replacement, ...literal }, false, other],
  ] as const) {
    // Native can use a stored identity only on the selected catalog route.
    for (const route of [expected, expected === other ? url : other]) {
      const result = await probeWithWorkspacePolicy(
        {
          config: {
            model: "workspace-model",
            ...(route && {
              model_providers: { openai: { model_catalog_url: route } },
            }),
          },
        },
        overrides,
        { nativeProfile, storedLogin: true },
      );
      expect(
        result.program,
        JSON.stringify({ overrides, nativeProfile, expected, route }),
      ).toBe(route === expected ? "daybreak_blue" : "standard");
    }
  }
}, 30_000);

test("a dotted SDK catalog override never sends the key to a conflicting launcher route", async () => {
  const scanUrl = "https://chatgpt.com/caller/models";
  const launcherUrl = "https://chatgpt.com/launcher/models";
  const select = (config: JsonObject) =>
    probeWithWorkspacePolicy({ config: { model: "workspace-model" } }, config, {
      launcherOverrides: [
        `model_providers.openai.model_catalog_url=${JSON.stringify(launcherUrl)}`,
      ],
    });
  const dotted = await select({
    "model_providers.openai.model_catalog_url": scanUrl,
  });
  expect(dotted.program).toBe("standard");
  expect(
    dotted.observations.some((entry) => entry.action === "catalog-http"),
  ).toBe(false);
  const nested = await select({
    model_providers: { openai: { model_catalog_url: scanUrl } },
  });
  expect(nested.program).toBe("daybreak_blue");
  expect(
    nested.observations.find((entry) => entry.action === "catalog-http")?.route,
  ).toBe(launcherUrl);
});

test.each(["none", "same"] as const)(
  "a launcher that changes catalogs when given the project key cannot override the SDK URL (anonymous catalog: %s)",
  async (anonymous) => {
    const target = "https://chatgpt.com/scan/models";
    const redirected = "https://chatgpt.com/conditional/models";
    const select = (config: JsonObject) =>
      probeWithWorkspacePolicy(
        { config: { model: "workspace-model" } },
        config,
        {
          launcherOverrides:
            anonymous === "same"
              ? [
                  `model_providers.openai.model_catalog_url=${JSON.stringify(target)}`,
                ]
              : [],
          keyedLauncherCatalog: redirected,
        },
      );
    const constrained = await select({
      "model_providers.openai.model_catalog_url": target,
    });
    expect(constrained.program).toBe("standard");
    expect(
      constrained.observations.some(
        (entry) => entry.key !== undefined || entry.action === "catalog-http",
      ),
    ).toBe(false);
    const unrestricted = await select({});
    expect(unrestricted.program).toBe("daybreak_blue");
    expect(
      unrestricted.observations
        .filter((entry) => entry.action === "catalog-http")
        .map((entry) => [entry.route, entry.key]),
    ).toEqual([[redirected, "synthetic-key"]]);
  },
);

test.each([
  ["empty SDK provider table", {}, false, "standard"],
  ["native whole provider table", { name: "OpenAI" }, true, "standard"],
  ["SDK provider name only", { name: "OpenAI" }, false, "daybreak_blue"],
] as const)(
  "a key-dependent launcher preserves native precedence for %s",
  async (_case, provider, nativeProfile, expected) => {
    const route = "https://chatgpt.com/conditional/models";
    const result = await probeWithWorkspacePolicy(
      { config: { model: "workspace-model" } },
      { "model_providers.openai": provider },
      { keyedLauncherCatalog: route, nativeProfile },
    );
    expect(result.program).toBe(expected);
    expect(
      result.observations
        .filter((entry) => entry.action === "catalog-http")
        .map((entry) => [entry.route, entry.key]),
    ).toEqual(expected === "standard" ? [] : [[route, "synthetic-key"]]);
  },
);

test.each([
  ["a different URL", "https://chatgpt.com/managed/models"],
  ["the same URL", "https://chatgpt.com/launcher/models"],
  ["the built-in default URL", undefined],
] as const)(
  "a launcher catalog respects a managed provider requiring %s",
  async (_case, managedUrl) => {
    const launcherUrl = "https://chatgpt.com/launcher/models";
    const openai: JsonObject = managedUrl
      ? { model_catalog_url: managedUrl }
      : {};
    const select = (model: string, config: JsonObject = {}) =>
      probeWithWorkspacePolicy(
        {
          config: { model },
          requirements: { modelProviders: { openai } },
        },
        config,
        {
          keyedLauncherCatalog: "https://chatgpt.com/conditional/models",
          launcherOverrides: [
            `model_providers.openai.model_catalog_url=${JSON.stringify(launcherUrl)}`,
          ],
        },
      );
    const result = await select("workspace-model");
    expect(result.program).toBe("standard");
    expect(
      result.observations.some(
        (entry) => entry.action === "key-catalog" && entry.key !== undefined,
      ),
    ).toBe(false);
    expect(
      result.observations
        .filter((entry) => entry.action === "catalog-http")
        .map((entry) => [entry.route, entry.key]),
    ).toEqual([]);
    const local = { model_catalog_json: "scan-catalog.json" };
    const blue = await select("gpt-test", local);
    expect(blue.program).toBe("daybreak_blue");
    expect(
      blue.observations.some(
        (entry) => entry.action === "catalog-http" || entry.key !== undefined,
      ),
    ).toBe(false);
    await expect(select("gpt-red-only", local)).rejects.toThrow(
      "--cyber-access-program daybreak_red",
    );
  },
);

test("the keyed catalog uses the OpenAI provider required by the workspace despite a launcher override", async () => {
  const result = await probeWithWorkspacePolicy(
    {
      config: { model: "workspace-model" },
      requirements: { modelProvider: "openai" },
    },
    {},
    {
      homeConfig:
        '[model_providers.alternate]\nname="Synthetic alternate"\nbase_url="http://127.0.0.1:1/v1"\nwire_api="responses"\nhttp_headers={"X-Fixture"="synthetic-alternate-secret"}\n',
      launcherOverrides: ['model_provider="alternate"'],
    },
  );
  expect(result.program).toBe("daybreak_blue");
  const key = result.observations.find(
    (entry) => entry.action === "key-catalog",
  )!;
  expect(key.snapshot + key.args.join(" ")).not.toContain(
    "synthetic-alternate-secret",
  );
  expect(key.args.filter((arg) => arg.startsWith("model_provider="))).toEqual([
    'model_provider="alternate"',
    'model_provider="openai"',
  ]);
  expect(
    result.observations
      .filter((entry) => entry.action === "catalog-http")
      .map((entry) => [entry.provider, entry.key]),
  ).toEqual([["openai", "synthetic-key"]]);
});

test("a launcher-provided identity endpoint is inspected without opening the saved credential home", async () => {
  const result = await probeWithWorkspacePolicy(
    { savedAccount: "chatgpt" },
    {},
    { launcherOverrides: ['chatgpt_base_url="https://identity.example.test"'] },
  );
  expect(result.program).toBe("standard");
  const starts = result.observations.filter(
    (entry) => entry.action === "app-server",
  );
  expect(starts.length).toBeGreaterThan(0);
  expect(
    starts.every(
      (entry) =>
        entry.home !== result.home &&
        !entry.authFile &&
        !entry.credentialEnv.length,
    ),
  ).toBe(true);
  expect(
    result.observations.some((entry) =>
      ["account/read", "key-catalog", "catalog-http"].includes(entry.action),
    ),
  ).toBe(false);
});

test("the scan's forced login method takes precedence in a guarded project-key lookup", async () => {
  const select = (
    model: string,
    caller: "api" | "chatgpt",
    launcher: "api" | "chatgpt",
  ) =>
    probeWithWorkspacePolicy(
      { savedAccount: "chatgpt" },
      {
        model,
        model_catalog_json: "scan-catalog.json",
        forced_login_method: caller,
      },
      {
        launcherOverrides: [
          'chatgpt_base_url="https://identity.example.test"',
          `forced_login_method=${JSON.stringify(launcher)}`,
        ],
      },
    );
  await expect(select("gpt-red-only", "api", "chatgpt")).rejects.toThrow(
    "--cyber-access-program daybreak_red",
  );
  const blue = await select("gpt-test", "api", "chatgpt");
  expect(blue.program).toBe("standard");
  const disabled = await select("gpt-red-only", "chatgpt", "api");
  expect(disabled.program).toBeUndefined();
  for (const result of [blue, disabled]) {
    expect(
      result.observations.every(
        (entry) =>
          entry.home !== result.home &&
          !entry.authFile &&
          !entry.credentialEnv.length &&
          !["catalog-http", "account/read"].includes(entry.action),
      ),
    ).toBe(true);
  }
  expect(
    disabled.observations.some((entry) =>
      ["key-catalog", "model/list"].includes(entry.action),
    ),
  ).toBe(false);
});

test("a guarded login endpoint only checks a Red-only file when the scan selects OpenAI", async () => {
  const select = (config: JsonObject) =>
    probeWithWorkspacePolicy(
      { savedAccount: "chatgpt" },
      {
        model: "gpt-red-only",
        model_catalog_json: "scan-catalog.json",
        ...config,
      },
      {
        launcherOverrides: [
          'chatgpt_base_url="https://identity.example.test"',
          'model_providers.custom={name="Synthetic",base_url="http://127.0.0.1:1/v1",wire_api="responses"}',
          'model_provider="custom"',
        ],
      },
    );
  const custom = await select({});
  expect(custom.program).toBeUndefined();
  expect(
    custom.observations.some(
      (entry) =>
        entry.authFile ||
        entry.credentialEnv.length ||
        ["model/list", "key-catalog", "catalog-http", "account/read"].includes(
          entry.action,
        ),
    ),
  ).toBe(false);
  await expect(select({ model_provider: "openai" })).rejects.toThrow(
    "--cyber-access-program daybreak_red",
  );
});

test.each(["home", "SDK", "undeclared"])(
  "a guarded launcher honors provider registration (%s)",
  async (definition) => {
    const registry = [
      "[model_providers.custom]",
      'name="synthetic-private-provider-name"',
      'base_url="http://127.0.0.1:1/synthetic-private-provider"',
      'wire_api="responses"',
      'http_headers={Authorization="synthetic-private-provider-header"}',
      "[model_providers.custom.auth]",
      'command="synthetic-private-provider-auth"',
    ].join("\n");
    const select = (caller: JsonObject = {}) =>
      probeWithWorkspacePolicy(
        { savedAccount: "chatgpt" },
        {
          model: "gpt-red-only",
          model_catalog_json: "scan-catalog.json",
          ...(definition === "SDK"
            ? (Bun.TOML.parse(registry) as JsonObject)
            : {}),
          ...caller,
        },
        {
          homeConfig: definition === "home" ? registry : undefined,
          launcherOverrides: [
            'model_provider="custom"',
            'chatgpt_base_url="https://identity.example.test"',
          ],
        },
      );
    if (definition === "undeclared") {
      await expect(select()).rejects.toThrow(
        "Model provider `custom` not found",
      );
    } else {
      const result = await select();
      expect(result.program).toBeUndefined();
      expect(
        result.observations.some(
          (entry) =>
            entry.authFile ||
            entry.credentialEnv.length ||
            [
              "key-catalog",
              "model/list",
              "catalog-http",
              "account/read",
            ].includes(entry.action),
        ),
      ).toBe(false);
      expect(
        result.observations
          .flatMap((entry) => [...(entry.args ?? []), entry.snapshot ?? ""])
          .join(" "),
      ).not.toContain("synthetic-private-provider");
    }
    await expect(select({ model_provider: "openai" })).rejects.toThrow(
      "--cyber-access-program daybreak_red",
    );
  },
);

test.each(["home", "launcher", "caller"])(
  "a guarded login endpoint uses the provider selected by the %s",
  async (selection) => {
    const homeConfig = [
      'model_provider="alternate"',
      "[model_providers.alternate]",
      'name="Synthetic alternate"',
      'base_url="http://127.0.0.1:1/v1"',
      'wire_api="responses"',
      'http_headers={"X-Fixture-Auth"="synthetic-private-header"}',
      "[model_providers.alternate.auth]",
      'command="synthetic-private-command"',
    ].join("\n");
    const select = (model: string, local: boolean) =>
      probeWithWorkspacePolicy(
        { savedAccount: "chatgpt" },
        {
          model,
          ...(local && { model_catalog_json: "scan-catalog.json" }),
          ...(selection === "caller" && { model_provider: "openai" }),
        },
        {
          homeConfig,
          launcherOverrides: [
            'chatgpt_base_url="https://identity.example.test"',
            ...(selection === "launcher" ? ['model_provider="openai"'] : []),
          ],
        },
      );
    for (const [model, local] of [
      ["no-metadata", false],
      ["gpt-standard-only", true],
    ] as const) {
      const result = await select(model, local);
      expect(result.program).toBe(
        selection === "home" ? undefined : "standard",
      );
      if (selection === "home")
        expect(
          result.observations.some((entry) => entry.action === "key-catalog"),
        ).toBe(false);
      const probeInputs = result.observations.flatMap((entry) => [
        ...(entry.args ?? []),
        entry.home === result.home ? "" : (entry.snapshot ?? ""),
      ]);
      expect(probeInputs.join(" ")).not.toMatch(
        /synthetic-private-(?:command|header)/,
      );
      expect(
        result.observations.some(
          (entry) =>
            entry.authFile ||
            entry.credentialEnv.length ||
            entry.action === "account/read" ||
            entry.action === "catalog-http",
        ),
      ).toBe(false);
    }
    if (selection === "home")
      expect((await select("gpt-red-only", true)).program).toBeUndefined();
    else
      await expect(select("gpt-red-only", true)).rejects.toThrow(
        "--cyber-access-program daybreak_red",
      );
  },
);

test.each([
  ["caller", true],
  ["launcher", false],
] as const)(
  "an explicit native home Daybreak setting bypasses selection when the %s selects OpenAI",
  async (selection, daybreak) => {
    const result = await probeWithWorkspacePolicy(
      { savedAccount: "chatgpt" },
      {
        model: "gpt-red-only",
        model_catalog_json: "scan-catalog.json",
        ...(selection === "caller" && { model_provider: "openai" }),
      },
      {
        homeConfig: `daybreak=${daybreak}\n`,
        launcherOverrides: [
          'chatgpt_base_url="https://identity.example.test"',
          ...(selection === "launcher" ? ['model_provider="openai"'] : []),
        ],
      },
    );
    expect(result.program).toBeUndefined();
    expect(
      result.observations.some(
        (entry) =>
          entry.action === "key-catalog" ||
          entry.action === "model/list" ||
          entry.authFile ||
          entry.credentialEnv.length,
      ),
    ).toBe(false);
  },
);

test("model discovery preserves the SDK and native profile feature override semantics", async () => {
  const select = (
    features: JsonObject,
    nativeProfile = false,
    model = "workspace-model",
  ) =>
    probeWithWorkspacePolicy(
      { config: { model } },
      { features },
      { launcherDiscovery: false, nativeProfile },
    );
  const plugins = await select({ plugins: true });
  expect(plugins.program).toBe("standard");
  expect(
    plugins.observations.some((entry) => entry.action === "catalog-http"),
  ).toBe(false);
  const reset = await select({});
  expect(reset.program).toBe("daybreak_blue");
  expect(
    reset.observations.some((entry) => entry.action === "catalog-http"),
  ).toBe(true);
  const profile = await select({ plugins: true }, true);
  expect(profile.program).toBe("daybreak_blue");
  await expect(
    select({ plugins: true }, true, "requested-model"),
  ).rejects.toThrow("--cyber-access-program daybreak_red");
});

test("the initial scratch app-server preserves native-home analytics consent at its original precedence", async () => {
  const select = (launcherOverrides: string[]) =>
    probeWithWorkspacePolicy(
      { config: { model: "workspace-model" } },
      {},
      {
        homeConfig: "[analytics]\nenabled=false\n",
        analyticsDefault: true,
        launcherOverrides,
      },
    );
  for (const launcherOptIn of [false, true]) {
    const result = await select(
      launcherOptIn ? ["analytics.enabled=true"] : [],
    );
    const first = result.observations.find(
      (entry) => entry.action === "app-server",
    )!;
    expect(first.home).not.toBe(result.home);
    expect(first.args).toContain("--analytics-default-enabled");
    expect(first.analyticsEnabled).toBe(launcherOptIn);
  }
});

test.each(["keyed", "disabled discovery", "home catalog"])(
  "the %s lookup inherits effective analytics settings from native config",
  async (mode) => {
    const analytics = { enabled: false };
    const attribution = {
      codex_security_operation_id: "synthetic-home-operation",
    };
    const header = "synthetic-home-exporter-secret";
    const catalog = fileURLToPath(
      new URL("./fixtures/native-skill-model-catalog.json", import.meta.url),
    );
    const result = await probeWithWorkspacePolicy(
      {
        config: {
          model: mode === "home catalog" ? "gpt-test" : "workspace-model",
          ...(mode === "disabled discovery" && {
            features: { api_key_model_discovery: false },
          }),
          analytics,
          responses_api_metadata: attribution,
          otel: {
            exporter: {
              "otlp-http": { headers: { "x-fixture-header": header } },
            },
          },
        },
        ...(mode === "home catalog" && {
          layers: [
            { name: { type: "user" }, config: { model_catalog_json: catalog } },
          ],
        }),
      },
      {},
      {
        homeConfig: `analytics.enabled=false\nresponses_api_metadata.codex_security_operation_id="synthetic-home-operation"\n`,
      },
    );
    expect(result.program).toBe(
      mode === "disabled discovery" ? "standard" : "daybreak_blue",
    );
    const key = result.observations.find(
      (entry) =>
        entry.key !== undefined &&
        entry.action ===
          (mode === "disabled discovery" ? "app-server" : "key-catalog"),
    )!;
    expect(Bun.TOML.parse(key.snapshot)).toMatchObject({
      analytics,
      responses_api_metadata: attribution,
    });
    expect(key.snapshot + key.args.join(" ")).not.toContain(header);
    expect(key.credentialEnv).toEqual(["CODEX_API_KEY"]);
  },
);

test.each(["online", "offline"])(
  "the %s catalog commands honor scan analytics and operation attribution",
  async (mode) => {
    const result = await probeWithWorkspacePolicy(
      {
        config: {
          model: "workspace-model",
        },
      },
      {
        ...(mode === "online"
          ? { analytics: { enabled: false } }
          : { "analytics.enabled": false }),
        responses_api_metadata: {
          codex_security_operation_id: "synthetic-catalog-operation",
        },
        otel: {
          exporter: {
            "otlp-http": {
              headers: {
                "x-fixture-token": "synthetic-private-exporter-header",
              },
            },
          },
        },
        ...(mode === "offline" && {
          features: { api_key_model_discovery: false },
        }),
      },
      { injectedCatalog: mode === "offline" ? false : undefined },
    );
    expect(result.program).toBe(
      mode === "online" ? "daybreak_blue" : "standard",
    );
    const commands = result.observations.filter((entry) =>
      ["app-server", "bundled-catalog", "key-catalog"].includes(entry.action),
    );
    const metadata = commands.find(
      (entry) => entry.action === "app-server" && entry.home !== result.home,
    )!;
    const sqliteHome = join(metadata.home, "sqlite");
    expect(
      commands.every(
        (entry) =>
          entry.sqliteHome === sqliteHome &&
          entry.args.filter((arg) => arg.startsWith("sqlite_home=")).at(-1) ===
            `sqlite_home=${JSON.stringify(sqliteHome)}`,
      ),
    ).toBe(true);
    expect(commands.some((entry) => entry.action === "bundled-catalog")).toBe(
      true,
    );
    expect(
      commands.some(
        (entry) =>
          entry.action ===
            (mode === "offline" ? "app-server" : "key-catalog") &&
          entry.key !== undefined,
      ),
    ).toBe(true);
    for (const entry of commands) {
      const args = entry.args.join(" ");
      expect(args).toMatch(
        /analytics(?:\.enabled|=\{["']?enabled["']?)\s*=\s*false/,
      );
      expect(args).toContain("synthetic-catalog-operation");
      expect(args).not.toContain("synthetic-private-exporter-header");
    }
  },
);

test("a launcher-provided static catalog takes precedence over the user's home catalog", async () => {
  const directory = await mkdtemp(join(tmpdir(), "scan-home-catalog-"));
  const catalog = join(directory, "models.json");
  try {
    await writeFile(
      catalog,
      JSON.stringify({
        models: [
          {
            slug: "launcher-blue",
            available_access_programs: { cyber: ["daybreak_red"] },
          },
        ],
      }),
    );
    const result = await probeWithWorkspacePolicy(
      {
        config: { model: "launcher-blue" },
        layers: [
          { name: { type: "user" }, config: { model_catalog_json: catalog } },
        ],
      },
      {},
      { injectedCatalog: true },
    );
    expect(result.program).toBe("daybreak_blue");
    expect(
      result.observations.some((entry) => entry.action === "catalog-http"),
    ).toBe(false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("the keyed catalog keeps the caller's model discovery override after the launcher's flag", async () => {
  const result = await probeWithWorkspacePolicy(
    { config: { model: "workspace-model" } },
    { features: { api_key_model_discovery: true } },
    { launcherDiscovery: false },
  );
  expect(result.program).toBe("daybreak_blue");
  const key = result.observations.find(
    (entry) => entry.action === "key-catalog",
  )!;
  expect(
    key.args.filter((arg) =>
      arg.startsWith("features.api_key_model_discovery="),
    ),
  ).toEqual([
    "features.api_key_model_discovery=false",
    "features.api_key_model_discovery=true",
  ]);
});

test.each(["scan", "home", "managed"])(
  "a %s static catalog follows native precedence under managed network controls",
  async (source) => {
    const directory = await mkdtemp(join(tmpdir(), "scan-offline-catalog-"));
    const catalog = join(directory, "models.json");
    try {
      await writeFile(
        catalog,
        JSON.stringify({
          models: [
            {
              slug: "offline-blue",
              available_access_programs: { cyber: ["daybreak_blue"] },
            },
            {
              slug: "offline-red",
              available_access_programs: { cyber: ["daybreak_red"] },
            },
          ],
        }),
      );
      const select = (model: string) =>
        probeWithWorkspacePolicy(
          {
            config: { model },
            requirements: {
              enforceResidency: "us",
              featureRequirements: { respect_system_proxy: true },
              application: { network: { enabled: true } },
              ...(source === "managed" && {
                modelCatalogJson: pathToFileURL(catalog).href,
              }),
            },
            layers:
              source === "home"
                ? [
                    {
                      name: { type: "user" },
                      config: { model_catalog_json: catalog },
                    },
                  ]
                : [],
          },
          source === "scan" ? { model_catalog_json: catalog } : {},
        );
      const blue = await select("offline-blue");
      expect(blue.program).toBe(
        source === "home" ? "standard" : "daybreak_blue",
      );
      expect(
        blue.observations.some((entry) => entry.action === "key-catalog"),
      ).toBe(false);
      expect(
        blue.observations.find((entry) => entry.action === "model/list")
          ?.catalog,
      ).toBe(source === "home" ? undefined : catalog);
      expect(
        blue.observations.some(
          (entry) => entry.action === "catalog-http" || entry.key !== undefined,
        ),
      ).toBe(false);
      if (source === "home")
        expect((await select("offline-red")).program).toBe("standard");
      else
        await expect(select("offline-red")).rejects.toThrow(
          "--cyber-access-program daybreak_red",
        );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test("only the isolated key reads the scan catalog using the native effective model", async () => {
  const scanEndpoint = "https://scan-only.example.test/";
  const result = await probeWithWorkspacePolicy(
    {
      config: { model: "workspace-model", cli_auth_credentials_store: "file" },
    },
    {
      model_providers: {
        synthetic: {
          name: "Synthetic registry provider",
          wire_api: "responses",
          http_headers: { "X-Fixture-Token": "synthetic-private-header" },
        },
        openai: {
          model_catalog_url:
            "https://chatgpt.com/backend-api/private-scan-catalog",
        },
      },
      model: "requested-model",
      chatgpt_base_url: scanEndpoint,
      openai_base_url: scanEndpoint + "v1",
      features: { respect_system_proxy: true, system_proxy_fallback: false },
    },
  );
  expect(result.program).toBe("daybreak_blue");
  const stored = result.observations.find(
    (entry) =>
      entry.action === "app-server" &&
      entry.args.some((arg) => arg.includes("Synthetic registry provider")),
  )!;
  expect(stored.key).toBeUndefined();
  expect(stored.home).not.toBe(result.home);
  expect(stored.lockHeld).toBe(false);
  const bootstrapSettings = stored.args.join(" ") + stored.snapshot;
  expect(bootstrapSettings).not.toContain(scanEndpoint);
  expect(bootstrapSettings).toContain("Synthetic registry provider");
  expect(bootstrapSettings).not.toContain("synthetic-private-header");
  const key = result.observations.find(
    (entry) => entry.action === "key-catalog",
  )!;
  expect(key.key).toBe("synthetic-key");
  expect(key.lockHeld).toBe(false);
  expect(key.snapshot).toMatch(/model_provider\s*=\s*"openai"/);
  expect(key.originator).toBe("codex_sdk_ts");
  expect(key.home).not.toBe(result.home);
  const keySettings = key.args.join(" ") + key.snapshot;
  expect(keySettings).toContain(scanEndpoint);
  expect(key.snapshot).toContain("private-scan-catalog");
  expect(key.args.join(" ")).not.toContain("private-scan-catalog");
  expect(keySettings).toMatch(/respect_system_proxy["']?\s*=\s*true/);
  expect(keySettings).toMatch(/system_proxy_fallback["']?\s*=\s*false/);
});

test("a Codex launcher without --cd still requests Blue and rejects Red-only models", async () => {
  const launcher = {
    launcher: "legacy",
    originator: "synthetic-sdk-origin",
  } as const;
  const blue = await probeWithWorkspacePolicy(
    {
      config: { model: "workspace-model" },
      startupConfig: { model: "requested-model" },
      layers: [
        { name: { type: "project" }, config: { model: "workspace-model" } },
      ],
      startupLayers: [
        { name: { type: "project" }, config: { model: "requested-model" } },
      ],
    },
    {},
    launcher,
  );
  expect(blue.program).toBe("daybreak_blue");
  expect(new Set(blue.observations.map((entry) => entry.cwd))).toEqual(
    new Set([blue.launcherCwd]),
  );
  expect(blue.observations.map((entry) => entry.action)).toContain(
    "bundled-catalog",
  );
  expect(
    blue.observations.find((entry) => entry.action === "app-server")?.args,
  ).not.toContain("--cd");
  expect(
    blue.observations.find((entry) => entry.action === "config/read")
      ?.configCwd,
  ).toBe(blue.home);
  expect(
    blue.observations.find((entry) => entry.action === "key-catalog")
      ?.originator,
  ).toBe(launcher.originator);
  await expect(
    probeWithWorkspacePolicy(
      { config: { model: "requested-model" } },
      {},
      launcher,
    ),
  ).rejects.toThrow("--cyber-access-program daybreak_red");
});

test.each([
  ["enabled Daybreak", {}, "standard"],
  ["disabled Daybreak", { cli_daybreak: false }, undefined],
  [
    "disabled API-key forwarding",
    { api_key_cyber_access_programs: false },
    undefined,
  ],
] as const)(
  "an older launcher skips the keyed catalog with a different workspace login and %s",
  async (_mode, features, expected) => {
    const result = await probeWithWorkspacePolicy(
      {
        savedAccount: "chatgpt",
        config: { model: "workspace-model", features },
        startupConfig: { forced_login_method: "api" },
      },
      {},
      { launcher: "legacy" },
    );
    expect(result.program).toBe(expected);
    expect(
      result.observations.some((entry) => entry.action === "key-catalog"),
    ).toBe(false);
  },
);

test.each([
  [
    "project disables forwarding",
    "api_key_cyber_access_programs",
    null,
    undefined,
  ],
  [
    "session enables forwarding",
    "api_key_cyber_access_programs",
    "session",
    "standard",
  ],
  [
    "machine requires forwarding",
    "api_key_cyber_access_programs",
    "machine",
    "standard",
  ],
  ["project disables Daybreak", "cli_daybreak", null, undefined],
  [
    "project forces API login and disables forwarding",
    "api_key_cyber_access_programs",
    "api-login",
    undefined,
  ],
  ["project uses native defaults", undefined, null, "standard"],
] as const)(
  "a legacy launcher with a different workspace honors local settings when the %s",
  async (_case, feature, override, expected) => {
    const enabled = { cli_daybreak: true, api_key_cyber_access_programs: true };
    const sessionEnabled = override === "session";
    const apiLogin = override === "api-login";
    const targetLogin: JsonObject = apiLogin
      ? { forced_login_method: "api" }
      : { cli_auth_credentials_store: "ephemeral" };
    const selector = apiLogin
      ? 'forced_login_method="api"'
      : 'cli_auth_credentials_store="ephemeral"';
    const scanConfig: JsonObject = sessionEnabled
      ? { features: { api_key_cyber_access_programs: true } }
      : apiLogin
        ? { cli_auth_credentials_store: "file" }
        : {};
    const session =
      sessionEnabled || apiLogin
        ? [{ name: { type: "sessionFlags" }, config: scanConfig }]
        : [];
    const result = await probeWithWorkspacePolicy(
      {
        savedAccount: "chatgpt",
        config: {
          model: "workspace-model",
          ...scanConfig,
          ...targetLogin,
          features: enabled,
        },
        startupConfig: {
          cli_auth_credentials_store: "file",
          ...(apiLogin && { forced_login_method: "chatgpt" }),
        },
        requirements: { featureRequirements: enabled },
        targetLoginPolicy: {
          selector,
          features: feature ? { [feature]: sessionEnabled } : {},
          requirements:
            override === "machine" ? { featureRequirements: enabled } : {},
        },
        layers: [
          ...session,
          {
            name: { type: "project" },
            config: {
              ...targetLogin,
              features: feature ? { [feature]: false } : {},
            },
          },
        ],
        startupLayers: session,
      },
      scanConfig,
      { launcher: "legacy" },
    );
    expect(result.program).toBe(expected);
    const policyStarts = result.observations.filter(
      (entry) => entry.action === "app-server",
    );
    expect(policyStarts.length).toBeGreaterThan(0);
    expect(
      policyStarts.every(
        (entry) => entry.home !== result.home && !entry.key && !entry.authFile,
      ),
    ).toBe(true);
    expect(
      result.observations.some((entry) => entry.action === "key-catalog"),
    ).toBe(false);
  },
);

test("an older launcher honors a project login mismatch masked by workspace settings", async () => {
  const result = await probeWithWorkspacePolicy(
    {
      savedAccount: "chatgpt",
      config: { model: "workspace-model", cli_auth_credentials_store: "file" },
      layers: [
        {
          name: { type: "project" },
          config: { forced_login_method: "chatgpt" },
        },
      ],
      startupLayers: [
        { name: { type: "project" }, config: { forced_login_method: "api" } },
      ],
    },
    {},
    { launcher: "legacy" },
  );
  expect(result.program).toBe("standard");
  expect(
    result.observations.some((entry) => entry.action === "key-catalog"),
  ).toBe(false);
});

test.each(["keyed", "offline"] as const)(
  "the %s catalog command overrides a relative launcher's project trust flags",
  async (mode) => {
    const launcherFlags = (cwd: string): [string, string] => [
      'project_root_markers=[".git"]',
      `projects={${JSON.stringify(projectTrustKey(cwd))}={trust_level="trusted"}}`,
    ];
    const result = await probeWithWorkspacePolicy(
      { config: { model: mode === "keyed" ? "workspace-model" : "gpt-test" } },
      mode === "offline"
        ? { features: { api_key_model_discovery: false } }
        : {},
      {
        launcher: "legacy",
        launcherOverrides: launcherFlags,
        homeCatalog: mode === "offline",
      },
    );
    expect(result.program).toBe("daybreak_blue");
    const debug = result.observations.find(
      (entry) => entry.action === "key-catalog",
    )!;
    expect(debug.cwd).toBe(result.launcherCwd);
    expect(debug.credentialEnv).toEqual(["CODEX_API_KEY"]);
    if (mode === "offline")
      expect(debug.args).toContain("features.api_key_model_discovery=false");
    const [originalMarkers, originalTrust] = launcherFlags(result.launcherCwd);
    const flags = debug.args.filter(
      (_, index, args) => args[index - 1] === "-c",
    );
    expect(
      flags.filter((flag) => flag.startsWith("project_root_markers=")),
    ).toEqual([originalMarkers, "project_root_markers=[]"]);
    const trust = flags.filter((flag) => flag.startsWith("projects="));
    expect(trust[0]).toBe(originalTrust);
    expect(Bun.TOML.parse(trust.at(-1)!)).toEqual({
      projects: {
        [projectTrustKey(result.launcherCwd)]: { trust_level: "untrusted" },
      },
    });
  },
);

test.each(["configured", "default"])(
  "catalog discovery isolates SQLite with a %s scan directory setting on a relative launcher",
  async (mode) => {
    const injectedSqlite = 'sqlite_home="launcher-state"';
    const result = await probeWithWorkspacePolicy(
      { config: { model: "gpt-test" } },
      {
        project_root_markers: [".scan-workspace"],
        ...(mode === "configured" && { sqlite_home: "scan-state" }),
        model_catalog_json: "scan-catalog.json",
      },
      { launcher: "modern", launcherOverrides: [injectedSqlite] },
    );
    expect(result.program).toBe("daybreak_blue");
    expect(new Set(result.observations.map((entry) => entry.cwd))).toEqual(
      new Set([result.launcherCwd]),
    );
    const servers = result.observations.filter(
      (entry) => entry.action === "app-server",
    );
    expect(servers.length).toBeGreaterThanOrEqual(2);
    for (const { args } of servers) {
      expect(args).toContain("--cd");
      expect(args[args.indexOf("--cd") + 1]).toBe(result.home);
      expect(args).toContain('project_root_markers=[".scan-workspace"]');
    }
    const metadata = servers[0]!;
    const policyArgs = servers.at(-1)!.args;
    const sqliteFlags = metadata.args.filter((arg) =>
      arg.startsWith("sqlite_home="),
    );
    expect(sqliteFlags[0]).toBe(injectedSqlite);
    const selected = JSON.parse(
      sqliteFlags.at(-1)!.slice("sqlite_home=".length),
    ) as string;
    expect(
      selected === metadata.home || selected.startsWith(metadata.home + sep),
    ).toBe(true);
    expect(
      policyArgs.filter((arg) => arg.startsWith("sqlite_home=")).at(-1),
    ).toBe(sqliteFlags.at(-1));
    const local = result.observations.find(
      (entry) => entry.action === "key-catalog",
    );
    expect(
      local?.args.filter((arg) => arg.startsWith("model_catalog_json=")).at(-1),
    ).toBe(
      `model_catalog_json=${JSON.stringify(join(result.home, "scan-catalog.json"))}`,
    );
  },
);

test.each([
  ["hidden ChatGPT login", "chatgpt", "api", {}, "daybreak_blue"],
  ["hidden API login", "apiKey", "chatgpt", {}, "daybreak_blue"],
  ["signed-out scan", null, undefined, {}, undefined],
  [
    "locally disabled Daybreak",
    "chatgpt",
    "api",
    { cli_daybreak: false },
    undefined,
  ],
  [
    "locally disabled API forwarding",
    "apiKey",
    "chatgpt",
    { api_key_cyber_access_programs: false },
    undefined,
  ],
] as const)(
  "an older launcher with a %s looks at the target's authentication scope",
  async (_case, savedAccount, forced, features, expected) => {
    const select = (model: string) =>
      probeWithWorkspacePolicy(
        {
          savedAccount,
          config: { model, features },
          startupConfig: forced ? { forced_login_method: forced } : {},
          startupLayers: forced
            ? [
                {
                  name: { type: "project" },
                  config: { forced_login_method: forced },
                },
              ]
            : [],
        },
        {
          cli_auth_credentials_store: "auto",
          model_catalog_json: "scan-catalog.json",
        },
        { launcher: "legacy", storedLogin: true },
      );
    const resolved = await select("gpt-test");
    expect(resolved.program).toBe(expected);
    expect(
      resolved.observations.some((entry) => entry.action === "key-catalog"),
    ).toBe(false);
    if (expected === "daybreak_blue") {
      const accountReads = resolved.observations.filter(
        (entry) => entry.action === "account/read",
      );
      expect(accountReads.map((entry) => entry.account?.type ?? null)).toEqual([
        savedAccount,
      ]);
      expect(
        accountReads.every(
          (entry) => entry.home === resolved.home && entry.authFile,
        ),
      ).toBe(true);
      const rebound = resolved.observations.find(
        (entry) =>
          entry.action === "app-server" &&
          entry.args.includes("project_root_markers=[]"),
      );
      expect(rebound?.home).toBe(resolved.home);
      expect(rebound?.credentialEnv).toEqual([]);
      await expect(select("gpt-red-only")).rejects.toThrow(
        "--cyber-access-program daybreak_red",
      );
    }
  },
);

test("an older launcher with a persistent login mismatch forwards Standard without reading the wrong account", async () => {
  const launcherConfig = { forced_login_method: "api" };
  const result = await probeWithWorkspacePolicy(
    {
      savedAccount: "chatgpt",
      config: { model: "gpt-test" },
      startupConfig: launcherConfig,
      neutralStartupConfig: launcherConfig,
    },
    { model_catalog_json: "scan-catalog.json" },
    { launcher: "legacy", storedLogin: true },
  );
  expect(result.program).toBe("standard");
  expect(
    result.observations.some(
      (entry) =>
        entry.action === "account/read" ||
        entry.action === "model/list" ||
        entry.action === "key-catalog",
    ),
  ).toBe(false);
});

test.each([
  ["apiKey", undefined],
  ["chatgpt", "standard"],
] as const)(
  "an older launcher's persistent login policy honors disabled forwarding for a saved %s account",
  async (savedAccount, expected) => {
    const launcherConfig = { forced_login_method: "api" };
    const result = await probeWithWorkspacePolicy(
      {
        savedAccount,
        config: {
          model: "gpt-test",
          cli_auth_credentials_store: "file",
          features: { api_key_cyber_access_programs: false },
        },
        startupConfig: launcherConfig,
        neutralStartupConfig: launcherConfig,
      },
      { cli_auth_credentials_store: "file" },
      { launcher: "legacy", storedLogin: true },
    );
    expect(result.program).toBe(expected);
    expect(
      result.observations.some(
        (entry) =>
          entry.action === "key-catalog" || entry.action === "model/list",
      ),
    ).toBe(false);
  },
);

test.each([
  [
    "known key with launcher forwarding enabled",
    "api_key",
    "api",
    true,
    "file",
    undefined,
  ],
  [
    "known key hidden by a ChatGPT-only launcher",
    "api_key",
    "chatgpt",
    false,
    "file",
    undefined,
  ],
  [
    "known key with a different launcher store",
    "api_key",
    "api",
    true,
    "ephemeral",
    "standard",
  ],
  ["known ChatGPT target", "chatgpt", "api", true, "file", "standard"],
  ["unknown target identity", undefined, "api", true, "file", "standard"],
] as const)(
  "a persistent launcher mismatch respects disabled target forwarding with %s",
  async (_case, credentialType, forcedLogin, forwarding, store, expected) => {
    const target = {
      cli_auth_credentials_store: "file",
      features: { api_key_cyber_access_programs: false },
    };
    const launch = {
      cli_auth_credentials_store: store,
      forced_login_method: forcedLogin,
      features: { api_key_cyber_access_programs: forwarding },
    };
    const result = await probeWithWorkspacePolicy(
      {
        savedAccount: credentialType === "chatgpt" ? "chatgpt" : "apiKey",
        config: target,
        startupConfig: launch,
        neutralStartupConfig: launch,
        layers: [
          { name: { type: "project" }, config: { features: target.features } },
        ],
        startupLayers: [
          {
            name: { type: "project" },
            config: {
              forced_login_method: forcedLogin,
              features: launch.features,
            },
          },
        ],
      },
      { model_catalog_json: "scan-catalog.json" },
      { launcher: "legacy", storedLogin: true, credentialType },
    );
    expect(result.program).toBe(expected);
    expect(
      result.observations.some((entry) =>
        ["key-catalog", "catalog-http", "model/list", "account/read"].includes(
          entry.action,
        ),
      ),
    ).toBe(false);
  },
);

test.each([
  [
    "a different workspace",
    { forced_chatgpt_workspace_id: "synthetic-launcher-workspace" },
  ],
  ["a different credential store", { cli_auth_credentials_store: "ephemeral" }],
] as const)(
  "a target that requires API login and disables forwarding omits the program when the launcher selects %s",
  async (_case, mismatch) => {
    const target = {
      forced_login_method: "api",
      features: { api_key_cyber_access_programs: false },
    };
    const launch = {
      forced_login_method: null,
      features: { api_key_cyber_access_programs: true },
      ...mismatch,
    };
    const result = await probeWithWorkspacePolicy(
      {
        savedAccount: "apiKey",
        config: { ...target, cli_auth_credentials_store: "file" },
        startupConfig: launch,
        neutralStartupConfig: launch,
        layers: [{ name: { type: "project" }, config: target }],
        startupLayers: [{ name: { type: "project" }, config: mismatch }],
      },
      {},
      { launcher: "legacy", storedLogin: true, credentialType: "api_key" },
    );
    expect(result.program).toBeUndefined();
    expect(
      result.observations.some((entry) =>
        ["model/list", "account/read", "key-catalog", "catalog-http"].includes(
          entry.action,
        ),
      ),
    ).toBe(false);
  },
);

test("an API-only legacy launcher confirms the scan's selected credential store before applying its disabled gate", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "scan-target-store-")),
  );
  const home = join(root, "home");
  const invocation = join(root, "invocation");
  const target = join(root, "target");
  try {
    await Promise.all([
      mkdir(home),
      mkdir(target),
      mkdir(join(invocation, ".codex"), { recursive: true }),
      mkdir(join(invocation, ".git"), { recursive: true }),
    ]);
    await writeFile(
      join(home, "auth.json"),
      JSON.stringify({
        auth_mode: "apikey",
        OPENAI_API_KEY: "synthetic-store-key",
      }),
      { mode: 0o600 },
    );
    const catalog = fileURLToPath(
      new URL("./fixtures/native-skill-model-catalog.json", import.meta.url),
    );
    await writeFile(
      join(home, "config.toml"),
      [
        'cli_auth_credentials_store="file"',
        `model_catalog_json=${JSON.stringify(catalog)}`,
        'openai_base_url="http://127.0.0.1:1/v1"',
        'chatgpt_base_url="http://127.0.0.1:1"',
        "[features]",
        "api_key_cyber_access_programs=false",
        "api_key_model_discovery=false",
      ].join("\n"),
    );
    await writeFile(
      join(invocation, ".codex", "config.toml"),
      'cli_auth_credentials_store="ephemeral"\nforced_login_method="api"\n[features]\napi_key_cyber_access_programs=true\n',
    );
    const trust = `projects={${JSON.stringify(projectTrustKey(invocation))}={trust_level="trusted"}}`;
    const launcher = join(root, "launcher.mjs");
    await writeFile(
      launcher,
      `
      import { spawnSync } from "node:child_process";
      const result = spawnSync(${JSON.stringify(resolveBundledCodexExecutable())}, [...process.argv.slice(2), "-c", ${JSON.stringify(trust)}], {stdio:"inherit"});
      process.exit(result.status ?? 1);
    `,
    );
    for (const store of ["auto", undefined]) {
      const program = await resolveScanCyberAccessProgram({
        command: { command: process.execPath, args: [launcher] },
        cwd: target,
        launcherCwd: invocation,
        environment: {
          PATH: process.env["PATH"] ?? "",
          CODEX_HOME: home,
          HOME: home,
          USERPROFILE: home,
        },
        config: store ? { cli_auth_credentials_store: store } : {},
        credentialType: store ? undefined : "api_key",
        model: "local-model",
        signal: new AbortController().signal,
      });
      expect(program).toBeUndefined();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test.each([
  ["known file key, forwarding off", "api_key", false, undefined],
  ["known file key, machine requires forwarding", "api_key", true, "standard"],
  ["unclassified login", undefined, false, "standard"],
  ["ChatGPT login", "chatgpt", false, "standard"],
] as const)(
  "a legacy launcher whose project store is overridden respects the target gate (%s)",
  async (_description, credentialType, forwarding, expected) => {
    const target = { features: { api_key_cyber_access_programs: forwarding } };
    const launcher = {
      forced_login_method: "api",
      cli_auth_credentials_store: "ephemeral",
    };
    const startup = {
      forced_login_method: "api",
      features: { api_key_cyber_access_programs: true },
    };
    const result = await probeWithWorkspacePolicy(
      {
        savedAccount: credentialType === "chatgpt" ? "chatgpt" : "apiKey",
        config: {
          ...target,
          model: "workspace-model",
          cli_auth_credentials_store: "file",
        },
        startupConfig: startup,
        neutralStartupConfig: startup,
        requirements: forwarding
          ? { featureRequirements: { api_key_cyber_access_programs: true } }
          : {},
        layers: [
          {
            name: { type: "project" },
            config: { features: { api_key_cyber_access_programs: false } },
          },
        ],
        startupLayers: [{ name: { type: "project" }, config: launcher }],
      },
      { cli_auth_credentials_store: "file" },
      { launcher: "legacy", storedLogin: true, credentialType },
    );
    expect(result.program).toBe(expected);
    expect(
      result.observations.some((entry) =>
        ["model/list", "account/read", "key-catalog", "catalog-http"].includes(
          entry.action,
        ),
      ),
    ).toBe(false);
  },
);

test.each([
  ["matching settings", {}, "daybreak_blue", false],
  [
    "different reasoning effort",
    { model_reasoning_effort: "high" },
    "daybreak_blue",
    false,
  ],
  [
    "different reasoning effort and a static catalog",
    { model_reasoning_effort: "high" },
    "daybreak_blue",
    true,
  ],
  [
    "a launcher-specific identity endpoint",
    { chatgpt_base_url: "https://startup.example.test" },
    "daybreak_blue",
    false,
  ],
  [
    "different catalog URLs",
    {
      model_providers: {
        openai: {
          model_catalog_url: "https://chatgpt.com/backend-api/codex/models",
        },
      },
    },
    "standard",
    false,
  ],
  [
    "a launcher-specific credential store",
    { cli_auth_credentials_store: "ephemeral" },
    "daybreak_blue",
    false,
  ],
  [
    "different Daybreak features",
    { features: { cli_daybreak: false } },
    "standard",
    false,
  ],
] as const)(
  "a stored login with %s on an older Codex",
  async (_scope, startupConfig, expected, staticCatalog) => {
    const result = await probeWithWorkspacePolicy(
      {
        config: { model: staticCatalog ? "gpt-test" : "workspace-model" },
        startupConfig,
      },
      staticCatalog ? { model_catalog_json: "scan-catalog.json" } : {},
      { launcher: "legacy", storedLogin: true },
    );
    expect(result.program).toBe(expected);
    const scopeReads = result.observations
      .filter(
        (entry) => entry.action === "config/read" && entry.home === result.home,
      )
      .map((entry) => entry.configCwd);
    expect(scopeReads.slice(0, 2)).toEqual([result.home, result.launcherCwd]);
    expect(
      result.observations.some((entry) => entry.action === "model/list"),
    ).toBe(expected === "daybreak_blue");
  },
);
