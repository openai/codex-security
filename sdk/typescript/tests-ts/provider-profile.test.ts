import { existsSync } from "node:fs";
import {
  chmod,
  mkdir,
  readFile,
  readdir,
  stat,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import type { CodexOptions } from "@openai/codex-sdk";
import { parse } from "smol-toml";
import {
  createProfileCodex,
  createProviderProfile,
  providerPreflightCommand,
} from "../src/provider-profile.js";
import { CodexLoginHandle } from "../src/auth.js";
import { structuredCodexConfig } from "../src/config.js";
import {
  bundledPluginRoot,
  resolveCodexCommand,
  runCodexCommand,
} from "../src/runtime.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-provider-profile-",
);
afterEach(cleanup);

const provider = {
  name: "Synthetic",
  wire_api: "responses",
  http_headers: { "X-Synthetic-Key": "synthetic-provider-secret" },
};
const config = {
  model_provider: "synthetic.gateway",
  model_providers: { "synthetic.gateway": provider },
};

const startupProvider = {
  ...provider,
  requires_openai_auth: true,
  base_url: "https://provider.example.test/v1",
  env_key: "SYNTHETIC_API_KEY",
  auth: {
    command: "synthetic-auth",
    args: ["synthetic-command-secret"],
  },
};
const startupProviders = {
  omitted: null,
  "synthetic.gateway": startupProvider,
};

test.each([
  [
    "explicit custom",
    { ...config, model_providers: startupProviders },
    "synthetic.gateway",
    true,
  ],
  [
    "selected profile",
    {
      model_provider: "openai",
      model_providers: startupProviders,
      profile: "cloud.production",
      profiles: { "cloud.production": { model_provider: "synthetic.gateway" } },
    },
    "synthetic.gateway",
    true,
  ],
  [
    "explicit OpenAI without definitions",
    { model_provider: "openai" },
    "openai",
    false,
  ],
  [
    "explicit OpenAI with empty definitions",
    { model_provider: "openai", model_providers: {} },
    "openai",
    false,
  ],
  ["inherited provider", {}, undefined, false],
  [
    "inherited provider with metadata",
    { model_providers: startupProviders },
    undefined,
    true,
  ],
  ["empty provider definitions", { model_providers: {} }, undefined, false],
  ["explicit empty selection", { model_provider: "" }, "", false],
] as const)(
  "native startup preserves %s selection and private credentials",
  async (_case, settings, selection, metadata) => {
    const home = await temporaryDirectory();
    const inherited = "synthetic.inherited";
    const sharedConfig = `approval_policy = "never"\ncli_auth_credentials_store = "file"\nmodel_provider = "${inherited}"\n${selection === undefined ? `[model_providers."${inherited}"]\nname = "Synthetic inherited"\nwire_api = "responses"\nrequires_openai_auth = false\n` : ""}`;
    await writeFile(join(home, "config.toml"), sharedConfig);
    const script = join(home, "native startup.mjs");
    await writeFile(
      script,
      `import { readFileSync } from "node:fs";
    import { join } from "node:path";
    console.log(JSON.stringify({
      args: process.argv.slice(2),
      home: process.env.CODEX_HOME,
      config: readFileSync(join(process.env.CODEX_HOME, "config.toml"), "utf8"),
    }));`,
    );
    const command = await providerPreflightCommand(
      { command: process.execPath, args: [script] },
      settings,
    );
    const environment = { ...process.env, CODEX_HOME: home };
    const result = await runCodexCommand(
      command,
      ["plugin", "marketplace", "list"],
      environment,
    );
    expect(result.success).toBe(true);
    const observed = JSON.parse(result.stdout);
    expect(observed.home).toBe(home);
    expect(observed.config).toBe(sharedConfig);
    const overrides = observed.args.slice(0, -3);
    const decoded: Record<string, unknown> = {};
    for (let index = 0; index < overrides.length; index += 2) {
      expect(overrides[index]).toBe("-c");
      Object.assign(decoded, parse(overrides[index + 1]));
    }
    expect(decoded).toEqual({
      ...(selection === undefined ? {} : { model_provider: selection }),
      ...(metadata
        ? {
            model_providers: {
              "synthetic.gateway": {
                name: "Synthetic",
                wire_api: "responses",
                requires_openai_auth: true,
              },
            },
          }
        : {}),
    });
    expect(observed.args.slice(-3)).toEqual(["plugin", "marketplace", "list"]);
    for (const marker of [
      "synthetic-provider-secret",
      "synthetic-command-secret",
      "SYNTHETIC_API_KEY",
      "provider.example.test",
    ]) {
      expect(JSON.stringify(observed.args)).not.toContain(marker);
    }
    const login = new CodexLoginHandle(
      command,
      ["login"],
      environment,
      () => {},
    );
    const completed = await login.wait();
    expect(completed.success).toBe(true);
    expect(JSON.parse(completed.stdout)).toEqual({
      ...observed,
      args: [...overrides, "login"],
    });

    const prefix = [
      "-c",
      "features.api_key_model_discovery=false",
      "-c",
      "features.plugins=false",
    ];
    const native = await providerPreflightCommand(
      { ...resolveCodexCommand({}), args: prefix },
      settings,
    );
    expect(native.args?.slice(0, prefix.length)).toEqual(prefix);
    const { readDeepScanRuntimeConfig } = await import(
      pathToFileURL(
        join(
          await bundledPluginRoot(),
          "mcp",
          "permission-profile-preflight.mjs",
        ),
      ).href
    );
    const read = () =>
      readDeepScanRuntimeConfig({
        codexPath: native.command,
        commandArgs: native.args,
        cwd: home,
        configOverrides: [],
        env: {
          PATH: process.env["PATH"] ?? "",
          ...(process.env["SystemRoot"] === undefined
            ? {}
            : { SystemRoot: process.env["SystemRoot"] }),
          ...(process.env["TMPDIR"] === undefined
            ? {}
            : { TMPDIR: process.env["TMPDIR"] }),
          HOME: home,
          CODEX_HOME: home,
        },
        signal: new AbortController().signal,
        context: "helper",
      });
    if (selection === "") {
      await expect(read()).rejects.toThrow("Model provider `` not found");
    } else {
      const effective = await read();
      expect(effective.model_provider).toBe(selection ?? inherited);
    }
    expect(await readFile(join(home, "config.toml"), "utf8")).toBe(
      sharedConfig,
    );
  },
);

test("native profile turns omit optional null fields and retain array errors", async () => {
  const home = await temporaryDirectory();
  const script = join(home, "profile child.mjs");
  await writeFile(
    script,
    `for await (const chunk of process.stdin) {}
    console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-thread" }));
    console.log(JSON.stringify({ type: "item.completed", item: {
      type: "agent_message", id: "answer", text: JSON.stringify(process.argv.slice(1)),
    } }));
    console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 1, output_tokens: 1 } }));
    process.exit(0);`,
  );
  const node = Bun.which("node");
  expect(node).not.toBeNull();
  const options = {
    codexPathOverride: node!,
    env: {
      ...process.env,
      CODEX_HOME: home,
      NODE_OPTIONS: `--import=${pathToFileURL(script).href}`,
    },
  };
  const codex = await createProfileCodex(
    {
      ...options,
      config: structuredCodexConfig({
        model_provider: "synthetic.gateway",
        service_tier: "fast",
        profile: "review",
        profiles: { review: { model_provider: null, service_tier: null } },
        features: { plugins: false, optional: null },
        nested: [{ enabled: true, optional: null }],
      }) as CodexOptions["config"],
    },
    "synthetic-profile",
  );
  for (const resumed of [false, true]) {
    const thread = resumed
      ? codex.resumeThread("synthetic-thread")
      : codex.startThread();
    const result = await thread.run("synthetic prompt");
    const args: string[] = JSON.parse(result.finalResponse);
    const overrides = args.flatMap((arg, index) =>
      arg === "--config" ? [args[index + 1]!] : [],
    );
    expect(parse(overrides.join("\n"))).toEqual({
      model_provider: "synthetic.gateway",
      service_tier: "fast",
      features: { plugins: false },
      nested: [{ enabled: true }],
    });
    expect(args.includes("resume")).toBe(resumed);
  }
  const invalid = await createProfileCodex(
    {
      ...options,
      config: { invalid: [null] } as unknown as CodexOptions["config"],
    },
    "synthetic-profile",
  );
  await expect(invalid.startThread().run("synthetic prompt")).rejects.toThrow(
    "Codex config overrides must contain finite TOML values",
  );
});

test("private profiles retain providers for native required and inherited selection", async () => {
  const home = await temporaryDirectory();
  const definitions = {
    "synthetic.selected": { name: "Synthetic selected", wire_api: "responses" },
    "synthetic.required": { name: "Synthetic required", wire_api: "responses" },
    "amazon-bedrock": {
      aws: { region: "us-east-1" },
      http_headers: { "X-Synthetic-Key": "synthetic-inherited-header" },
    },
  };
  const profile = await createProviderProfile(home, {
    model_provider: "synthetic.selected",
    model_providers: definitions,
  });
  try {
    for (const selection of ["synthetic.required", "amazon-bedrock"]) {
      // Managed requirements can override the initial selection. Exercise the
      // same native file lookup without writing platform-specific system policy.
      const result = await runCodexCommand(
        resolveCodexCommand({}),
        [
          "--profile",
          profile.name,
          "-c",
          `model_provider=${JSON.stringify(selection)}`,
          "mcp",
          "list",
          "--json",
        ],
        {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          CODEX_HOME: home,
        },
      );
      expect(result.success, result.stderr).toBe(true);
      expect(JSON.parse(result.stdout)).toEqual([]);
    }
    expect(parse(await readFile(profile.path, "utf8"))).toEqual({
      model_providers: definitions,
    });
  } finally {
    await profile.cleanup();
  }
});

async function inspectHome(home: string) {
  const auth = join(home, "auth.json");
  return {
    files: (await readdir(home)).sort(),
    auth: existsSync(auth) ? await readFile(auth, "utf8") : null,
  };
}

test.each(["existing", "new"])(
  "secures the %s Windows credential home before writing a provider profile",
  async (kind) => {
    const root = await temporaryDirectory();
    const home = join(root, "credential home");
    const auth = '{"api_key":"synthetic-existing-auth"}\n';
    const originalConfig = 'model = "synthetic-model"\n';
    if (kind === "existing") {
      await mkdir(home);
      await writeFile(join(home, "auth.json"), auth);
      await writeFile(join(home, "config.toml"), originalConfig);
    }
    let secured = false;
    const profile = await createProviderProfile(home, config, {
      platform: "win32",
      async secureWindowsHome(path) {
        expect(path).toBe(home);
        expect(await inspectHome(path)).toEqual({
          files: kind === "existing" ? ["auth.json", "config.toml"] : [],
          auth: kind === "existing" ? auth : null,
        });
        secured = true;
      },
    });
    try {
      expect(secured).toBe(true);
      expect(profile.path).toBe(join(home, `${profile.name}.config.toml`));
      expect(parse(await readFile(profile.path, "utf8"))).toEqual({
        model_providers: { "synthetic.gateway": provider },
      });
      expect(await inspectHome(home)).toEqual({
        files: [
          ...(kind === "existing" ? ["auth.json", "config.toml"] : []),
          `${profile.name}.config.toml`,
        ].sort(),
        auth: kind === "existing" ? auth : null,
      });
      if (kind === "existing") {
        expect(await readFile(join(home, "config.toml"), "utf8")).toBe(
          originalConfig,
        );
      }
    } finally {
      await profile.cleanup();
    }
    expect(
      (await readdir(home)).some((name) => name.startsWith("codex_security_")),
    ).toBe(false);
  },
);

test.each(["rejected", "aborted"])(
  "leaves no provider file when Windows credential protection is %s",
  async (kind) => {
    const root = await temporaryDirectory();
    const home = join(root, "credential home");
    const failure = new Error("synthetic ACL failure");
    if (kind === "aborted") failure.name = "AbortError";
    await expect(
      createProviderProfile(home, config, {
        platform: "win32",
        async secureWindowsHome(path) {
          expect((await inspectHome(path)).files).toEqual([]);
          throw failure;
        },
      }),
    ).rejects.toMatchObject({ cause: failure });
    expect((await inspectHome(home)).files).toEqual([]);
  },
);

(process.platform === "win32" ? test.skip : test)(
  "keeps provider files private in an existing readable POSIX home",
  async () => {
    const home = await temporaryDirectory();
    await chmod(home, 0o755);
    const profile = await createProviderProfile(home, config);
    try {
      expect((await stat(home)).mode & 0o777).toBe(0o755);
      expect((await stat(profile.path)).mode & 0o777).toBe(0o600);
      expect(parse(await readFile(profile.path, "utf8"))).toEqual({
        model_providers: { "synthetic.gateway": provider },
      });
    } finally {
      await profile.cleanup();
    }
  },
);

test.each([
  ["synthetic-tools", false],
  ["synthetic.tools", false],
  ["synthetic.tools", true],
] as const)(
  "native overrides disable inherited MCP server %s (private profile: %j)",
  async (name, privateProfile) => {
    const home = await temporaryDirectory();
    const sharedConfig = `[mcp_servers.${JSON.stringify(name)}]\ncommand = "synthetic-never-launched"\nenabled = true\n`;
    await writeFile(join(home, "config.toml"), sharedConfig);
    const profile = privateProfile
      ? await createProviderProfile(home, config)
      : undefined;
    const { profileConfigOverrides } = await import(
      pathToFileURL(
        join(await bundledPluginRoot(), "scripts", "codex_profile.mjs"),
      ).href
    );
    const command = resolveCodexCommand({});
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      CODEX_HOME: home,
    };
    try {
      const inherited = await runCodexCommand(
        command,
        ["mcp", "list", "--json"],
        environment,
      );
      expect(inherited.success, inherited.stderr).toBe(true);
      expect(JSON.parse(inherited.stdout)).toMatchObject([
        { name, enabled: true },
      ]);
      const overrides = profileConfigOverrides({
        features: { plugins: false },
        mcp_servers: { [name]: { enabled: false } },
      });
      const result = await runCodexCommand(
        command,
        [
          ...(profile ? ["--profile", profile.name] : []),
          ...overrides.flatMap((value: string) => ["-c", value]),
          "mcp",
          "list",
          "--json",
        ],
        environment,
      );
      expect(result.success, result.stderr).toBe(true);
      expect(JSON.parse(result.stdout)).toMatchObject([
        {
          name,
          enabled: false,
          transport: { command: "synthetic-never-launched" },
        },
      ]);
      expect(await readFile(join(home, "config.toml"), "utf8")).toBe(
        sharedConfig,
      );
    } finally {
      await profile?.cleanup();
    }
  },
);
