import { spawnSync } from "node:child_process";
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

test("native startup receives provider metadata while credentials stay private", async () => {
  const home = await temporaryDirectory();
  const sharedConfig = 'approval_policy = "never"\n';
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
    {
      profile: "cloud.production",
      profiles: {
        "cloud.production": {
          ...config,
          model_providers: {
            omitted: null,
            "synthetic.gateway": {
              ...provider,
              requires_openai_auth: true,
              base_url: "https://provider.example.test/v1",
              env_key: "SYNTHETIC_API_KEY",
              auth: {
                command: "synthetic-auth",
                args: ["synthetic-command-secret"],
              },
            },
          },
        },
      },
    },
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
  expect(observed.args[0]).toBe("-c");
  expect(parse(observed.args[1])).toEqual({
    model_providers: {
      "synthetic.gateway": {
        name: "Synthetic",
        wire_api: "responses",
        requires_openai_auth: true,
      },
    },
  });
  expect(observed.args.slice(2)).toEqual(["plugin", "marketplace", "list"]);
  const login = new CodexLoginHandle(command, ["login"], environment, () => {});
  const completed = await login.wait();
  expect(completed.success).toBe(true);
  expect(JSON.parse(completed.stdout)).toEqual({
    ...observed,
    args: [...observed.args.slice(0, 2), "login"],
  });
});

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

function inspectHome(home: string) {
  const child = spawnSync(
    process.execPath,
    [
      "-e",
      `const fs = require("node:fs");
       const path = require("node:path");
       const home = process.argv[1];
       console.log(JSON.stringify({
         files: fs.readdirSync(home).sort(),
         auth: fs.existsSync(path.join(home, "auth.json"))
           ? fs.readFileSync(path.join(home, "auth.json"), "utf8") : null,
       }));`,
      home,
    ],
    { encoding: "utf8", windowsHide: true },
  );
  expect(child.status, child.stderr).toBe(0);
  return JSON.parse(child.stdout) as { files: string[]; auth: string | null };
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
        expect(inspectHome(path)).toEqual({
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
      expect(inspectHome(home)).toEqual({
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
          expect(inspectHome(path).files).toEqual([]);
          throw failure;
        },
      }),
    ).rejects.toMatchObject({ cause: failure });
    expect(inspectHome(home).files).toEqual([]);
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

test.each(["synthetic-tools", "synthetic.tools"])(
  "native overrides disable the inherited MCP server %s",
  async (name) => {
    const home = await temporaryDirectory();
    await writeFile(
      join(home, "config.toml"),
      `[mcp_servers.${JSON.stringify(name)}]\ncommand = "synthetic-never-launched"\nenabled = true\n`,
    );
    const { profileConfigOverrides } = await import(
      pathToFileURL(
        join(await bundledPluginRoot(), "scripts", "codex_profile.mjs"),
      ).href
    );
    const overrides = profileConfigOverrides({
      features: { plugins: false },
      mcp_servers: { [name]: { enabled: false } },
    });
    const result = await runCodexCommand(
      resolveCodexCommand({}),
      [
        ...overrides.flatMap((value: string) => ["-c", value]),
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
    expect(JSON.parse(result.stdout)).toMatchObject([
      {
        name,
        enabled: false,
        transport: { command: "synthetic-never-launched" },
      },
    ]);
  },
);
