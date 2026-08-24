import { execFileSync, spawnSync } from "node:child_process";
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
import { afterEach, describe, expect, test } from "bun:test";
import {
  scanPreflightCodexConfig,
  scanRuntimeCodexConfig,
} from "../src/api.js";
import {
  FIREWORKS_CODEX_PROVIDER,
  OPENROUTER_CODEX_PROVIDER,
  scanModelProvider,
  writeCodexConfig,
  type JsonObject,
} from "../src/config.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];
const EXTERNAL_PROVIDER_CASES = [
  [
    "OpenRouter",
    "openrouter",
    "OPENROUTER_API_KEY",
    "anthropic/claude-sonnet-4.5",
    OPENROUTER_CODEX_PROVIDER,
  ],
  [
    "Fireworks AI",
    "fireworks",
    "FIREWORKS_API_KEY",
    "accounts/fireworks/models/qwen3-235b-a22b",
    FIREWORKS_CODEX_PROVIDER,
  ],
] as const;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-preflight-")),
  );
  temporaryDirectories.push(path);
  return path;
}

function runPreflight(
  config: string,
  profile: string,
  options: readonly string[] = [],
): { status: number | null; payload: Record<string, unknown> } {
  const interpreter =
    Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(interpreter).not.toBeNull();
  const result = spawnSync(
    interpreter!,
    [
      "-I",
      "-B",
      join(PLUGIN_ROOT, "scripts", "config_preflight.py"),
      "--profile",
      profile,
      "--config",
      config,
      ...options,
    ],
    { encoding: "utf8" },
  );
  expect(result.error).toBeUndefined();
  return {
    status: result.status,
    payload: JSON.parse(result.stdout) as Record<string, unknown>,
  };
}

describe("CodexSecurity preflight configuration", () => {
  test.skipIf(process.platform !== "win32")(
    "loads trusted project config through a Windows path alias",
    async () => {
      const root = await temporaryDirectory();
      const codexHome = join(root, "codex-home");
      const repository = join(root, "Repository");
      const projectConfig = join(repository, ".codex", "config.toml");
      await mkdir(join(repository, ".git"), { recursive: true });
      await mkdir(join(repository, ".codex"), { recursive: true });
      await mkdir(codexHome);
      await writeFile(projectConfig, "[features]\ngoals = true\n");
      await writeCodexConfig(join(codexHome, "config.toml"), {
        projects: {
          [repository.toUpperCase()]: { trust_level: "trusted" },
        },
      });

      const interpreter =
        process.env["PYTHON"] ??
        Bun.which("python3") ??
        Bun.which("python") ??
        Bun.which("py");
      expect(interpreter).not.toBeNull();
      const result = spawnSync(
        interpreter!,
        [
          "-I",
          "-B",
          join(PLUGIN_ROOT, "scripts", "config_preflight.py"),
          "--profile",
          "security_scan",
          "--cwd",
          repository,
        ],
        {
          encoding: "utf8",
          env: { PATH: process.env["PATH"], CODEX_HOME: codexHome },
        },
      );
      expect(result.error).toBeUndefined();
      const payload = JSON.parse(result.stdout) as Record<string, unknown>;
      expect(payload["config_resolution"]).toBe("cwd-discovery");
      expect(payload["config_discovery"]).toMatchObject({
        project_layers_loaded: true,
      });
      expect(payload["config_paths"]).toContain(projectConfig);
    },
  );

  test("ignores unrelated runtime settings for profiles without parent-runtime requirements", async () => {
    const root = await temporaryDirectory();
    const config = join(root, "empty.toml");
    await writeFile(config, "");
    const settings = [
      {
        args: [
          "--effective-config",
          "features.multi_agent_v2.enabled=true",
          "--effective-config",
          "agents.max_threads=8",
        ],
        context: { owner: "native", version: "v2", agent_max_threads: 8 },
        error: "agents.max_threads cannot be set",
      },
      {
        args: ["--effective-config", "multiagent_config.max_concurrency=8"],
        context: { owner: "unknown", version: "unknown" },
        error: "does not prove bridge ownership",
      },
    ];

    for (const { args, context, error } of settings) {
      for (const profile of ["deep_security_scan", "security_diff_scan"]) {
        const result = runPreflight(config, profile, args);
        expect(result.status).toBe(0);
        expect(result.payload).toMatchObject({
          multi_agent_context: context,
          profile,
          status: "ready",
        });
      }

      const required = runPreflight(config, "security_scan", args);
      expect(required.status).toBe(2);
      expect(required.payload["error"]).toContain(error);
    }
  });

  test("keeps custom profile requirements and explicit runtime ownership strict", async () => {
    const root = await temporaryDirectory();
    const config = join(root, "empty.toml");
    const registry = join(root, "registry.toml");
    await writeFile(config, "");
    await writeFile(
      registry,
      [
        "version = 1",
        "[capabilities.available]",
        'kind = "runtime"',
        'check = "available"',
        "[capabilities.mode]",
        'kind = "multi_agent_mode"',
        'owner = "native"',
        'version = "v2"',
        "[capabilities.bridge]",
        'kind = "config"',
        'path = "multiagent_config.max_concurrency"',
        'op = ">="',
        "value = 1",
        ...[
          ["root_bridge", "multiagent_config"],
          ["root_agents", "agents"],
          ["root_features", "features"],
          ["v2_feature", "features.multi_agent_v2"],
        ].flatMap(([capability, path]) => [
          `[capabilities.${capability}]`,
          'kind = "config"',
          `path = "${path}"`,
          'op = "=="',
          "value = {}",
        ]),
        ...[
          ["similar_v20", "features.multi_agent_v20"],
          ["similar_preview", "features.multi_agent_v2_preview"],
        ].flatMap(([capability, path]) => [
          `[capabilities.${capability}]`,
          'kind = "config"',
          `path = "${path}"`,
          'op = "=="',
          "value = true",
        ]),
        ...[
          "available",
          "mode",
          "bridge",
          "root_bridge",
          "root_agents",
          "root_features",
          "v2_feature",
          "similar_v20",
          "similar_preview",
        ].flatMap((profile) => [
          `[profiles.${profile}]`,
          `description = "${profile} capability"`,
          `[[profiles.${profile}.requirements]]`,
          `capability = "${profile}"`,
          'severity = "block"',
          'reason = "Required capability"',
        ]),
        "[profiles.root_patch]",
        'description = "Root runtime remediation"',
        "[[profiles.root_patch.requirements]]",
        'capability = "available"',
        'severity = "block"',
        'reason = "Required capability"',
        "[profiles.root_patch.remediation]",
        "[[profiles.root_patch.remediation.patches]]",
        'path = "multiagent_config"',
        "value = {}",
      ].join("\n"),
    );
    const conflictingNative = [
      "--registry",
      registry,
      "--runtime-check",
      "available=true",
      "--effective-config",
      "features.multi_agent_v2.enabled=true",
      "--effective-config",
      "agents.max_threads=8",
    ];

    expect(runPreflight(config, "available", conflictingNative)).toMatchObject({
      status: 0,
      payload: { status: "ready" },
    });
    for (const profile of ["mode", "root_agents", "root_features"]) {
      expect(runPreflight(config, profile, conflictingNative)).toMatchObject({
        status: 2,
        payload: { error: expect.stringContaining("agents.max_threads") },
      });
    }
    for (const profile of [
      "bridge",
      "root_bridge",
      "root_patch",
      "v2_feature",
    ]) {
      expect(
        runPreflight(config, profile, [
          "--registry",
          registry,
          "--runtime-check",
          "available=true",
          "--effective-config",
          "multiagent_config.max_concurrency=8",
        ]),
      ).toMatchObject({
        status: 2,
        payload: { error: expect.stringContaining("bridge ownership") },
      });
    }
    for (const [profile, feature] of [
      ["similar_v20", "features.multi_agent_v20"],
      ["similar_preview", "features.multi_agent_v2_preview"],
    ] as const) {
      expect(
        runPreflight(config, profile, [
          "--registry",
          registry,
          "--effective-config",
          `${feature}=true`,
          "--effective-config",
          "multiagent_config.max_concurrency=8",
        ]),
      ).toMatchObject({ status: 0, payload: { status: "ready" } });
    }

    for (const [version, additional] of [
      ["v2", []],
      ["v1", ["--effective-config", "features.multi_agent_v2.enabled=true"]],
    ] as const) {
      const conflictingNativeRuntime = runPreflight(
        config,
        "deep_security_scan",
        [
          "--multi-agent-runtime-owner",
          "native",
          "--multi-agent-runtime-version",
          version,
          "--multi-agent-runtime-provenance",
          "tool-surface",
          "--effective-config",
          "agents.max_threads=8",
          ...additional,
        ],
      );
      expect(conflictingNativeRuntime.status).toBe(2);
      expect(conflictingNativeRuntime.payload["error"]).toContain(
        "agents.max_threads",
      );
    }

    const forged = runPreflight(config, "deep_security_scan", [
      "--multi-agent-runtime-owner",
      "codex-bridge",
      "--multi-agent-runtime-provenance",
      "tool-surface",
    ]);
    expect(forged.status).toBe(2);
    expect(forged.payload["error"]).toContain("verified-bridge");

    const conflictingBridge = runPreflight(config, "deep_security_scan", [
      "--multi-agent-runtime-owner",
      "codex-bridge",
      "--multi-agent-runtime-version",
      "v2",
      "--multi-agent-runtime-provenance",
      "verified-bridge",
      "--multi-agent-session-cap",
      "9",
      "--effective-config",
      "multiagent_config.max_concurrency=8",
    ]);
    expect(conflictingBridge.status).toBe(2);
    expect(conflictingBridge.payload["error"]).toContain(
      "conflicting bridge concurrency facts",
    );
  });

  test("uses a root-read filesystem profile with only writable workspaces", () => {
    const original = {
      approval_policy: "on-request",
      approvals_reviewer: "user",
      sandbox_mode: "workspace-write",
      allow_login_shell: true,
      default_permissions: "unsafe",
      permissions: {
        existing: { filesystem: { ":root": "read" } },
        codex_security_scan: {
          extends: ":workspace",
          filesystem: { ":tmpdir": "write" },
        },
      },
    };

    expect(scanRuntimeCodexConfig(original)).toEqual({
      approval_policy: "on-request",
      approvals_reviewer: "auto_review",
      allow_login_shell: false,
      default_permissions: "codex_security_scan",
      permissions: {
        existing: { filesystem: { ":root": "read" } },
        codex_security_scan: {
          filesystem: {
            ":root": "read",
            ":workspace_roots": "write",
          },
        },
      },
    });
    expect(original).toMatchObject({
      approval_policy: "on-request",
      approvals_reviewer: "user",
      sandbox_mode: "workspace-write",
      allow_login_shell: true,
      default_permissions: "unsafe",
    });
  });

  test("keeps persistent credentials and their ancestry read-only", () => {
    const stateDirectory = join(tmpdir(), "codex-security-persistent-state");
    const credentialHome = join(stateDirectory, "codex-home");
    const config = scanRuntimeCodexConfig({}, credentialHome);

    expect(config["permissions"]).toEqual({
      codex_security_scan: {
        filesystem: {
          ":root": "read",
          ":workspace_roots": "write",
          [credentialHome]: "read",
        },
      },
    });
  });

  test("preserves an explicitly requested strict approval policy", () => {
    expect(
      scanRuntimeCodexConfig({
        approval_policy: "never",
        approvals_reviewer: "user",
      }),
    ).toMatchObject({
      approval_policy: "never",
      approvals_reviewer: "auto_review",
      default_permissions: "codex_security_scan",
    });
  });

  test("preserves a strict approval policy from the selected profile", () => {
    const config = {
      approval_policy: "on-request",
      profile: "strict",
      profiles: {
        strict: { approval_policy: "never", model: "profile-model" },
        other: { approval_policy: "on-request" },
      },
    };

    expect(scanRuntimeCodexConfig(config)).toMatchObject({
      approval_policy: "never",
      approvals_reviewer: "auto_review",
      profiles: { strict: { model: "profile-model" }, other: {} },
    });
    expect(config.profiles.strict.approval_policy).toBe("never");
  });

  test("removes execution and permission overrides from every configured profile", () => {
    const original = {
      profile: "selected",
      profiles: {
        selected: {
          model: "profile-model",
          approval_policy: "on-request",
          approvals_reviewer: "auto_review",
          default_permissions: "unsafe",
          permissions: { unsafe: { filesystem: { ":root": "write" } } },
          sandbox_mode: "danger-full-access",
        },
        other: {
          model_reasoning_effort: "high",
          approval_policy: "untrusted",
          approvals_reviewer: "guardian_subagent",
          default_permissions: "other-unsafe",
          permissions: { "other-unsafe": { filesystem: { ":root": "write" } } },
          sandbox_mode: "workspace-write",
        },
      },
    };

    const hardened = scanRuntimeCodexConfig(original);
    expect(hardened).toMatchObject({
      approval_policy: "on-request",
      approvals_reviewer: "auto_review",
      default_permissions: "codex_security_scan",
      profile: "selected",
    });
    expect(hardened["profiles"]).toEqual({
      selected: { model: "profile-model" },
      other: { model_reasoning_effort: "high" },
    });
    expect(original.profiles.selected).toMatchObject({
      approval_policy: "on-request",
      approvals_reviewer: "auto_review",
      default_permissions: "unsafe",
      permissions: { unsafe: { filesystem: { ":root": "write" } } },
      sandbox_mode: "danger-full-access",
    });
  });

  test("preserves configured Responses metadata without persisting scan attribution", () => {
    const stateDirectory = join(tmpdir(), "codex-security-persistent-state");
    const credentialHome = join(stateDirectory, "codex-home");
    const config = scanRuntimeCodexConfig(
      {
        responses_api_metadata: {
          request_trace: "preserve-configured-metadata",
        },
      },
      credentialHome,
    );

    expect(config["responses_api_metadata"]).toEqual({
      request_trace: "preserve-configured-metadata",
    });
  });

  test("projects only capability and trust metadata into the readable preflight config", async () => {
    const root = await temporaryDirectory();
    const configPath = join(root, "config-preflight.toml");
    const repository = join(root, "repository");
    const ordinaryProject = join(
      root,
      "settings-service-development-monkey-dataset",
    );
    await mkdir(repository);
    const sanitized = scanPreflightCodexConfig({
      model: "gpt-5.6-sol",
      model_reasoning_effort: "high",
      features: {
        plugins: true,
        goals: true,
        multi_agent_v2: { enabled: false, secret: "FEATURE_SECRET" },
        api_key: "FEATURE_KEY",
      },
      agents: { max_threads: 12, max_depth: 2, token: "AGENT_TOKEN" },
      profile: "review",
      profiles: {
        review: {
          model: "profile-model",
          features: { goals: true, secret: "PROFILE_SECRET" },
          agents: { max_threads: 4, token: "PROFILE_AGENT_TOKEN" },
          shell_environment_policy: { set: { SECRET: "PROFILE_ENV_SECRET" } },
        },
        secret_profile: { features: { goals: false } },
        "credential-prod": { features: { goals: false } },
        "mcp-server": { features: { goals: true } },
        "token-review": { features: { goals: false } },
        development: { features: { goals: true } },
        ["a".repeat(129)]: { features: { goals: false } },
      },
      project_root_markers: [
        ".git",
        ".workspace",
        ".env",
        "PASSWORD_VALUE",
        "settings.gradle",
        "a".repeat(257),
      ],
      projects: {
        [repository]: { trust_level: "trusted", token: "PROJECT_TOKEN" },
        [join(root, "secret-project")]: { trust_level: "trusted" },
        [join(root, "bearer-PRIVATE")]: { trust_level: "trusted" },
        [join(root, "mcp-server")]: { trust_level: "trusted" },
        [join(root, "token-review")]: { trust_level: "untrusted" },
        [ordinaryProject]: { trust_level: "untrusted" },
        relative: { trust_level: "trusted" },
        [join(root, "bad-trust")]: { trust_level: "PROJECT_SECRET" },
      },
      mcp_servers: { private: { bearer_token: "MCP_TOKEN" } },
      shell_environment_policy: { set: { SECRET: "SHELL_SECRET" } },
    });
    expect(sanitized).toEqual({
      model: "gpt-5.6-sol",
      model_reasoning_effort: "high",
      features: { goals: true, multi_agent_v2: { enabled: false } },
      agents: { max_threads: 12, max_depth: 2 },
      profile: "review",
      profiles: {
        review: {
          model: "profile-model",
          features: { goals: true },
          agents: { max_threads: 4 },
        },
        secret_profile: { features: { goals: false } },
        "credential-prod": { features: { goals: false } },
        "mcp-server": { features: { goals: true } },
        "token-review": { features: { goals: false } },
        development: { features: { goals: true } },
        ["a".repeat(129)]: { features: { goals: false } },
      },
      project_root_markers: [
        ".git",
        ".workspace",
        ".env",
        "PASSWORD_VALUE",
        "settings.gradle",
        "a".repeat(257),
      ],
      projects: {
        [repository]: { trust_level: "trusted" },
        [join(root, "secret-project")]: { trust_level: "trusted" },
        [join(root, "bearer-PRIVATE")]: { trust_level: "trusted" },
        [join(root, "mcp-server")]: { trust_level: "trusted" },
        [join(root, "token-review")]: { trust_level: "untrusted" },
        [ordinaryProject]: { trust_level: "untrusted" },
      },
    });
    await writeCodexConfig(configPath, sanitized);
    const serialized = await readFile(configPath, "utf8");
    for (const secret of [
      "FEATURE_SECRET",
      "FEATURE_KEY",
      "AGENT_TOKEN",
      "PROFILE_SECRET",
      "PROFILE_AGENT_TOKEN",
      "PROFILE_ENV_SECRET",
      "PROJECT_TOKEN",
      "MCP_TOKEN",
      "SHELL_SECRET",
    ]) {
      expect(serialized).not.toContain(secret);
    }
    const interpreter =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(interpreter).not.toBeNull();
    const output = execFileSync(
      interpreter!,
      [
        join(PLUGIN_ROOT, "scripts", "config_preflight.py"),
        "--skill",
        "security-scan",
        "--config",
        configPath,
        "--cwd",
        repository,
        "--multi-agent-runtime-owner",
        "native",
        "--multi-agent-runtime-version",
        "v1",
        "--multi-agent-runtime-provenance",
        "tool-surface",
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        "--effective-config",
        "features.goals=true",
      ],
      {
        env: { PATH: process.env["PATH"], CODEX_HOME: join(root, "denied") },
        encoding: "utf8",
      },
    );
    const preflight = JSON.parse(output) as Record<string, unknown>;
    expect(preflight["status"]).toBe("ready");
    expect(preflight["config_resolution"]).toBe("manual-layers");
    expect(preflight["config_paths"]).toEqual([configPath]);
    expect(preflight["config_profile"]).toBe("review");
    expect(JSON.stringify(preflight)).toContain("max_threads");
    expect(JSON.stringify(preflight)).toContain("12");

    const bridgeConfigPath = join(root, "bridge-preflight.toml");
    const bridge = scanPreflightCodexConfig({
      features: { goals: true },
      multiagent_config: {
        max_concurrency: 12,
        token: "BRIDGE_TOKEN",
      },
      mcp_servers: { private: { bearer_token: "BRIDGE_MCP_TOKEN" } },
    });
    expect(bridge).toEqual({
      features: { goals: true },
      multiagent_config: { max_concurrency: 12 },
    });
    await writeCodexConfig(bridgeConfigPath, bridge);
    const bridgeSerialized = await readFile(bridgeConfigPath, "utf8");
    expect(bridgeSerialized).not.toContain("BRIDGE_TOKEN");
    expect(bridgeSerialized).not.toContain("BRIDGE_MCP_TOKEN");
    const bridgeOutput = execFileSync(
      interpreter!,
      [
        join(PLUGIN_ROOT, "scripts", "config_preflight.py"),
        "--skill",
        "security-scan",
        "--config",
        bridgeConfigPath,
        "--cwd",
        repository,
        "--multi-agent-runtime-owner",
        "codex-bridge",
        "--multi-agent-runtime-version",
        "v2",
        "--multi-agent-runtime-provenance",
        "verified-bridge",
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        "--effective-config",
        "features.goals=true",
      ],
      {
        env: { PATH: process.env["PATH"], CODEX_HOME: join(root, "denied") },
        encoding: "utf8",
      },
    );
    const bridgePreflight = JSON.parse(bridgeOutput) as Record<string, unknown>;
    expect(bridgePreflight["status"]).toBe("ready");
    expect(bridgePreflight["config_resolution"]).toBe("manual-layers");
    expect(bridgePreflight["config_paths"]).toEqual([bridgeConfigPath]);
    expect(bridgePreflight["multi_agent_mode"]).toBe("bridge-v2");
    expect(JSON.stringify(bridgePreflight)).toContain(
      "multiagent_config.max_concurrency",
    );
    expect(JSON.stringify(bridgePreflight)).toContain("12");
    const largeConfig = scanPreflightCodexConfig({
      projects: Object.fromEntries(
        Array.from({ length: 256 }, (_, index) => [
          `/workspace/${index}/${"界".repeat(1300)}`,
          { trust_level: "trusted" },
        ]),
      ),
    });
    expect(Object.keys(largeConfig["projects"] as JsonObject)).toHaveLength(
      256,
    );
    const largeCapacity = scanPreflightCodexConfig({
      features: {
        multi_agent_v2: {
          unknown: true,
          max_concurrent_threads_per_session: 1_000_001,
        },
      },
    });
    expect(largeCapacity).toEqual({
      features: {
        multi_agent_v2: { max_concurrent_threads_per_session: 1_000_001 },
      },
    });
    await expect(
      writeCodexConfig(join(root, "large-capacity.toml"), largeCapacity),
    ).resolves.toBeUndefined();
  });

  test("keeps every valid profile, project, and root marker", () => {
    const activeProject = "/workspace/active";
    const profiles = Object.fromEntries([
      ...Array.from({ length: 256 }, (_, index) => [
        `profile_${index}`,
        { features: { goals: index % 2 === 0 } },
      ]),
      ["selected", { agents: { max_threads: 17 } }],
    ]);
    const projects = Object.fromEntries([
      ...Array.from({ length: 256 }, (_, index) => [
        `/workspace/project-${index}`,
        { trust_level: "untrusted" },
      ]),
      [activeProject, { trust_level: "trusted" }],
    ]);

    const prioritized = scanPreflightCodexConfig({
      profile: "selected",
      profiles,
      projects,
      project_root_markers: Array.from(
        { length: 65 },
        (_, index) => `.marker-${index}`,
      ),
    });

    expect(prioritized["profile"]).toBe("selected");
    expect(Object.keys(prioritized["profiles"] as JsonObject)).toHaveLength(
      257,
    );
    expect(prioritized["profiles"]).toMatchObject({
      selected: { agents: { max_threads: 17 } },
    });
    expect(Object.keys(prioritized["projects"] as JsonObject)).toHaveLength(
      257,
    );
    expect(prioritized["projects"]).toMatchObject({
      [activeProject]: { trust_level: "trusted" },
    });
    expect(prioritized["project_root_markers"]).toHaveLength(65);

    const validProfiles = Object.fromEntries(
      Array.from({ length: 256 }, (_, index) => [
        `valid_${index}`,
        { features: { goals: true } },
      ]),
    );
    const validProjects = Object.fromEntries(
      Array.from({ length: 256 }, (_, index) => [
        `/valid/project-${index}`,
        { trust_level: "trusted" },
      ]),
    );
    const afterInvalid = scanPreflightCodexConfig({
      profiles: {
        ...Object.fromEntries(
          Array.from({ length: 256 }, (_, index) => [
            `invalid.profile.${index}`,
            { features: { goals: false } },
          ]),
        ),
        ...validProfiles,
      },
      projects: {
        ...Object.fromEntries(
          Array.from({ length: 256 }, (_, index) => [
            `relative-${index}`,
            { trust_level: "trusted" },
          ]),
        ),
        ...validProjects,
      },
    });

    expect(Object.keys(afterInvalid["profiles"] as JsonObject)).toHaveLength(
      256,
    );
    expect(afterInvalid["profiles"]).toMatchObject({
      valid_255: { features: { goals: true } },
    });
    expect(Object.keys(afterInvalid["projects"] as JsonObject)).toHaveLength(
      256,
    );
    expect(afterInvalid["projects"]).toMatchObject({
      "/valid/project-255": { trust_level: "trusted" },
    });
  });

  test.each(EXTERNAL_PROVIDER_CASES)(
    "keeps the %s provider in sanitized scan configuration",
    (_name, provider, _apiKey, model, providerConfig) => {
      expect(
        scanPreflightCodexConfig({
          model,
          model_provider: provider,
          model_providers: {
            [provider]: providerConfig,
            private: { api_key: "synthetic-secret" },
          },
        }),
      ).toEqual({
        model,
        model_provider: provider,
        model_providers: { [provider]: providerConfig },
      });
    },
  );

  test.each(EXTERNAL_PROVIDER_CASES)(
    "preserves the selected %s profile provider in saved scan recipes",
    (_name, provider, _apiKey, model, providerConfig) => {
      const config = scanPreflightCodexConfig({
        model_provider: "openai",
        profile: "selected",
        profiles: { selected: { model, model_provider: provider } },
        model_providers: {
          [provider]: {
            ...providerConfig,
            api_key: "synthetic-provider-secret",
          },
          private: { bearer_token: "synthetic-unrelated-secret" },
        },
      });

      expect(config).toEqual({
        model_provider: "openai",
        profile: "selected",
        profiles: { selected: { model, model_provider: provider } },
        model_providers: { [provider]: providerConfig },
      });
      expect(scanModelProvider(config)).toBe(provider);
      expect(JSON.stringify(config)).not.toContain("synthetic-");
    },
  );

  test("preserves safe Bedrock provider settings in profile-selected scan recipes", () => {
    const config = scanPreflightCodexConfig({
      model_provider: "openai",
      profile: "bedrock",
      profiles: {
        bedrock: {
          model: "openai.gpt-5.6-luna",
          model_provider: "amazon-bedrock",
        },
      },
      model_providers: {
        "amazon-bedrock": {
          aws: {
            region: "us-east-2",
            profile: "security-prod",
            access_key_id: "synthetic-aws-access-key",
            secret_access_key: "synthetic-aws-secret-key",
            session_token: "synthetic-aws-session-token",
            bearer_token: "synthetic-bedrock-bearer",
          },
          api_key: "synthetic-provider-key",
        },
        openrouter: { api_key: "synthetic-unrelated-key" },
      },
    });

    expect(config).toEqual({
      model_provider: "openai",
      profile: "bedrock",
      profiles: {
        bedrock: {
          model: "openai.gpt-5.6-luna",
          model_provider: "amazon-bedrock",
        },
      },
      model_providers: {
        "amazon-bedrock": {
          aws: { region: "us-east-2", profile: "security-prod" },
        },
      },
    });
    expect(scanModelProvider(config)).toBe("amazon-bedrock");
    expect(JSON.stringify(config)).not.toContain("synthetic-");
  });
});
