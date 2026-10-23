import { mkdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  scanPreflightCodexConfig,
  scanRuntimeCodexConfig,
} from "../src/api.js";
import {
  CHEAPERINFERENCE_CODEX_PROVIDER,
  FIREWORKS_CODEX_PROVIDER,
  OPENROUTER_CODEX_PROVIDER,
  scanModelProvider,
  writeCodexConfig,
  type JsonObject,
} from "../src/config.js";
import { TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-preflight-",
);
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
  [
    "Cheaper Inference",
    "cheaperinference",
    "CHEAPER_INFERENCE_API_KEY",
    "gpt-5.4",
    CHEAPERINFERENCE_CODEX_PROVIDER,
  ],
] as const;

afterEach(cleanup);

describe("CodexSecurity preflight configuration", () => {
  test("retains only native skill path and enabled settings for fallback workers", () => {
    const rootSkill = join(
      tmpdir(),
      "owned cache",
      "security-scan",
      "SKILL.md",
    );
    const selectedSkill = join(tmpdir(), "other skill", "SKILL.md");
    const input: JsonObject = {
      skills: {
        config: [
          { path: rootSkill, enabled: false, token: "SYNTHETIC_ENTRY_SECRET" },
        ],
        auth: "SYNTHETIC_ROOT_SECRET",
      },
      profile: "selected",
      profiles: {
        selected: {
          skills: {
            config: [
              {
                path: selectedSkill,
                enabled: true,
                extra: "SYNTHETIC_PROFILE_SECRET",
              },
            ],
            private: "SYNTHETIC_TABLE_SECRET",
          },
        },
      },
    };
    const before = structuredClone(input);
    expect(scanPreflightCodexConfig(input)).toEqual({
      skills: { config: [{ path: rootSkill, enabled: false }] },
      profile: "selected",
      profiles: {
        selected: {
          skills: { config: [{ path: selectedSkill, enabled: true }] },
        },
      },
    });
    expect(input).toEqual(before);
    expect(scanPreflightCodexConfig({ skills: { config: [] } })).toEqual({
      skills: { config: [] },
    });
  });

  test.each([
    ["model", { model: null }, true],
    ["reasoning effort", { model_reasoning_effort: null }, true],
    ["both", { model: null, model_reasoning_effort: null }, true],
    ["defaults", { model: null, model_reasoning_effort: null }, false],
  ] as const)(
    "inherits %s when selected profile settings are null",
    async (_name, profile, explicitRoot) => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      await mkdir(repository);
      await using client = new TestClient(
        {
          codexOverrides: {
            ...(explicitRoot
              ? { model: "gpt-5.6-terra", model_reasoning_effort: "low" }
              : {}),
            profile: "review",
            profiles: { review: profile },
          },
        },
        {
          environment: { CODEX_SECURITY_STATE_DIR: join(root, "state") },
          prepareRuntime: async () => {
            throw new Error("Local preflight must not start the runtime");
          },
        },
      );
      for (const mode of ["standard", "deep"] as const) {
        await expect(
          client.preflight(repository, { mode }),
        ).resolves.toMatchObject({
          mode,
          model: explicitRoot ? "gpt-5.6-terra" : "gpt-5.6-sol",
          reasoningEffort: explicitRoot ? "low" : "xhigh",
        });
      }
    },
  );

  test.each([
    ["standard", "openai.gpt-daybreak-blue-5.6-sol"],
    ["deep", "openai.gpt-daybreak-blue-5.6-sol"],
    ["standard", "openai.gpt-5.6-cyber"],
    ["deep", "openai.gpt-5.6-cyber"],
  ] as const)(
    "accepts a cost limit for a %s Bedrock %s scan without starting inference",
    async (mode, model) => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      await mkdir(repository);
      await using client = new TestClient(
        {
          codexOverrides: {
            model_provider: "amazon-bedrock",
            model,
          },
        },
        {
          environment: {
            AWS_PROFILE: "synthetic-bedrock-profile",
            AWS_REGION: "us-east-2",
            CODEX_SECURITY_STATE_DIR: join(root, "state"),
          },
          prepareRuntime: async () => {
            throw new Error("Local preflight must not start the runtime");
          },
        },
      );
      await expect(
        client.preflight(repository, { mode, maxCostUsd: 1 }),
      ).resolves.toMatchObject({
        mode,
        modelProvider: "amazon-bedrock",
        model,
        maxCostUsd: 1,
        authentication: {
          method: "aws_credentials",
          source: "AWS_PROFILE",
          verified: false,
        },
      });
    },
  );

  test("separates writable scans from read-only policy permissions", () => {
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
      model_provider: "openai",
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
        codex_security_policy: {
          filesystem: {
            [process.platform === "win32" ? ":root" : ":minimal"]: "read",
            ":workspace_roots": "read",
          },
          network: { enabled: false },
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

  test("denies model commands access to the persistent credential home", () => {
    const stateDirectory = join(tmpdir(), "codex-security-persistent-state");
    const credentialHome = join(stateDirectory, "codex-home");
    const config = scanRuntimeCodexConfig({}, credentialHome);

    expect(config["permissions"]).toEqual({
      codex_security_scan: {
        filesystem: {
          ":root": "read",
          ":workspace_roots": "write",
          [credentialHome]: { ".": "deny" },
        },
      },
      codex_security_policy: {
        filesystem: {
          [process.platform === "win32" ? ":root" : ":minimal"]: "read",
          ":workspace_roots": "read",
          [credentialHome]: { ".": "deny" },
        },
        network: { enabled: false },
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

  test.each([
    ["on-request", "never"],
    ["never", "on-request"],
  ] as const)(
    "lets root %s use the selected profile's %s approval policy",
    (rootPolicy, profilePolicy) => {
      const config = {
        approval_policy: rootPolicy,
        profile: "selected",
        profiles: {
          selected: { approval_policy: profilePolicy, model: "profile-model" },
          other: { approval_policy: rootPolicy },
        },
      };

      expect(scanRuntimeCodexConfig(config)).toMatchObject({
        approval_policy: profilePolicy,
        approvals_reviewer: "auto_review",
        model: "profile-model",
      });
      expect(config.approval_policy).toBe(rootPolicy);
      expect(config.profiles.selected.approval_policy).toBe(profilePolicy);
    },
  );

  test("resolves the selected profile without its execution and permission overrides", () => {
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
      model: "profile-model",
    });
    expect(hardened).not.toHaveProperty("profile");
    expect(hardened).not.toHaveProperty("profiles");
    expect(hardened["permissions"]).not.toHaveProperty("unsafe");
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
      openai_base_url:
        "https://synthetic-user:synthetic-password@gateway.example.test/v1?token=synthetic-root-token",
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
          openai_base_url:
            "https://synthetic-user:synthetic-password@profile.example.test/v1?token=synthetic-profile-token",
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

  test.each(EXTERNAL_PROVIDER_CASES)(
    "does not synthesize %s defaults over native provider settings",
    (_name, provider, _apiKey, model, providerConfig) => {
      const cases: JsonObject[] = [
        { base_url: "https://example.invalid/custom" },
        { env_key: "SYNTHETIC_PROVIDER_KEY" },
        { experimental_bearer_token: "synthetic-provider-token" },
        { auth: { command: "synthetic-auth", args: ["synthetic-account"] } },
        { requires_openai_auth: true },
        { http_headers: { Authorization: "Bearer synthetic-provider-header" } },
        { env_http_headers: { Authorization: "SYNTHETIC_PROVIDER_HEADER" } },
      ];
      for (const settings of cases) {
        const nativeProvider: JsonObject = { ...providerConfig, ...settings };
        if ("http_headers" in settings || "env_http_headers" in settings)
          delete nativeProvider["env_key"];
        const projected = scanPreflightCodexConfig(
          {
            profile: "selected",
            profiles: { selected: { model, model_provider: provider } },
            model_providers: {
              [provider]: nativeProvider,
            },
          },
          true,
        );
        expect(scanModelProvider(projected)).toBe(provider);
        expect(projected).not.toHaveProperty("model_providers");
        expect(projected["profiles"]).toEqual({
          selected: { model, model_provider: provider },
        });
      }
    },
  );

  test.each(["root", "profile", "merged"] as const)(
    "preserves safe Bedrock provider settings from %s in scan recipes",
    (source) => {
      const providers = {
        "amazon-bedrock": {
          aws: {
            region: "us-east-2",
            profile: "scan-profile",
            access_key_id: "synthetic-aws-access-key",
            secret_access_key: "synthetic-aws-secret-key",
            session_token: "synthetic-aws-session-token",
            bearer_token: "synthetic-bedrock-bearer",
          },
          api_key: "synthetic-provider-key",
        },
        openrouter: { api_key: "synthetic-unrelated-key" },
      };
      const selectedProviders = structuredClone(providers);
      if (source === "merged") {
        providers["amazon-bedrock"].aws.region = "us-west-2";
        delete (selectedProviders["amazon-bedrock"].aws as JsonObject)[
          "profile"
        ];
      }
      const config = scanPreflightCodexConfig({
        model_provider: "openai",
        profile: "bedrock",
        profiles: {
          bedrock: {
            model: "openai.gpt-5.6-luna",
            model_provider: "amazon-bedrock",
            ...(source === "root"
              ? {}
              : { model_providers: selectedProviders }),
          },
        },
        ...(source === "profile" ? {} : { model_providers: providers }),
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
            aws: { region: "us-east-2", profile: "scan-profile" },
          },
        },
      });
      expect(scanModelProvider(config)).toBe("amazon-bedrock");
      expect(JSON.stringify(config)).not.toContain("synthetic-");
    },
  );

  test("preserves cyber_access_program in sanitized scan configuration and profiles", () => {
    const config = scanPreflightCodexConfig({
      model: "gpt-5.6-sol",
      cyber_access_program: "daybreakBlue",
      profile: "daybreak-red",
      profiles: {
        "daybreak-red": {
          model: "gpt-5.6-sol",
          cyber_access_program: "daybreakRed",
        },
      },
    });

    expect(config).toEqual({
      model: "gpt-5.6-sol",
      cyber_access_program: "daybreakBlue",
      profile: "daybreak-red",
      profiles: {
        "daybreak-red": {
          model: "gpt-5.6-sol",
          cyber_access_program: "daybreakRed",
        },
      },
    });
  });

  test("filters invalid cyber_access_program values in preflight configuration", () => {
    const config = scanPreflightCodexConfig({
      model: "gpt-5.6-sol",
      cyber_access_program: "",
      profiles: {
        invalid: {
          model: "gpt-5.6-sol",
          cyber_access_program: 123 as unknown as string,
        },
      },
    });

    expect(config).toEqual({
      model: "gpt-5.6-sol",
      profiles: {
        invalid: {
          model: "gpt-5.6-sol",
        },
      },
    });
  });
});
