import { realpath, rm } from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { resolveCodexProfile, type JsonObject } from "../src/config.js";
import { resolveSkillAuthentication } from "../src/skill-authentication.js";
import { runProviderSkill } from "./support/cli-provider-authentication.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

const commandSources = [
  ["validate", "override"],
  ["patch", "override"],
  ["verify-fix", "override"],
  ["patch", "ambient"],
  ["verify-fix", "ambient"],
  ["patch", "profile"],
  ["verify-fix", "profile"],
] as const;

function providerSettings(
  source: "override" | "ambient" | "profile",
  requiresOpenAiAuth: boolean | undefined,
  credential: "env_key" | "bearer",
) {
  const configuredEnvKey =
    process.platform === "win32" ? "gateway_api_key" : "GATEWAY_API_KEY";
  const environment = { GATEWAY_API_KEY: "SYNTHETIC_GATEWAY_KEY" };
  const providerConfig = {
    name: "Synthetic gateway",
    base_url: "https://gateway.example.test/v1",
    wire_api: "responses",
    ...(requiresOpenAiAuth === undefined
      ? {}
      : { requires_openai_auth: requiresOpenAiAuth }),
  };
  const settings = [
    ...Object.entries(providerConfig).map(
      ([key, value]) => `${key}=${JSON.stringify(value)}`,
    ),
    ...(credential === "env_key"
      ? [`env_key=${JSON.stringify(configuredEnvKey)}`]
      : []),
    ...(credential === "bearer" || requiresOpenAiAuth === false
      ? ['experimental_bearer_token="SYNTHETIC_FALLBACK_KEY"']
      : []),
  ];
  return {
    providerConfig,
    environment,
    overrides:
      source === "override"
        ? [
            'model_provider="gateway"',
            ...settings.map((setting) => `model_providers.gateway.${setting}`),
          ]
        : [],
    ...(source === "override"
      ? {}
      : {
          ambientConfig: [
            ...(source === "profile"
              ? ['profile="gateway-profile"', "[profiles.gateway-profile]"]
              : []),
            'model_provider="gateway"',
            "[model_providers.gateway]",
            ...settings,
          ].join("\n"),
        }),
  };
}

describe("skill authentication configuration", () => {
  test("a Standard Compute skill requires an explicit provider key and rejects ChatGPT", () => {
    const options = {
      command: "patch" as const,
      modelProvider: "standardcompute",
    };
    const environment = {
      STANDARDCOMPUTE_API_KEY: "synthetic-key",
      OPENAI_API_KEY: "unused-account",
    };
    const config = {
      model_providers: {
        standardcompute: { env_key: "STANDARDCOMPUTE_API_KEY" },
      },
    };
    const skill = resolveSkillAuthentication(
      { ...options, auth: "auto" },
      environment,
      config,
    );
    expect(skill.environment).toEqual({
      STANDARDCOMPUTE_API_KEY: "synthetic-key",
    });
    expect(skill.requiresOpenAiAuth).toBe(false);
    expect(() =>
      resolveSkillAuthentication(
        { ...options, auth: "chatgpt" },
        environment,
        config,
      ),
    ).toThrow(/ChatGPT/);
  });

  test("custom ChatGPT gateways and ignored OpenAI tables cannot forward the Standard Compute key", () => {
    for (const provider of ["gateway", "openai"]) {
      const skill = resolveSkillAuthentication(
        { command: "patch", auth: provider === "gateway" ? "chatgpt" : "auto" },
        { STANDARDCOMPUTE_API_KEY: "unused" },
        {
          model_provider: provider,
          model_providers: {
            [provider]: { env_key: "STANDARDCOMPUTE_API_KEY" },
          },
        },
      );
      expect(skill.requiresOpenAiAuth).toBe(true);
      expect(skill.environment).not.toHaveProperty("STANDARDCOMPUTE_API_KEY");
    }
  });

  test.each(
    (["override", "ambient", "profile"] as const).flatMap((source) =>
      [true, false, undefined].flatMap((requiresOpenAiAuth) =>
        (["env_key", "bearer"] as const).map(
          (credential) => [source, requiresOpenAiAuth, credential] as const,
        ),
      ),
    ),
  )(
    "explicit ChatGPT auth removes the custom provider key from %s config (requires OpenAI: %p, credential: %s)",
    (source, requiresOpenAiAuth, credential) => {
      const { providerConfig, environment, overrides, ambientConfig } =
        providerSettings(source, requiresOpenAiAuth, credential);
      const options = {
        command: "patch" as const,
        auth: "chatgpt" as const,
        codexOverrides: parseToml(overrides.join("\n")) as JsonObject,
      };
      const ambient = resolveCodexProfile(
        parseToml(ambientConfig ?? "") as JsonObject,
      );
      const originalOptions = structuredClone(options);
      const originalAmbient = structuredClone(ambient);
      const result = resolveSkillAuthentication(options, environment, ambient);

      expect(result.authentication).toEqual({
        method: "stored_credentials",
        verified: false,
      });
      expect(result.requiresOpenAiAuth).toBe(true);
      expect(result.provider).toBe("gateway");
      expect(result.environment).toEqual(
        credential === "env_key" ? {} : environment,
      );
      expect(result.providerConfiguration).toEqual({
        ...providerConfig,
        requires_openai_auth: true,
      });
      expect(parseToml(result.configOverrides.join("\n"))).toEqual(
        source === "override"
          ? {
              model_providers: {
                gateway: { ...providerConfig, requires_openai_auth: true },
              },
            }
          : {},
      );
      expect(options).toEqual(originalOptions);
      expect(ambient).toEqual(originalAmbient);
      expect(environment).toEqual({ GATEWAY_API_KEY: "SYNTHETIC_GATEWAY_KEY" });
    },
  );
});

describe("skill authentication at the subprocess boundary", () => {
  let stateDirectory: string;

  beforeEach(async () => {
    stateDirectory = await realpath(
      await temporaryDirectory("codex-security-cli-authentication-"),
    );
  });

  afterEach(async () => {
    await rm(stateDirectory, { recursive: true, force: true });
  });

  // Each command/config source still launches Codex with stored credentials.
  // Include both native credential forms together to verify neither leaks.
  test.each(commandSources)(
    "%s applies ChatGPT authentication to %s configuration in the child",
    async (command, source) => {
      const { providerConfig, ...settings } = providerSettings(
        source,
        false,
        "env_key",
      );
      const result = await runProviderSkill(stateDirectory, {
        ...settings,
        command,
        auth: "chatgpt",
        storedCredentials: true,
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.launch.environment).toEqual({});
      expect(parseToml(result.launch.config)["model_providers"]).toEqual({
        gateway: { ...providerConfig, requires_openai_auth: true },
      });
      const providerOverride = result.launch.args.findLast((arg: string) =>
        arg.startsWith("model_providers="),
      );
      if (source === "override") {
        expect(parseToml(providerOverride)["model_providers"]).toEqual({
          gateway: { ...providerConfig, requires_openai_auth: true },
        });
      } else {
        expect(providerOverride).toBeUndefined();
      }
      expect(result.requests.map((request) => request.method)).not.toContain(
        "account/login/start",
      );
      expect(settings.environment.GATEWAY_API_KEY).toBe(
        "SYNTHETIC_GATEWAY_KEY",
      );
    },
  );
});
