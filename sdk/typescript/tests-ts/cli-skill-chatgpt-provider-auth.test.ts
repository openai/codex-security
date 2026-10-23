import { realpath, rm } from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { runProviderSkill } from "./support/cli-provider-authentication.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

let stateDirectory: string;

beforeEach(async () => {
  stateDirectory = await realpath(
    await temporaryDirectory("codex-security-cli-authentication-"),
  );
});

afterEach(async () => {
  await rm(stateDirectory, { recursive: true, force: true });
});

describe("skill authentication", () => {
  test.each(
    (
      [
        ["validate", "override"],
        ["patch", "override"],
        ["verify-fix", "override"],
        ["patch", "ambient"],
        ["verify-fix", "ambient"],
        ["patch", "profile"],
        ["verify-fix", "profile"],
      ] as const
    ).flatMap(([command, source]) =>
      [true, false, undefined].flatMap((requiresOpenAiAuth) =>
        ["env_key", "bearer"].map(
          (credential) =>
            [command, source, requiresOpenAiAuth, credential] as const,
        ),
      ),
    ),
  )(
    "%s removes the custom provider key and %s config for explicit ChatGPT auth (requires OpenAI: %p, credential: %s)",
    async (command, source, requiresOpenAiAuth, credential) => {
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
      const providerSettings = [
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
      const result = await runProviderSkill(stateDirectory, {
        command,
        auth: "chatgpt",
        overrides:
          source === "override"
            ? [
                'model_provider="gateway"',
                ...providerSettings.map(
                  (setting) => `model_providers.gateway.${setting}`,
                ),
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
                ...providerSettings,
              ].join("\n"),
            }),
        environment,
        storedCredentials: true,
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.launch.environment).toEqual(
        credential === "env_key" ? {} : environment,
      );
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
      expect(environment.GATEWAY_API_KEY).toBe("SYNTHETIC_GATEWAY_KEY");
    },
  );
});
