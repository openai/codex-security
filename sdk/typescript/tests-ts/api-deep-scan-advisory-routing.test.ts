import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, test } from "bun:test";
import type { TurnOptions } from "@openai/codex-sdk";
import type { ScanAuthentication, ScanOptions } from "../src/api.js";
import { createDeepApiFixtures } from "./support/deep-api.js";

const { fixture, cleanup } = createDeepApiFixtures();
afterEach(cleanup);

interface RoutingCase {
  name: string;
  environment?: Record<string, string>;
  storedAuthMode?: string;
  auth?: ScanOptions["auth"];
  provider?: string;
  commandAuth?: boolean;
  authentication: ScanAuthentication;
}

const cases: RoutingCase[] = [
  {
    name: "ChatGPT with unrelated AWS credentials",
    environment: { AWS_PROFILE: "synthetic-unrelated-profile" },
    storedAuthMode: "chatgpt",
    authentication: {
      method: "stored_credentials",
      credentialType: "chatgpt",
      verified: false,
    },
  },
  {
    name: "selected ChatGPT with an ambient API key",
    environment: { CODEX_API_KEY: "synthetic-unused-key" },
    storedAuthMode: "chatgpt",
    auth: "chatgpt",
    authentication: {
      method: "stored_credentials",
      credentialType: "chatgpt",
      verified: false,
    },
  },
  {
    name: "stored credentials without auth.json",
    authentication: { method: "stored_credentials", verified: false },
  },
  {
    name: "unclassified stored credentials",
    storedAuthMode: "unknown",
    authentication: { method: "stored_credentials", verified: false },
  },
  {
    name: "command authentication with an ambient API key",
    environment: { CODEX_API_KEY: "synthetic-unused-key" },
    commandAuth: true,
    authentication: { method: "command", verified: false },
  },
  {
    name: "selected API key with stored ChatGPT credentials",
    environment: { CODEX_API_KEY: "synthetic-selected-key" },
    storedAuthMode: "chatgpt",
    authentication: {
      method: "api_key",
      source: "CODEX_API_KEY",
      verified: false,
    },
  },
  ...["apikey", "api_key"].map((storedAuthMode): RoutingCase => ({
    name: `stored ${storedAuthMode} credentials`,
    storedAuthMode,
    authentication: {
      method: "stored_credentials",
      credentialType: "api_key",
      verified: false,
    },
  })),
  {
    name: "selected Bedrock with stored ChatGPT credentials",
    provider: "amazon-bedrock",
    storedAuthMode: "chatgpt",
    authentication: {
      method: "aws_credentials",
      source: "default_credential_chain",
      verified: false,
    },
  },
  {
    name: "selected Bedrock with command authentication",
    provider: "amazon-bedrock",
    commandAuth: true,
    authentication: { method: "command", verified: false },
  },
  {
    name: "selected external provider API key",
    provider: "openrouter",
    environment: { OPENROUTER_API_KEY: "synthetic-provider-key" },
    storedAuthMode: "chatgpt",
    authentication: {
      method: "api_key",
      source: "OPENROUTER_API_KEY",
      verified: false,
    },
  },
];

test.each(cases)(
  "composed Deep Scan preserves authentication and access selection for $name",
  async (scenario) => {
    const h = await fixture();
    for (const key of Object.keys(h.environment)) {
      if (
        ![
          "PATH",
          "SystemRoot",
          "HOME",
          "CODEX_HOME",
          "CODEX_SECURITY_STATE_DIR",
          "SYNTHETIC_SETTING",
        ].includes(key)
      )
        delete h.environment[key];
    }
    Object.assign(h.environment, scenario.environment);
    if (scenario.storedAuthMode !== undefined)
      await writeFile(
        join(h.home, "auth.json"),
        JSON.stringify({ auth_mode: scenario.storedAuthMode }),
      );
    const provider = scenario.provider ?? "openai";
    const onAuthentication = mock();
    await using client = h.makeClient({
      model_provider: provider,
      features: { api_key_cyber_access_programs: false },
      ...(scenario.commandAuth
        ? {
            model_providers: {
              [provider]: { auth: { command: "synthetic-auth" } },
            },
          }
        : {}),
    });
    await client.run(h.repository, {
      ...h.options,
      workers: 1,
      maxDiscoveryRuns: 2,
      auth: scenario.auth,
      cyberAccessProgram: "daybreak_blue",
      onAuthentication,
    });
    expect(onAuthentication).toHaveBeenCalledWith(scenario.authentication);
    expect(h.launches.length).toBeGreaterThan(1);
    for (const launch of h.launches) {
      expect((launch.runOptions as TurnOptions).cyberAccessProgram).toBe(
        "daybreak_blue",
      );
      expect(launch.options.config).toMatchObject({
        model_provider: provider,
        features: { api_key_cyber_access_programs: false },
      });
    }
  },
);
