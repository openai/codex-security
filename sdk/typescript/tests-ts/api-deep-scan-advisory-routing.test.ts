import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, test } from "bun:test";
import type { TurnOptions } from "@openai/codex-sdk";
import { parse } from "smol-toml";
import type { ScanAuthentication, ScanOptions } from "../src/api.js";
import type { DirectDeepScanOptions } from "../src/deep-scan.js";
import { TestClient } from "./support/api-client.js";
import {
  preparedRuntime,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

interface RoutingCase {
  name: string;
  route: "parent" | "direct";
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
    route: "parent",
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
    route: "parent",
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
    route: "parent",
    authentication: { method: "stored_credentials", verified: false },
  },
  {
    name: "unclassified stored credentials",
    route: "parent",
    storedAuthMode: "unknown",
    authentication: { method: "stored_credentials", verified: false },
  },
  {
    name: "command authentication with an ambient API key",
    route: "parent",
    environment: { CODEX_API_KEY: "synthetic-unused-key" },
    commandAuth: true,
    authentication: { method: "command", verified: false },
  },
  {
    name: "selected API key with stored ChatGPT credentials",
    route: "direct",
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
    route: "direct",
    storedAuthMode,
    authentication: {
      method: "stored_credentials",
      credentialType: "api_key",
      verified: false,
    },
  })),
  {
    name: "selected Bedrock with stored ChatGPT credentials",
    route: "direct",
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
    route: "direct",
    provider: "amazon-bedrock",
    commandAuth: true,
    authentication: { method: "command", verified: false },
  },
  {
    name: "selected external provider API key",
    route: "direct",
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
  "Deep Scan preserves the advisory route for $name",
  async (scenario) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    await mkdir(scanDir, { mode: 0o700 });
    if (scenario.storedAuthMode !== undefined) {
      await writeFile(
        join(codexHome, "auth.json"),
        JSON.stringify({ auth_mode: scenario.storedAuthMode }),
      );
    }
    const environment = {
      ...scenario.environment,
      CODEX_HOME: codexHome,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      XDG_CACHE_HOME: join(root, "cache"),
    };
    const configPath = join(codexHome, "scan-runtime.toml");
    const deepScanConfigPath = join(codexHome, "deep-scan.toml");
    const modelProvider = scenario.provider ?? "openai";
    const onAuthentication = mock();
    const parentTurn = mock(async (prompt: string, options?: TurnOptions) => {
      expect(prompt).toContain("start_codex_security_deep_scan");
      expect(options?.cyberAccessProgram).toBe("daybreak_blue");
      throw new Error("parent route reached");
    });
    const directRun = mock(async function* (options: DirectDeepScanOptions) {
      expect(options.scanDir).toBe(scanDir);
      expect(options.repository).toBe(repository);
      throw new Error("direct route reached");
    });
    const client = new TestClient(
      {
        codexOverrides: {
          model: "gpt-6.1-sol",
          model_reasoning_effort: "high",
          model_provider: modelProvider,
          features: { api_key_cyber_access_programs: false },
          ...(scenario.commandAuth
            ? {
                model_providers: {
                  [modelProvider]: { auth: { command: "synthetic-auth" } },
                },
              }
            : {}),
        },
      },
      {
        ...scanRuntimeDependencies(codexHome, scanDir),
        environment,
        prepareRuntime: async () => ({
          ...preparedRuntime(codexHome),
          environment,
          configPath,
          deepScanConfigPath,
        }),
        // Exercise routing independently of the host's Bun capability fallback.
        supportsDirectDeepScan: async () => true,
        createCodex: (options) => {
          expect(options.config).toMatchObject({
            model: "gpt-6.1-sol",
            model_reasoning_effort: "high",
            model_provider: modelProvider,
            features: { api_key_cyber_access_programs: false },
          });
          expect(options.env).toMatchObject({
            XDG_CACHE_HOME: environment.XDG_CACHE_HOME,
            CODEX_SECURITY_CONFIG_PATH: configPath,
            CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: deepScanConfigPath,
          });
          return {
            startThread: (options) => {
              expect(options.workingDirectory).toBe(scanDir);
              return { id: null, runStreamed: parentTurn };
            },
          };
        },
        runDeepScan: directRun,
      },
    );
    try {
      await expect(
        client.run(repository, {
          mode: "deep",
          auth: scenario.auth,
          cyberAccessProgram: "daybreak_blue",
          onAuthentication,
        }),
      ).rejects.toThrow(`${scenario.route} route reached`);
      expect(onAuthentication).toHaveBeenCalledWith(scenario.authentication);
      expect(parentTurn).toHaveBeenCalledTimes(
        scenario.route === "parent" ? 1 : 0,
      );
      expect(directRun).toHaveBeenCalledTimes(
        scenario.route === "direct" ? 1 : 0,
      );
      expect(parse(await readFile(configPath, "utf8"))).toMatchObject({
        codex_security: { cyber_access_program: "daybreak_blue" },
        features: { api_key_cyber_access_programs: false },
      });
      expect(parse(await readFile(deepScanConfigPath, "utf8"))).toMatchObject({
        worker_runtime: {
          model_provider: modelProvider,
          features: { api_key_cyber_access_programs: false },
        },
      });
    } finally {
      await client.close();
    }
  },
);
