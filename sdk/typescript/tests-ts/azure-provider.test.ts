import { afterEach, expect, test } from "bun:test";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { scanAuthentication, selectedScanEnvironment } from "../src/api.js";
import { mergedCodexConfig } from "../src/config.js";
import { TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

const deployment = { model: "incident-review", model_provider: "azure" };
const resource = "https://fixture.openai.azure.com";

test.each([
  "http://fixture.example",
  "https://fixture.example/openai/deployments/legacy",
  "https://synthetic-sensitive@fixture.example",
  "https://fixture.example/?signature=synthetic-sensitive",
  "https://fixture.example/#synthetic-sensitive",
  "invalid-synthetic-sensitive",
])(
  "rejects invalid Azure endpoints without exposing their contents: %s",
  async (value) => {
    const fromEnvironment = mergedCodexConfig(
      { codexOverrides: deployment },
      undefined,
      { AZURE_OPENAI_ENDPOINT: value },
    );
    const fromOverride = mergedCodexConfig(
      {
        codexOverrides: {
          ...deployment,
          model_providers: { azure: { base_url: value } },
        },
      },
      undefined,
      { AZURE_OPENAI_ENDPOINT: resource },
    );
    for (const result of await Promise.allSettled([
      fromEnvironment,
      fromOverride,
    ])) {
      expect(result.status).toBe("rejected");
      if (result.status === "rejected") {
        expect(String(result.reason)).toMatch(/Azure/u);
        expect(String(result.reason)).not.toContain(value);
        expect(String(result.reason)).not.toContain("synthetic-sensitive");
      }
    }
  },
);

test("Azure metadata headers preserve the default key while authentication headers stand alone", async () => {
  for (const [headers, environment, expectedKey] of [
    [
      { http_headers: { "X-Request-ID": "synthetic-request" } },
      { AZURE_OPENAI_API_KEY: "synthetic-default" },
      "AZURE_OPENAI_API_KEY",
    ],
    [
      { env_http_headers: { "X-Request-ID": "REQUEST_ID" } },
      {
        AZURE_OPENAI_API_KEY: "synthetic-default",
        REQUEST_ID: "synthetic-request",
      },
      "AZURE_OPENAI_API_KEY",
    ],
    [
      { http_headers: { "API-Key": "synthetic-private" } },
      { AZURE_OPENAI_API_KEY: "synthetic-unrelated" },
      undefined,
    ],
    [
      { env_http_headers: { "X-Gateway-Proof": "GATEWAY_API_KEY" } },
      { GATEWAY_API_KEY: "synthetic-gateway" },
      undefined,
    ],
  ] as const) {
    const config = await mergedCodexConfig(
      {
        codexOverrides: {
          ...deployment,
          model_providers: { azure: { base_url: resource, ...headers } },
        },
      },
      undefined,
      environment,
    );
    expect(config).toMatchObject({ model_providers: { azure: headers } });
    const providers = config["model_providers"] as Record<
      string,
      Record<string, unknown>
    >;
    expect(providers["azure"]?.["env_key"]).toBe(expectedKey);
  }
});

test("Azure credentials stay isolated from other providers", () => {
  const keys = {
    AZURE_OPENAI_API_KEY: "synthetic-key",
    OPENAI_API_KEY: "other",
    CODEX_API_KEY: "other",
    FIREWORKS_API_KEY: "other",
    OPENROUTER_API_KEY: "other",
    CHEAPER_INFERENCE_API_KEY: "other",
  };
  expect(selectedScanEnvironment(keys, "auto", "azure")).toEqual({
    AZURE_OPENAI_API_KEY: keys.AZURE_OPENAI_API_KEY,
  });
  expect(
    selectedScanEnvironment(keys, "auto", "openrouter"),
  ).not.toHaveProperty("AZURE_OPENAI_API_KEY");
  expect(
    selectedScanEnvironment(keys, "chatgpt", "gateway", undefined, {
      model_provider: "gateway",
      model_providers: {
        gateway: { env_http_headers: { "x-api-key": "AZURE_OPENAI_API_KEY" } },
      },
    }),
  ).not.toHaveProperty("AZURE_OPENAI_API_KEY");
  expect(() =>
    scanAuthentication({ OPENAI_API_KEY: "other" }, "auto", "azure"),
  ).toThrow(/AZURE_OPENAI_API_KEY/u);
});

test.each([
  "experimental_bearer_token",
  "http_headers",
  "env_http_headers",
] as const)(
  "Azure %s preflight uses the private provider table",
  async (source) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repo");
    await mkdir(repository);
    await using client = new TestClient(
      {
        codexOverrides: {
          ...deployment,
          model_providers: {
            azure: {
              base_url: resource,
              [source]: {
                experimental_bearer_token: "synthetic-private-bearer",
                http_headers: { "api-key": "synthetic-private-bearer" },
                env_http_headers: { Authorization: "NATIVE_DEPLOYMENT_KEY" },
              }[source],
            },
          },
        },
      },
      {
        environment: {
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          OPENAI_API_KEY: "synthetic-unrelated",
          NATIVE_DEPLOYMENT_KEY: "synthetic-private-bearer",
        },
      },
    );
    const preflight = await client.preflight(repository, { auth: "api-key" });
    expect(preflight.authentication).toEqual({
      method: "api_key",
      source,
      verified: false,
    });
    expect(JSON.stringify(preflight)).not.toContain("synthetic-private-bearer");
  },
);

test.each(["incident-review", "gpt-5.4"])(
  "requires verified pricing to budget Azure deployment %s",
  async (model) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repo");
    await mkdir(repository);
    await using client = new TestClient(
      { codexOverrides: { ...deployment, model } },
      {
        environment: {
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          AZURE_OPENAI_ENDPOINT: resource,
          AZURE_OPENAI_API_KEY: "synthetic-key",
        },
      },
    );
    await expect(client.preflight(repository)).resolves.toMatchObject({
      model,
      modelProvider: "azure",
      authentication: { method: "api_key", source: "AZURE_OPENAI_API_KEY" },
    });
    await expect(
      client.preflight(repository, { maxCostUsd: 1 }),
    ).rejects.toThrow(/cost limit|pricing/iu);
  },
);
