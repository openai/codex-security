import { describe, expect, test } from "bun:test";
import {
  scanAuthentication,
  scanPreflightCodexConfig,
  selectedScanEnvironment,
} from "../src/api.js";
import {
  AZURE_CODEX_PROVIDER,
  azureBaseUrl,
  externalProviderTable,
} from "../src/config.js";
import { parseCodexOverrides } from "../src/cli.js";

const RESOURCE = "https://synthetic-resource.openai.azure.com";
const azureEnvironment = (overrides: Record<string, string> = {}) => ({
  AZURE_OPENAI_BASE_URL: RESOURCE,
  AZURE_OPENAI_API_KEY: "synthetic-azure-key",
  ...overrides,
});

describe("Azure endpoint resolution", () => {
  test.each([
    ["bare resource endpoint", RESOURCE],
    ["trailing slash", `${RESOURCE}/`],
    ["explicit v1 path", `${RESOURCE}/openai/v1`],
    ["explicit v1 path with slash", `${RESOURCE}/openai/v1/`],
  ])("normalizes the %s", (_name, configured) => {
    expect(azureBaseUrl({ AZURE_OPENAI_BASE_URL: configured })).toBe(
      `${RESOURCE}/openai/v1`,
    );
  });

  // Azure hands out at least three endpoint domains for the same v1 surface.
  test.each([
    ["openai.azure.com", "https://synthetic.openai.azure.com"],
    ["services.ai.azure.com", "https://synthetic.services.ai.azure.com"],
    [
      "cognitiveservices.azure.com",
      "https://synthetic.cognitiveservices.azure.com",
    ],
  ])("accepts a %s endpoint", (_name, endpoint) => {
    expect(azureBaseUrl({ AZURE_OPENAI_BASE_URL: endpoint })).toBe(
      `${endpoint}/openai/v1`,
    );
  });

  test("falls back to AZURE_OPENAI_ENDPOINT", () => {
    expect(azureBaseUrl({ AZURE_OPENAI_ENDPOINT: RESOURCE })).toBe(
      `${RESOURCE}/openai/v1`,
    );
  });

  test("prefers AZURE_OPENAI_BASE_URL over AZURE_OPENAI_ENDPOINT", () => {
    expect(
      azureBaseUrl({
        AZURE_OPENAI_BASE_URL: RESOURCE,
        AZURE_OPENAI_ENDPOINT: "https://ignored.openai.azure.com",
      }),
    ).toBe(`${RESOURCE}/openai/v1`);
  });

  test.each([
    ["unset", {}],
    ["blank", { AZURE_OPENAI_BASE_URL: "   " }],
    ["not a URL", { AZURE_OPENAI_BASE_URL: "synthetic-resource" }],
    ["wrong protocol", { AZURE_OPENAI_BASE_URL: "ftp://synthetic/openai" }],
  ])("rejects an endpoint that is %s", (_name, environment) => {
    expect(() => azureBaseUrl(environment)).toThrow();
  });
});

describe("Azure provider table", () => {
  test("resolves a complete Codex provider table", () => {
    expect(externalProviderTable("azure", azureEnvironment())).toEqual({
      ...AZURE_CODEX_PROVIDER,
      base_url: `${RESOURCE}/openai/v1`,
    });
  });

  test("uses the Responses wire API", () => {
    expect(AZURE_CODEX_PROVIDER.wire_api).toBe("responses");
    expect(AZURE_CODEX_PROVIDER.env_key).toBe("AZURE_OPENAI_API_KEY");
  });

  test("--provider azure builds the Codex overrides", () => {
    expect(
      parseCodexOverrides(
        [],
        "gpt-4.1-mini",
        undefined,
        "azure",
        azureEnvironment(),
      ),
    ).toEqual({
      model: "gpt-4.1-mini",
      model_provider: "azure",
      model_providers: {
        azure: { ...AZURE_CODEX_PROVIDER, base_url: `${RESOURCE}/openai/v1` },
      },
    });
  });

  test("requires a deployment name because Azure models are deployments", () => {
    expect(() =>
      parseCodexOverrides(
        [],
        undefined,
        undefined,
        "azure",
        azureEnvironment(),
      ),
    ).toThrow("--model is required when using --provider azure");
  });

  test("reports a missing endpoint rather than building a broken provider", () => {
    expect(() =>
      parseCodexOverrides([], "gpt-4.1-mini", undefined, "azure", {
        AZURE_OPENAI_API_KEY: "synthetic-azure-key",
      }),
    ).toThrow(/AZURE_OPENAI_BASE_URL or AZURE_OPENAI_ENDPOINT/u);
  });
});

describe("Azure authentication", () => {
  test("selects the Azure key, which carries a resource key or an Entra token", () => {
    expect(scanAuthentication(azureEnvironment(), "auto", "azure")).toEqual({
      method: "api_key",
      source: "AZURE_OPENAI_API_KEY",
      verified: false,
    });
  });

  test("keeps only the selected provider's credential in the scan environment", () => {
    const environment = selectedScanEnvironment(
      azureEnvironment({
        OPENAI_API_KEY: "synthetic-openai-key",
        CODEX_API_KEY: "synthetic-codex-key",
        OPENROUTER_API_KEY: "synthetic-openrouter-key",
        FIREWORKS_API_KEY: "synthetic-fireworks-key",
        PATH: "/usr/bin",
      }),
      "auto",
      "azure",
    );
    expect(environment["AZURE_OPENAI_API_KEY"]).toBe("synthetic-azure-key");
    expect(environment["AZURE_OPENAI_BASE_URL"]).toBe(RESOURCE);
    expect(environment["PATH"]).toBe("/usr/bin");
    for (const leaked of [
      "OPENAI_API_KEY",
      "CODEX_API_KEY",
      "OPENROUTER_API_KEY",
      "FIREWORKS_API_KEY",
    ]) {
      expect(environment).not.toHaveProperty(leaked);
    }
  });

  test("drops the Azure key when another provider is selected", () => {
    const environment = selectedScanEnvironment(
      azureEnvironment(),
      "auto",
      "openrouter",
    );
    expect(environment).not.toHaveProperty("AZURE_OPENAI_API_KEY");
  });
});

describe("Azure scan recipes", () => {
  test("preserves the resource endpoint and strips provider secrets", () => {
    const config = scanPreflightCodexConfig({
      model: "gpt-4.1-mini",
      model_provider: "azure",
      model_providers: {
        azure: {
          ...AZURE_CODEX_PROVIDER,
          base_url: `${RESOURCE}/openai/v1`,
          api_key: "synthetic-azure-secret",
        },
        private: { bearer_token: "synthetic-unrelated-secret" },
      },
    });
    expect(config).toEqual({
      model: "gpt-4.1-mini",
      model_provider: "azure",
      model_providers: {
        azure: { ...AZURE_CODEX_PROVIDER, base_url: `${RESOURCE}/openai/v1` },
      },
    });
    expect(JSON.stringify(config)).not.toContain("synthetic-azure-secret");
    expect(JSON.stringify(config)).not.toContain("synthetic-unrelated-secret");
  });

  test("does not let a recipe override a fixed provider endpoint", () => {
    const config = scanPreflightCodexConfig({
      model: "anthropic/claude-sonnet-4.5",
      model_provider: "openrouter",
      model_providers: {
        openrouter: { base_url: "https://synthetic-attacker.example/v1" },
      },
    });
    expect(config["model_providers"]).toMatchObject({
      openrouter: { base_url: "https://openrouter.ai/api/v1" },
    });
  });
});
