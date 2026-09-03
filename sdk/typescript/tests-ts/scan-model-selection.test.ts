import { describe, expect, test } from "bun:test";
import type { JsonObject } from "../src/config.js";
import type { CatalogModel } from "../src/model-catalog.js";
import { getScanModelAdvice } from "../src/model-advice.js";
import { availableScanModels } from "../src/scan-model-selection.js";

const catalog: [CatalogModel, CatalogModel] = [
  {
    id: "gpt-5.4",
    model: "gpt-5.4",
    hidden: true,
    upgrade: "gpt-5.5",
    defaultReasoningEffort: "medium",
    supportedReasoningEfforts: [
      { reasoningEffort: "medium" },
      { reasoningEffort: "xhigh" },
    ],
  },
  {
    id: "current-model",
    model: "gpt-5.5",
    hidden: false,
    defaultReasoningEffort: "medium",
    supportedReasoningEfforts: [
      { reasoningEffort: "medium" },
      { reasoningEffort: "xhigh" },
    ],
  },
];

function fetchFixture(
  implementation: (
    ...args: Parameters<typeof fetch>
  ) => ReturnType<typeof fetch>,
): typeof fetch {
  return Object.assign(implementation, { preconnect: () => undefined });
}

function scan(config: JsonObject = {}) {
  return {
    command: { command: "synthetic-codex" },
    environment: {
      CODEX_HOME: "/synthetic/prepared-home",
      OPENAI_ORGANIZATION: "synthetic-organization",
      OPENAI_PROJECT: "synthetic-project",
    },
    config,
    apiKey: "synthetic-scan-key",
    signal: new AbortController().signal,
  };
}

describe("scan model availability", () => {
  test("intersects API access with Codex metadata using the scan's auth context", async () => {
    const options = scan({
      openai_base_url: "https://api.example.test/v1/",
      model_catalog_json: "/synthetic/model-catalog.json",
    });
    const result = await availableScanModels(options, {
      readModelCatalog: async (command, environment, auth) => {
        expect(command).toBe(options.command);
        expect(environment).toBe(options.environment);
        expect(auth).toEqual({
          config: options.config,
          apiKey: options.apiKey,
          signal: options.signal,
        });
        return catalog;
      },
      fetch: fetchFixture(async (input, init) => {
        expect(String(input)).toBe("https://api.example.test/v1/models");
        expect(new Headers(init?.headers).get("Authorization")).toBe(
          "Bearer synthetic-scan-key",
        );
        expect(new Headers(init?.headers).get("OpenAI-Organization")).toBe(
          "synthetic-organization",
        );
        expect(new Headers(init?.headers).get("OpenAI-Project")).toBe(
          "synthetic-project",
        );
        expect(init?.signal).toBe(options.signal);
        return Response.json({
          data: [{ id: "gpt-5.5" }, { id: "unrelated-api-model" }],
        });
      }),
    });
    expect(result).toEqual(catalog);
    expect(
      getScanModelAdvice({
        model: "gpt-5.4",
        reasoningEffort: "medium",
        availableModels: result,
      }).modelUpgrade?.model,
    ).toBe("gpt-5.5");
  });

  test("matches a catalog alias exposed by the API", async () => {
    expect(
      await availableScanModels(scan(), {
        readModelCatalog: async () => catalog,
        fetch: fetchFixture(async () =>
          Response.json({ data: [{ id: "current-model" }] }),
        ),
      }),
    ).toEqual(catalog);
  });

  test("keeps unavailable upgrade targets in the graph without recommending them", async () => {
    const result = await availableScanModels(scan(), {
      readModelCatalog: async () => catalog,
      fetch: fetchFixture(async () =>
        Response.json({ data: [{ id: "gpt-5.4" }] }),
      ),
    });
    expect(result).toEqual([catalog[0], { ...catalog[1], hidden: true }]);
    expect(
      getScanModelAdvice({
        model: "gpt-5.4",
        reasoningEffort: "medium",
        availableModels: result,
      }).modelUpgrade,
    ).toBeUndefined();
    expect(catalog[1].hidden).toBe(false);
  });

  test.each<JsonObject>([{}, { openai_base_url: "" }])(
    "uses the built-in endpoint when no nonempty base URL is configured: %j",
    async (config) => {
      await availableScanModels(scan(config), {
        readModelCatalog: async () => catalog,
        fetch: fetchFixture(async (input) => {
          expect(String(input)).toBe("https://api.openai.com/v1/models");
          return Response.json({ data: [] });
        }),
      });
    },
  );

  test("ignores built-in provider overrides that Codex does not apply", async () => {
    await availableScanModels(
      scan({
        model_provider: "openai",
        openai_base_url: "https://selected.example.test/v1",
        model_providers: {
          openai: {
            base_url: "https://ignored.example.test/v1",
            env_key: "SYNTHETIC_PROVIDER_KEY",
            experimental_bearer_token: "ignored-key",
            query_params: { "api-version": "ignored-version" },
            http_headers: {
              Authorization: "Bearer ignored-key",
              "X-Ignored-Header": "ignored-value",
            },
            env_http_headers: { "X-Ignored-Environment": "OPENAI_PROJECT" },
          },
        },
      }),
      {
        readModelCatalog: async () => catalog,
        fetch: fetchFixture(async (input, init) => {
          expect(String(input)).toBe("https://selected.example.test/v1/models");
          const headers = new Headers(init?.headers);
          expect(headers.get("Authorization")).toBe(
            "Bearer synthetic-scan-key",
          );
          expect(headers.has("X-Ignored-Header")).toBe(false);
          expect(headers.has("X-Ignored-Environment")).toBe(false);
          return Response.json({ data: [] });
        }),
      },
    );
  });

  test("uses the ChatGPT catalog without sending an API request", async () => {
    const options = {
      ...scan({
        profile: "selected",
        profiles: {
          selected: { model: "gpt-5.4" },
          other: { model_catalog_json: "/synthetic/other-catalog.json" },
        },
      }),
      apiKey: null,
    };
    expect(
      await availableScanModels(options, {
        readModelCatalog: async (_command, _environment, auth) => {
          expect(auth).toEqual({
            config: options.config,
            signal: options.signal,
          });
          return catalog;
        },
        fetch: fetchFixture(async () => {
          throw new Error("ChatGPT discovery must not call the API");
        }),
      }),
    ).toBe(catalog);
  });

  test.each<JsonObject>([
    { model_catalog_json: "/synthetic/model-catalog.json" },
    {
      profile: "selected",
      profiles: {
        selected: { model_catalog_json: "/synthetic/model-catalog.json" },
      },
    },
  ])(
    "does not infer ChatGPT account access from a custom catalog: %j",
    async (config) => {
      expect(
        await availableScanModels(
          { ...scan(config), apiKey: null },
          {
            readModelCatalog: async () => {
              throw new Error(
                "Custom catalogs do not establish ChatGPT account access",
              );
            },
            fetch: fetchFixture(async () => {
              throw new Error("ChatGPT discovery must not call the API");
            }),
          },
        ),
      ).toBeUndefined();
    },
  );

  test.each<JsonObject>([
    { model_provider: "synthetic-provider" },
    {
      profile: "selected",
      profiles: { selected: { model_provider: "synthetic-provider" } },
    },
    {
      model_provider: "openai",
      model_providers: { openai: { auth: { command: "synthetic-auth" } } },
    },
  ])(
    "does not send credentials for unsupported provider auth: %j",
    async (config) => {
      expect(
        await availableScanModels(scan(config), {
          readModelCatalog: async () => {
            throw new Error(
              "Unsupported auth must not start catalog discovery",
            );
          },
          fetch: fetchFixture(async () => {
            throw new Error("Unsupported auth must not send an API request");
          }),
        }),
      ).toBeUndefined();
    },
  );

  test("propagates catalog and API failures to the optional-advice caller", async () => {
    const failure = new Error("Synthetic catalog failure");
    await expect(
      availableScanModels(scan(), {
        readModelCatalog: async () => {
          throw failure;
        },
        fetch: fetchFixture(async () => {
          throw new Error("API discovery must not run after catalog failure");
        }),
      }),
    ).rejects.toBe(failure);
    await expect(
      availableScanModels(scan(), {
        readModelCatalog: async () => catalog,
        fetch: fetchFixture(
          async () => new Response("Unavailable", { status: 503 }),
        ),
      }),
    ).rejects.toThrow("HTTP 503");
    await expect(
      availableScanModels(scan(), {
        readModelCatalog: async () => catalog,
        fetch: fetchFixture(async () => {
          throw failure;
        }),
      }),
    ).rejects.toBe(failure);
  });
});
