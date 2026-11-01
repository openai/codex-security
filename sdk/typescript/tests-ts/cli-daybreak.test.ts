import { expect, test } from "bun:test";
import { appServerCyberAccessProgram } from "../src/cli-daybreak.js";
import type { JsonObject } from "../src/config.js";

const featureResponse = (enabled = true, apiKeyGate = true): JsonObject => ({
  data: [
    { name: "cli_daybreak", enabled },
    { name: "api_key_cyber_access_programs", enabled: apiKeyGate },
  ],
  nextCursor: null,
});

function withFeature(
  request: Parameters<typeof appServerCyberAccessProgram>[4],
  apiKeyGate = true,
): Parameters<typeof appServerCyberAccessProgram>[4] {
  return async (method, params) =>
    method === "experimentalFeature/list"
      ? featureResponse(true, apiKeyGate)
      : request(method, params);
}

test("resolves the selected model across catalog pages and prefers Blue", async () => {
  const requests: Array<{ method: string; params: JsonObject }> = [];
  const program = await appServerCyberAccessProgram(
    { daybreak: true, features: { cli_daybreak: false } },
    "selected-model",
    "openai",
    "selected-thread",
    async (method, params): Promise<JsonObject> => {
      requests.push({ method, params });
      if (method === "experimentalFeature/list") return featureResponse();
      if (method === "account/read") return { account: { type: "apiKey" } };
      return params["cursor"] === "next-page"
        ? {
            data: [
              {
                model: "selected-model",
                availableAccessPrograms: {
                  cyber: ["standard", "daybreakRed", "daybreakBlue"],
                },
              },
            ],
          }
        : {
            data: [
              {
                model: "other-model",
                availableAccessPrograms: { cyber: ["daybreakRed"] },
              },
            ],
            nextCursor: "next-page",
          };
    },
  );
  expect(program).toBe("daybreakBlue");
  expect(requests).toEqual([
    {
      method: "experimentalFeature/list",
      params: { threadId: "selected-thread" },
    },
    { method: "account/read", params: { refreshToken: false } },
    { method: "model/list", params: { includeHidden: true } },
    {
      method: "model/list",
      params: { includeHidden: true, cursor: "next-page" },
    },
  ]);
});

test.each([
  [true, "apiKey", true, ["daybreakRed"], "daybreakRed"],
  [false, "apiKey", true, ["standard"], "standard"],
  [false, "apiKey", false, ["standard"], undefined],
  [false, "chatgpt", false, ["standard"], "standard"],
  [false, "apiKey", true, ["daybreakBlue"], undefined],
  [true, "apiKey", true, [], undefined],
  [true, "apiKey", true, undefined, undefined],
] as const)(
  "resolves native treatment enabled=%p account=%s gate=%p programs=%j",
  async (daybreak, account, apiKeyGate, programs, expected) => {
    expect(
      await appServerCyberAccessProgram(
        { daybreak, features: { api_key_cyber_access_programs: apiKeyGate } },
        "selected-model",
        "openai",
        "selected-thread",
        withFeature(
          async (method): Promise<JsonObject> =>
            method === "account/read"
              ? { account: { type: account } }
              : {
                  data: [
                    {
                      model: "selected-model",
                      ...(programs === undefined
                        ? {}
                        : {
                            availableAccessPrograms: { cyber: [...programs] },
                          }),
                    },
                  ],
                },
          apiKeyGate,
        ),
      ),
    ).toBe(expected);
  },
);

test.each([
  [undefined, false, undefined],
  [true, false, undefined],
  [false, true, "standard"],
] as const)(
  "uses the effective API-key gate when raw=%p and effective=%p",
  async (raw, effective, expected) => {
    const program = await appServerCyberAccessProgram(
      {
        features:
          raw === undefined ? {} : { api_key_cyber_access_programs: raw },
      },
      "selected-model",
      "openai",
      "selected-thread",
      withFeature(
        async (method): Promise<JsonObject> =>
          method === "account/read"
            ? { account: { type: "apiKey" } }
            : {
                data: [
                  {
                    model: "selected-model",
                    availableAccessPrograms: { cyber: ["standard"] },
                  },
                ],
              },
        effective,
      ),
    );
    expect(program).toBe(expected);
  },
);

test("reads the API-key gate on a later native feature page", async () => {
  const featureRequests: JsonObject[] = [];
  const program = await appServerCyberAccessProgram(
    { features: { api_key_cyber_access_programs: true } },
    "selected-model",
    "openai",
    "selected-thread",
    async (method, params): Promise<JsonObject> => {
      if (method === "experimentalFeature/list") {
        featureRequests.push(params);
        return params["cursor"] === "api-key-page"
          ? {
              data: [{ name: "api_key_cyber_access_programs", enabled: false }],
              nextCursor: null,
            }
          : {
              data: [{ name: "cli_daybreak", enabled: true }],
              nextCursor: "api-key-page",
            };
      }
      if (method === "account/read") return { account: { type: "apiKey" } };
      return {
        data: [
          {
            model: "selected-model",
            availableAccessPrograms: { cyber: ["standard"] },
          },
        ],
      };
    },
  );
  expect(program).toBeUndefined();
  expect(featureRequests).toEqual([
    { threadId: "selected-thread" },
    { threadId: "selected-thread", cursor: "api-key-page" },
  ]);
});

test.each(["openai", "custom"])(
  "honors a managed feature disable for provider %s across native feature pages",
  async (provider) => {
    const requests: Array<{ method: string; params: JsonObject }> = [];
    const program = await appServerCyberAccessProgram(
      { daybreak: true, features: { cli_daybreak: true } },
      "selected-model",
      provider,
      "selected-thread",
      async (method, params) => {
        requests.push({ method, params });
        return params["cursor"] === "feature-page"
          ? featureResponse(false)
          : {
              data: [{ name: "other_feature", enabled: true }],
              nextCursor: "feature-page",
            };
      },
    );
    expect(program).toBeUndefined();
    expect(requests).toEqual([
      {
        method: "experimentalFeature/list",
        params: { threadId: "selected-thread" },
      },
      {
        method: "experimentalFeature/list",
        params: { threadId: "selected-thread", cursor: "feature-page" },
      },
    ]);
  },
);

test("preserves custom-provider behavior when Daybreak is available", async () => {
  const unexpectedRequest = async (): Promise<JsonObject> => {
    throw new Error("No native request expected");
  };
  expect(
    await appServerCyberAccessProgram(
      {},
      "selected-model",
      "custom",
      "selected-thread",
      withFeature(unexpectedRequest),
    ),
  ).toBeUndefined();
  await expect(
    appServerCyberAccessProgram(
      { daybreak: true },
      "selected-model",
      "custom",
      "selected-thread",
      withFeature(unexpectedRequest),
    ),
  ).rejects.toThrow("Daybreak requires the OpenAI model provider");
});

test("reports unavailable accounts and advertised models without Daybreak", async () => {
  await expect(
    appServerCyberAccessProgram(
      { daybreak: true },
      "selected-model",
      "openai",
      "selected-thread",
      withFeature(async () => ({ account: null })),
    ),
  ).rejects.toThrow(
    "Daybreak requires a signed-in ChatGPT account or an OpenAI API key",
  );
  await expect(
    appServerCyberAccessProgram(
      { daybreak: true },
      "selected-model",
      "openai",
      "selected-thread",
      withFeature(async (method): Promise<JsonObject> =>
        method === "account/read"
          ? { account: { type: "apiKey" } }
          : {
              data: [
                {
                  model: "selected-model",
                  availableAccessPrograms: { cyber: ["standard"] },
                },
              ],
            },
      ),
    ),
  ).rejects.toThrow("Daybreak is unavailable for model selected-model");
});

test("preserves account diagnostics and native catalog-failure behavior", async () => {
  const failure = new Error(
    "Synthetic native account failure with diagnostic detail",
  );
  await expect(
    appServerCyberAccessProgram(
      { daybreak: true },
      "selected-model",
      "openai",
      "selected-thread",
      withFeature(async () => {
        throw failure;
      }),
    ),
  ).rejects.toBe(failure);
  expect(
    await appServerCyberAccessProgram(
      {},
      "selected-model",
      "openai",
      "selected-thread",
      withFeature(async () => {
        throw new Error("Synthetic catalog unavailable");
      }),
    ),
  ).toBeUndefined();
});

test("preserves native feature-query diagnostics", async () => {
  const failure = new Error(
    "Synthetic native feature failure with diagnostic detail",
  );
  await expect(
    appServerCyberAccessProgram(
      { daybreak: true },
      "selected-model",
      "openai",
      "selected-thread",
      async () => {
        throw failure;
      },
    ),
  ).rejects.toBe(failure);
});
