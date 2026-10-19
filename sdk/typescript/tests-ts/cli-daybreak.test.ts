import { expect, test } from "bun:test";
import { appServerCyberAccessProgram } from "../src/cli-daybreak.js";
import type { JsonObject } from "../src/config.js";

test("resolves the selected model across catalog pages and prefers Blue", async () => {
  const requests: Array<{ method: string; params: JsonObject }> = [];
  const program = await appServerCyberAccessProgram(
    { daybreak: true },
    "selected-model",
    "openai",
    async (method, params): Promise<JsonObject> => {
      requests.push({ method, params });
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
        async (method): Promise<JsonObject> =>
          method === "account/read"
            ? { account: { type: account } }
            : {
                data: [
                  {
                    model: "selected-model",
                    ...(programs === undefined
                      ? {}
                      : { availableAccessPrograms: { cyber: [...programs] } }),
                  },
                ],
              },
      ),
    ).toBe(expected);
  },
);

test("leaves disabled features and other providers to native defaults", async () => {
  const unexpectedRequest = async (): Promise<JsonObject> => {
    throw new Error("No native request expected");
  };
  expect(
    await appServerCyberAccessProgram(
      { daybreak: true, features: { cli_daybreak: false } },
      "selected-model",
      "openai",
      unexpectedRequest,
    ),
  ).toBeUndefined();
  expect(
    await appServerCyberAccessProgram(
      {},
      "selected-model",
      "custom",
      unexpectedRequest,
    ),
  ).toBeUndefined();
  await expect(
    appServerCyberAccessProgram(
      { daybreak: true },
      "selected-model",
      "custom",
      unexpectedRequest,
    ),
  ).rejects.toThrow("Daybreak requires the OpenAI model provider");
});

test("reports unavailable accounts and advertised models without Daybreak", async () => {
  await expect(
    appServerCyberAccessProgram(
      { daybreak: true },
      "selected-model",
      "openai",
      async () => ({ account: null }),
    ),
  ).rejects.toThrow(
    "Daybreak requires a signed-in ChatGPT account or an OpenAI API key",
  );
  await expect(
    appServerCyberAccessProgram(
      { daybreak: true },
      "selected-model",
      "openai",
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
      async () => {
        throw failure;
      },
    ),
  ).rejects.toBe(failure);
  expect(
    await appServerCyberAccessProgram(
      {},
      "selected-model",
      "openai",
      async () => {
        throw new Error("Synthetic catalog unavailable");
      },
    ),
  ).toBeUndefined();
});
