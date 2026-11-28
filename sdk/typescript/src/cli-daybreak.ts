import type { JsonObject } from "./config.js";
import { asRecord, isRecord } from "./record.js";

type CyberAccessProgram = "standard" | "daybreakBlue" | "daybreakRed";

export type AppServerRequest = (
  method: string,
  params: JsonObject,
) => Promise<JsonObject>;

async function* listPages(
  request: AppServerRequest,
  method: string,
  params: JsonObject,
) {
  let cursor: string | undefined;
  do {
    const { data, nextCursor } = await request(
      method,
      cursor === undefined ? params : { ...params, cursor },
    );
    if (Array.isArray(data))
      yield data.filter((row): row is JsonObject => isRecord(row));
    cursor = typeof nextCursor === "string" ? nextCursor : undefined;
  } while (cursor !== undefined);
}

export async function daybreakFeatures(
  request: AppServerRequest,
  threadId?: string,
) {
  const features = new Map<string, unknown>();
  const pages = listPages(
    request,
    "experimentalFeature/list",
    threadId === undefined ? {} : { threadId },
  );
  for await (const flags of pages) {
    for (const { name, enabled } of flags) {
      if (typeof name === "string") features.set(name, enabled);
    }
    if (threadId !== undefined && features.get("cli_daybreak") === false) break;
    if (
      features.has("cli_daybreak") &&
      features.has("api_key_cyber_access_programs") &&
      (threadId !== undefined || features.has("api_key_model_discovery"))
    )
      break;
  }
  return features;
}

export async function modelCyberAccessPrograms(
  model: string,
  request: AppServerRequest,
) {
  for await (const models of listPages(request, "model/list", {
    includeHidden: true,
  })) {
    const selected = models.find((entry) => entry["model"] === model);
    if (selected === undefined) continue;
    const programs = asRecord(selected["availableAccessPrograms"])?.["cyber"];
    return Array.isArray(programs) ? programs : undefined;
  }
  return undefined;
}

export async function daybreakAccountType(request: AppServerRequest) {
  const { account } = await request("account/read", { refreshToken: false });
  return asRecord(account)?.["type"];
}

// App-server clients resolve Daybreak from the catalog before starting a turn,
// just as native Codex exec does; the config key alone does not select a program.
export async function appServerCyberAccessProgram(
  config: JsonObject,
  model: string,
  provider: string,
  threadId: string,
  request: AppServerRequest,
): Promise<CyberAccessProgram | undefined> {
  const features = await daybreakFeatures(request, threadId);
  if (features.get("cli_daybreak") === false) return undefined;
  if (!features.has("cli_daybreak")) {
    throw new Error("Codex did not report the effective cli_daybreak feature");
  }
  const enabled = config["daybreak"] === true;
  if (provider !== "openai") {
    if (enabled) throw new Error("Daybreak requires the OpenAI model provider");
    return undefined;
  }

  if (enabled) {
    const account = await daybreakAccountType(request);
    if (account !== "chatgpt" && account !== "apiKey") {
      throw new Error(
        "Daybreak requires a signed-in ChatGPT account or an OpenAI API key",
      );
    }
  }

  const programs = await modelCyberAccessPrograms(model, request).catch(
    () => undefined,
  );
  if (!programs?.length) return undefined;
  if (enabled) {
    for (const program of ["daybreakBlue", "daybreakRed"] as const) {
      if (programs.includes(program)) return program;
    }
    throw new Error(
      `Daybreak is unavailable for model ${model}; turn it off or choose a compatible model`,
    );
  }
  if (!programs.includes("standard")) return undefined;
  const account = await daybreakAccountType(request).catch(() => undefined);
  return account === "chatgpt" ||
    (account === "apiKey" &&
      features.get("api_key_cyber_access_programs") === true)
    ? "standard"
    : undefined;
}
