import type { JsonObject } from "./config.js";
import { isRecord } from "./record.js";

type CyberAccessProgram = "standard" | "daybreakBlue" | "daybreakRed";

// App-server clients resolve Daybreak from the catalog before starting a turn,
// just as native Codex exec does; the config key alone does not select a program.
export async function appServerCyberAccessProgram(
  config: JsonObject,
  model: string,
  provider: string,
  request: (method: string, params: JsonObject) => Promise<JsonObject>,
): Promise<CyberAccessProgram | undefined> {
  const features = isRecord(config["features"]) ? config["features"] : {};
  if (features["cli_daybreak"] === false) return undefined;
  const enabled = config["daybreak"] === true;
  if (provider !== "openai") {
    if (enabled) throw new Error("Daybreak requires the OpenAI model provider");
    return undefined;
  }

  const accountType = async (): Promise<unknown> => {
    const result = await request("account/read", { refreshToken: false });
    return isRecord(result["account"]) ? result["account"]["type"] : undefined;
  };
  if (enabled) {
    const account = await accountType();
    if (account !== "chatgpt" && account !== "apiKey") {
      throw new Error(
        "Daybreak requires a signed-in ChatGPT account or an OpenAI API key",
      );
    }
  }

  let cursor: string | undefined;
  do {
    const result = await request("model/list", {
      includeHidden: true,
      ...(cursor === undefined ? {} : { cursor }),
    }).catch(() => undefined);
    if (result === undefined) return undefined;
    const models = result["data"];
    const selected = Array.isArray(models)
      ? models.find((entry) => isRecord(entry) && entry["model"] === model)
      : undefined;
    if (isRecord(selected)) {
      const access = selected["availableAccessPrograms"];
      const programs = isRecord(access) ? access["cyber"] : undefined;
      if (!Array.isArray(programs) || programs.length === 0) return undefined;
      if (enabled) {
        for (const program of ["daybreakBlue", "daybreakRed"] as const) {
          if (programs.includes(program)) return program;
        }
        throw new Error(
          `Daybreak is unavailable for model ${model}; turn it off or choose a compatible model`,
        );
      }
      if (!programs.includes("standard")) return undefined;
      const account = await accountType().catch(() => undefined);
      return account === "chatgpt" ||
        (account === "apiKey" &&
          features["api_key_cyber_access_programs"] !== false)
        ? "standard"
        : undefined;
    }
    cursor =
      typeof result["nextCursor"] === "string"
        ? result["nextCursor"]
        : undefined;
  } while (cursor !== undefined);
  return undefined;
}
