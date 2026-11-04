import { parse } from "smol-toml";

export function requestMetadata(args: readonly string[] | undefined) {
  const override = args?.find((value) =>
    value.startsWith("responses_api_metadata="),
  );
  return override === undefined
    ? undefined
    : parse(override)["responses_api_metadata"];
}
