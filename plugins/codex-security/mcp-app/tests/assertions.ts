import assert from "node:assert/strict";
import { parse as parseToml } from "smol-toml";

interface ToolResponse {
  error?: { message?: string };
  result?: { isError?: boolean; content?: { text?: string }[] };
}

export function assertNoError(response: ToolResponse) {
  assert.equal(response.error, undefined, response.error?.message!);
  assert.ok(response.result, "Expected a JSON-RPC result");
  assert.notEqual(
    response.result.isError,
    true,
    response.result?.content?.map((item) => item.text).join(" ")!,
  );
}

export function assertFlagPair(
  args: readonly string[],
  flag: string,
  value: string,
) {
  const index = args.indexOf(flag);
  assert.notEqual(index, -1, `missing ${flag}`);
  assert.equal(args[index + 1], value);
}

export function nativeConfigOverrides(args: readonly string[]) {
  return args.flatMap((arg, index) =>
    arg === "--config" || arg === "-c" ? [args[index + 1]] : [],
  );
}

export function assertConfigOverrides(
  args: readonly string[],
  values: Record<string, string | number | boolean | undefined>,
) {
  const overrides = nativeConfigOverrides(args).map((value) =>
    parseToml(value),
  );
  for (const [key, value] of Object.entries(values)) {
    const supplied = overrides.map((config) =>
      key
        .split(".")
        .reduce<unknown>(
          (current, part) =>
            (current as Record<string, unknown> | undefined)?.[part],
          config,
        ),
    );
    assert.deepEqual(
      supplied.findLast((item) => item !== undefined),
      value,
      key,
    );
  }
}
