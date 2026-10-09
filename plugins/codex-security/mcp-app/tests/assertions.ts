import assert from "node:assert/strict";

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
