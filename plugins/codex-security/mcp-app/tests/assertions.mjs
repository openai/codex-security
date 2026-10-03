import assert from "node:assert/strict";

export function assertNoError(response) {
  assert.equal(response.error, undefined, response.error?.message);
  assert.equal(
    response.result?.isError,
    undefined,
    response.result?.content?.map((item) => item.text).join(" "),
  );
}

export function assertFlagPair(args, flag, value) {
  const index = args.indexOf(flag);
  assert.notEqual(index, -1, `missing ${flag}`);
  assert.equal(args[index + 1], value);
}
