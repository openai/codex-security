import assert from "node:assert/strict";
import { test } from "node:test";
import { importSource } from "./import-module.ts";
import { fileURLToPath } from "node:url";

const { workerTokenUsage } = await importSource(
  fileURLToPath(new URL("../src/deep-scan/usage-receipt.ts", import.meta.url)),
);

test("SDK defaulted zero remains unknown while positive native and legacy writes remain known", () => {
  const usage = { input_tokens: 10, cached_input_tokens: 2, output_tokens: 3 };
  assert.equal(
    workerTokenUsage({ ...usage, cache_write_input_tokens: 0 }, true)
      .cache_write_input_tokens_reported,
    false,
  );
  assert.equal(
    workerTokenUsage({ ...usage, cache_write_input_tokens: 0 }, false)
      .cache_write_input_tokens_reported,
    undefined,
  );
  for (const writes of [
    { cache_write_input_tokens: 4 },
    { cache_write_input_tokens: 0, cache_write_tokens: 4 },
  ]) {
    const normalized = workerTokenUsage({ ...usage, ...writes }, true);
    assert.equal(normalized.cache_write_input_tokens, 4);
    assert.equal(normalized.cache_write_input_tokens_reported, undefined);
  }
});
