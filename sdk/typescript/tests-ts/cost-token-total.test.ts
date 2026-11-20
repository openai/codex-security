import { describe, expect, test } from "bun:test";
import { tokenUsage } from "../src/cost-model.js";
import { addTokenUsage } from "../src/cost.js";

describe("token usage total", () => {
  test("keeps an ordinary exact total", () => {
    expect(
      tokenUsage({ input_tokens: 1_000, output_tokens: 500 }),
    ).toMatchObject({
      input_tokens: 1_000,
      output_tokens: 500,
      total_tokens: 1_500,
    });
  });

  test("accepts a total at the safe-integer boundary", () => {
    const input = Number.MAX_SAFE_INTEGER - 2;
    expect(tokenUsage({ input_tokens: input, output_tokens: 2 })).toMatchObject(
      {
        input_tokens: input,
        output_tokens: 2,
        total_tokens: Number.MAX_SAFE_INTEGER,
      },
    );
  });

  test("rejects a total beyond the safe-integer boundary", () => {
    expect(
      tokenUsage({
        input_tokens: Number.MAX_SAFE_INTEGER,
        output_tokens: 2,
      }),
    ).toBeNull();
  });

  test("does not report an inexact aggregate of individually valid records", () => {
    const first = tokenUsage({
      input_tokens: Number.MAX_SAFE_INTEGER,
      output_tokens: 0,
    });
    const second = tokenUsage({ input_tokens: 0, output_tokens: 2 });
    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    expect(addTokenUsage(first, second!)).toBeNull();
  });
});
