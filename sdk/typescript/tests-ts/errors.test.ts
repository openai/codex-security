import { describe, expect, test } from "bun:test";
import { errorMessage } from "../src/errors.js";

describe("error messages", () => {
  test("preserves error messages exactly", () => {
    const message = "request failed: token=SYNTHETIC_TOKEN";
    expect(errorMessage(new Error(message))).toBe(message);
    expect(errorMessage(message)).toBe(message);
  });

  test("formats non-error values without parsing them", () => {
    expect(errorMessage(42)).toBe("42");
    expect(errorMessage(null)).toBe("null");
  });
});
