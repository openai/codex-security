import { describe, expect, test } from "bun:test";
import fc from "fast-check";
import { errorMessage } from "../src/errors.js";
import { propertyOptions } from "./support/property.js";

describe("error-message invariants", () => {
  test("preserves arbitrary diagnostic text exactly", () => {
    fc.assert(
      fc.property(fc.string(), (message) => {
        expect(errorMessage(message)).toBe(message);
        expect(errorMessage(new Error(message))).toBe(message);
      }),
      propertyOptions,
    );
  });
});
