import { describe, expect, test } from "bun:test";
import fc from "fast-check";
import { errorMessage, safeErrorMessage } from "../src/errors.js";
import { propertyOptions } from "./support/property.js";

const word = fc.stringMatching(/^[a-zA-Z0-9]{1,40}$/u);
const credential = word.map((value) => `SYNTHETIC_${value}`);

describe("error-message invariants", () => {
  test("omits recognized credentials in plain, JSON, and URL-encoded errors", () => {
    fc.assert(
      fc.property(
        credential,
        fc.constantFrom(
          "api_key",
          "apikey",
          "accesskey",
          "access-key",
          "privatekey",
          "private-key",
          "sig",
          "access_token",
          "clientSecret",
          "password",
          "authorization",
        ),
        (secret, field) => {
          const json = JSON.stringify({ [field]: secret });
          for (const message of [
            `${field}=${secret}`,
            json,
            JSON.stringify(json),
            encodeURIComponent(json),
            `Bearer ${secret}`,
            `Basic  ${secret}`,
            `token%20${secret}`,
            `sk-${secret}`,
            `sk-proj-${secret}`,
            `github_pat_${secret}`,
            ...["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "npm_"].map(
              (prefix) => `${prefix}${secret}`,
            ),
            `https://synthetic:${secret}@example.test/`,
          ]) {
            expect(safeErrorMessage(message)).toBe("[redacted]");
            expect(safeErrorMessage(new Error(message))).toBe("[redacted]");
            expect(errorMessage(new Error(message))).toBe(message);
          }
        },
      ),
      propertyOptions,
    );
  });

  test("preserves ordinary diagnostic text exactly", () => {
    fc.assert(
      fc.property(fc.nat(), word, (index, detail) => {
        const message = `operation failed for item ${index} (${detail})`;
        expect(safeErrorMessage(message)).toBe(message);
        expect(safeErrorMessage(new Error(message))).toBe(message);
      }),
      propertyOptions,
    );
  });
});
