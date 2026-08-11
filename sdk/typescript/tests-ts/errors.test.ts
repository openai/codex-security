import { describe, expect, test } from "bun:test";
import { errorMessage, safeErrorMessage } from "../src/errors.js";

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

  test("omits credential-bearing messages at output boundaries", () => {
    for (const message of [
      "request failed: token=SYNTHETIC_TOKEN",
      "Authorization: Bearer sk-proj-SYNTHETIC_KEY_123",
      'upstream failed: {"clientSecret":"correct horse battery staple"}',
      JSON.stringify(JSON.stringify({ clientSecret: "SYNTHETIC_SECRET" })),
      "https://example.test/?credentials[access_token]=SYNTHETIC_SECRET",
      "proxy https://user:SYNTHETIC_PASSWORD@example.test",
      "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_PRIVATE_KEY",
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nSYNTHETIC_PRIVATE_KEY",
    ]) {
      expect(safeErrorMessage(new Error(message))).toBe("[redacted]");
    }
    expect(safeErrorMessage("upstream service unavailable")).toBe(
      "upstream service unavailable",
    );
  });
});
