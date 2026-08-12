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
      "authorizationHeaderValue=SYNTHETIC_SECRET",
      "api_key_header_value=SYNTHETIC_SECRET",
      'config["api_key"]="SYNTHETIC_SECRET"',
      JSON.stringify('config["api_key"]="SYNTHETIC_SECRET"'),
      encodeURIComponent(JSON.stringify({ api_key: "SYNTHETIC_SECRET" })),
      "https://example.test/?credentials[access_token]=SYNTHETIC_SECRET",
      "https://example.test/?user[password]=SYNTHETIC_SECRET",
      "https://example.test/?config[api_key]=SYNTHETIC_SECRET",
      "https://example.test/?access%5Fkey=SYNTHETIC_SECRET",
      "https://example.test/?private%2Dkey=SYNTHETIC_SECRET",
      "sig_value=SYNTHETIC_SIGNATURE",
      "sigHeader=SYNTHETIC_SIGNATURE",
      "proxy https://user:SYNTHETIC_PASSWORD@example.test",
      "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_PRIVATE_KEY",
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nSYNTHETIC_PRIVATE_KEY",
    ]) {
      expect(safeErrorMessage(new Error(message))).toBe("[redacted]");
    }
    expect(safeErrorMessage("upstream service unavailable")).toBe(
      "upstream service unavailable",
    );
    expect(safeErrorMessage("author=Michael")).toBe("author=Michael");
    expect(safeErrorMessage("signal=active")).toBe("signal=active");
    expect(safeErrorMessage("design=complete")).toBe("design=complete");
    expect(safeErrorMessage('worker 1: rg -n "password" src/login.ts')).toBe(
      'worker 1: rg -n "password" src/login.ts',
    );
    expect(safeErrorMessage("secret".repeat(4_000))).toBe(
      "secret".repeat(4_000),
    );
  });
});
