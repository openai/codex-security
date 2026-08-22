import { describe, expect, test } from "bun:test";
import {
  CodexSecurityError,
  OutputInsideProtectedRootError,
  ScanCostLimitExceededError,
  ScanInterruptedError,
  errorMessage,
  safeErrorMessage,
} from "../src/errors.js";

describe("error messages", () => {
  test("preserves public error names, causes, and recovery details", () => {
    const cause = new Error("synthetic cause");
    const base = new CodexSecurityError("synthetic failure", { cause });
    expect(base).toMatchObject({
      name: "CodexSecurityError",
      message: "synthetic failure",
      cause,
    });
    const output = new OutputInsideProtectedRootError("/scan", "/repository");
    expect(output).toMatchObject({
      name: "OutputInsideProtectedRootError",
      outputDirectory: "/scan",
      protectedRoot: "/repository",
      pathKind: "output",
    });
    expect(output.message).toContain("/scan");
    expect(
      new OutputInsideProtectedRootError("/runtime", "/repository", "runtime")
        .pathKind,
    ).toBe("runtime");
    expect(
      new ScanInterruptedError("stopped", "/scan", { cause }),
    ).toMatchObject({
      name: "ScanInterruptedError",
      message: "stopped",
      scanDir: "/scan",
      cause,
    });
    const cost = {
      model: "synthetic",
      inputTokens: 1,
      cachedInputTokens: 0,
      cacheWriteInputTokens: 0,
      outputTokens: 1,
      estimatedUsd: 2,
    };
    const limit = new ScanCostLimitExceededError(1, cost, "/scan");
    expect(limit).toBeInstanceOf(ScanInterruptedError);
    expect(limit).toMatchObject({
      name: "ScanCostLimitExceededError",
      maxCostUsd: 1,
      cost,
      scanDir: "/scan",
    });
    expect(limit.message).toContain("$2.00");
    expect(limit.message).toContain("$1.00");
    expect(limit.message).toContain("/scan");
  });

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
