import { describe, expect, test } from "bun:test";
import {
  CodexSecurityError,
  OutputInsideProtectedRootError,
  ScanCostLimitExceededError,
  ScanInterruptedError,
  errorMessage,
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
    expect(limit.message).toContain("short-context budget baseline $2.00");
    expect(limit.message).toContain("legacy estimate, context unknown");
    expect(limit.message).toContain("/scan");
  });

  test.each([
    "request failed: token=SYNTHETIC_TOKEN",
    "Authorization: Bearer sk-proj-SYNTHETIC_KEY_123",
    "token budget exceeded",
    "basic validation failed",
    "unable to open database file",
  ])("preserves error messages exactly: %s", (message) => {
    expect(errorMessage(new Error(message))).toBe(message);
    expect(errorMessage(message)).toBe(message);
  });

  test("formats non-error values without parsing them", () => {
    expect(errorMessage(42)).toBe("42");
    expect(errorMessage(null)).toBe("null");
  });
});
