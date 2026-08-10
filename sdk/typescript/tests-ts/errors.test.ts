import { describe, expect, test } from "bun:test";
import { redactedErrorMessage } from "../src/errors.js";

describe("credential redaction", () => {
  test("redacts standalone private keys without hiding surrounding diagnostics", () => {
    const message = [
      "connection failed:",
      "-----BEGIN PRIVATE KEY-----",
      "synthetic-key-material",
      "-----END PRIVATE KEY-----",
      "retrying",
    ].join("\n");

    expect(redactedErrorMessage(message)).toBe(
      "connection failed:\n[redacted]\nretrying",
    );
  });

  test("redacts truncated standalone private keys", () => {
    expect(
      redactedErrorMessage(
        "upstream failure: -----BEGIN RSA PRIVATE KEY-----\nsynthetic-key-material",
      ),
    ).toBe("upstream failure: [redacted]");
  });
});
