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

  test("does not end a private key at a different key-type delimiter", () => {
    for (const assignment of ["", "private_key="]) {
      for (const terminator of [
        "-----END EC PRIVATE KEY-----",
        "-----END rsa private key-----",
      ]) {
        const message = [
          `${assignment}-----BEGIN RSA PRIVATE KEY-----`,
          "synthetic-before",
          terminator,
          "synthetic-after",
          "-----END RSA PRIVATE KEY-----",
          "retrying",
        ].join("\n");

        expect(redactedErrorMessage(message)).toBe(
          `${assignment}[redacted]\nretrying`,
        );
      }
    }
  });

  test("redacts quoted credentials whose markers overlap a private key", () => {
    const message = [
      "-----BEGIN PRIVATE KEY-----",
      'password="',
      "-----END PRIVATE KEY-----",
      'SYNTHETIC_PASSWORD_123"',
    ].join("\n");

    expect(redactedErrorMessage(message)).toBe("[redacted]");
  });
});
