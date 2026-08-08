import { describe, expect, test } from "bun:test";
import { redactedErrorMessage } from "../src/errors.js";

describe("security error redaction", () => {
  test("redacts standalone and truncated PEM private-key envelopes", () => {
    expect(
      redactedErrorMessage(
        "provider failed: -----BEGIN PRIVATE KEY-----\nSYNTHETIC_PRIVATE_KEY\n-----END PRIVATE KEY----- safe=value",
      ),
    ).toBe("provider failed: [redacted] safe=value");
    expect(
      redactedErrorMessage(
        "provider failed: -----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC_TRUNCATED_KEY",
      ),
    ).toBe("provider failed: [redacted]");
  });

  test("redacts every parameter from structured authorization schemes", () => {
    expect(
      redactedErrorMessage(
        'Authorization: Digest username="example", response=SYNTHETIC_DIGEST_SECRET',
      ),
    ).toBe("Authorization: Digest [redacted]");
    expect(
      redactedErrorMessage("auth=Custom response=SYNTHETIC_AUTH_SECRET"),
    ).toBe("auth=Custom [redacted]");
    expect(
      redactedErrorMessage(
        "Authorization: Custom key=SYNTHETIC_AUTH_SECRET https://example.test/safe",
      ),
    ).toBe("Authorization: Custom [redacted] https://example.test/safe");
  });

  test("redacts encoded API-key names without consuming other parameters", () => {
    for (const separator of ["%5F", "%2D"]) {
      const value = `https://example.test/?api${separator}key%3DSYNTHETIC_API_KEY%26safe%3Dvisible`;
      expect(redactedErrorMessage(value)).toBe(
        `https://example.test/?api${separator}key%3D[redacted]%26safe%3Dvisible`,
      );
    }
  });

  test("redacts plural credential assignments and quoted values", () => {
    expect(
      redactedErrorMessage(
        "credentials=SYNTHETIC_CREDENTIAL clientCredentials=SYNTHETIC_CLIENT apiKeys=SYNTHETIC_KEYS",
      ),
    ).toBe(
      "credentials=[redacted] clientCredentials=[redacted] apiKeys=[redacted]",
    );
    expect(
      redactedErrorMessage('{"credentials":"correct horse battery staple"}'),
    ).toBe('{"credentials":"[redacted]"}');
  });
});
