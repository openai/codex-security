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

  test("redacts overlapping private-key blocks through their own delimiters", () => {
    const message = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN EC PRIVATE KEY-----",
      "-----END RSA PRIVATE KEY-----",
      "SYNTHETIC_EC_KEY_MATERIAL",
      "-----END EC PRIVATE KEY-----",
      "retrying",
    ].join("\n");

    expect(redactedErrorMessage(message)).toBe("[redacted]\nretrying");
  });

  test("pairs nested private keys with separate matching delimiters", () => {
    const message = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----END RSA PRIVATE KEY-----",
      "SYNTHETIC_OUTER_KEY_MATERIAL",
      "-----END RSA PRIVATE KEY-----",
      "retrying",
    ].join("\n");

    expect(redactedErrorMessage(message)).toBe("[redacted]\nretrying");
  });

  test("does not end a private key at a delimiter embedded in another line", () => {
    const message = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "prefix-----END RSA PRIVATE KEY-----suffix",
      "SYNTHETIC_KEY_MATERIAL",
      "-----END RSA PRIVATE KEY-----",
      "retrying",
    ].join("\n");

    expect(redactedErrorMessage(message)).toBe("[redacted]\nretrying");
  });

  test("does not end a private key before text on the delimiter line", () => {
    const message = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----END RSA PRIVATE KEY----- NOT_A_BOUNDARY",
      "SYNTHETIC_KEY_MATERIAL",
      "-----END RSA PRIVATE KEY-----",
      "retrying",
    ].join("\n");

    expect(redactedErrorMessage(message)).toBe("[redacted]\nretrying");
  });

  test("does not end a private key at an unrelated quote", () => {
    for (const suffix of ['"NOT_A_BOUNDARY', '",NOT_A_BOUNDARY']) {
      const message = [
        "-----BEGIN RSA PRIVATE KEY-----",
        `-----END RSA PRIVATE KEY-----${suffix}`,
        "SYNTHETIC_SECOND_KEY_MATERIAL",
        "-----END RSA PRIVATE KEY-----",
        "retrying",
      ].join("\n");

      expect(redactedErrorMessage(message)).toBe("[redacted]\nretrying");
    }
  });

  test("preserves text containing an invalid opening delimiter", () => {
    for (const suffix of ["NOT_A_PEM; retry=visible", "\nretry=visible"]) {
      for (const padding of ["", " "]) {
        const message = `parser rejected abc${padding}-----BEGIN RSA PRIVATE KEY-----${suffix}`;
        expect(redactedErrorMessage(message)).toBe(message);
      }
    }
  });

  test("does not confuse literal escapes with serialized line boundaries", () => {
    const message = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "prefix\\n-----END RSA PRIVATE KEY-----",
      "SYNTHETIC_SECOND_KEY_MATERIAL",
      "-----END RSA PRIVATE KEY-----",
      "retrying",
    ].join("\n");

    expect(redactedErrorMessage(message)).toBe("[redacted]\nretrying");
  });

  test("preserves diagnostics after repeatedly serialized private keys", () => {
    let message: string | { pem: string; safe: string } = {
      pem: [
        "-----BEGIN RSA PRIVATE KEY-----",
        "SYNTHETIC_KEY_MATERIAL",
        "-----END RSA PRIVATE KEY-----",
      ].join("\n"),
      safe: "visible",
    };

    for (let depth = 1; depth <= 4; depth += 1) {
      message = JSON.stringify(message);
      let redacted: unknown = redactedErrorMessage(message);
      for (let layer = 0; layer < depth; layer += 1) {
        redacted = JSON.parse(redacted as string);
      }
      expect(redacted).toEqual({ pem: "[redacted]", safe: "visible" });
    }
  });

  test("preserves fields after pretty-printed private-key values", () => {
    const message = JSON.stringify(
      {
        nested: {
          pem: [
            "-----BEGIN RSA PRIVATE KEY-----",
            "SYNTHETIC_KEY_MATERIAL",
            "-----END RSA PRIVATE KEY-----",
          ].join("\n"),
          safe: "visible",
        },
        tail: "kept",
      },
      null,
      2,
    );

    expect(JSON.parse(redactedErrorMessage(message))).toEqual({
      nested: { pem: "[redacted]", safe: "visible" },
      tail: "kept",
    });
  });

  test("checks serialized newline depth after private-key delimiters", () => {
    const message = JSON.stringify({
      pem: [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----\\nSYNTHETIC_SECOND_KEY_MATERIAL",
        "-----END RSA PRIVATE KEY-----",
      ].join("\n"),
      safe: "visible",
    });

    expect(JSON.parse(redactedErrorMessage(message))).toEqual({
      pem: "[redacted]",
      safe: "visible",
    });
  });

  test("redacts unquoted credentials next to a private-key placeholder", () => {
    const message = [
      "password=SYNTHETIC_VICTIM_PASSWORD -----BEGIN RSA PRIVATE KEY-----",
      "SYNTHETIC_KEY_MATERIAL",
      "-----END RSA PRIVATE KEY-----",
    ].join("\n");

    expect(redactedErrorMessage(message)).toBe(
      "password=[redacted] [redacted]",
    );
  });

  test("redacts lowercase private-key assignments", () => {
    expect(
      redactedErrorMessage(
        "private_key=-----begin rsa private key-----\nSYNTHETIC_KEY\n-----end rsa private key----- safe=value",
      ),
    ).toBe("private_key=[redacted] safe=value");
  });

  test("collapses repeated truncated private-key markers", () => {
    expect(
      redactedErrorMessage("-----BEGIN PRIVATE KEY-----\n".repeat(1_000)),
    ).toBe("[redacted]");
  });

  test("redacts quoted credentials and private keys that overlap in either direction", () => {
    for (const [lines, credential] of [
      [
        [
          "-----BEGIN PRIVATE KEY-----",
          'password="',
          "-----END PRIVATE KEY-----",
          'SYNTHETIC_PASSWORD_123"',
        ],
        "SYNTHETIC_PASSWORD_123",
      ],
      [
        [
          'password="prefix',
          "-----BEGIN PRIVATE KEY-----",
          'synthetic-before"',
          "SYNTHETIC_KEY_MATERIAL_123",
          "-----END PRIVATE KEY-----",
        ],
        "SYNTHETIC_KEY_MATERIAL_123",
      ],
    ] as const) {
      const redacted = redactedErrorMessage(lines.join("\n"));
      expect(redacted).toContain("[redacted]");
      expect(redacted).not.toContain(credential);
      expect(redacted).not.toContain("PRIVATE KEY");
    }
  });
});
