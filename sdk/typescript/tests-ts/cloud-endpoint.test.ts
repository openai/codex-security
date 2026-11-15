import { describe, expect, test } from "bun:test";
import {
  cloudBaseUrl,
  cloudPublishUrl,
  DEFAULT_CLOUD_BASE_URL,
} from "../src/cloud-endpoint.js";

describe("cloudPublishUrl", () => {
  test("defaults to the configured Cloud base findings path", () => {
    expect(cloudPublishUrl({})).toBe(`${DEFAULT_CLOUD_BASE_URL}/cli/findings`);
    expect(cloudPublishUrl({ CODEX_SECURITY_CLOUD_PUBLISH_URL: "   " })).toBe(
      `${DEFAULT_CLOUD_BASE_URL}/cli/findings`,
    );
    expect(
      cloudPublishUrl({
        CODEX_SECURITY_CLOUD_BASE_URL:
          "https://cloud.example.test/backend-api/aardvark/",
      }),
    ).toBe("https://cloud.example.test/backend-api/aardvark/cli/findings");
  });

  test("keeps a valid publish override on a different host", () => {
    expect(
      cloudPublishUrl({
        CODEX_SECURITY_CLOUD_PUBLISH_URL:
          "https://other-cloud.example.test/publish",
      }),
    ).toBe("https://other-cloud.example.test/publish");
  });

  test("accepts a loopback HTTP publish override", () => {
    for (const publishUrl of [
      "http://localhost:8080/publish",
      "http://127.1.2.3:8080/publish",
      "http://[::1]:8080/publish",
    ]) {
      expect(
        cloudPublishUrl({
          CODEX_SECURITY_CLOUD_PUBLISH_URL: publishUrl,
        }),
      ).toBe(publishUrl);
    }
  });

  test("rejects a publish override that violates the Cloud transport rules", () => {
    for (const [publishUrl, message] of [
      ["http://cloud.example.test/publish", "requires HTTPS"],
      ["https://user:secret@cloud.example.test/publish", "without credentials"],
      ["https://cloud.example.test/publish?token=1", "without credentials"],
      ["https://cloud.example.test/publish#fragment", "without credentials"],
      ["ftp://cloud.example.test/publish", "without credentials"],
      ["not a url", "absolute HTTP(S)"],
    ] as const) {
      expect(() =>
        cloudPublishUrl({
          CODEX_SECURITY_CLOUD_PUBLISH_URL: publishUrl,
        }),
      ).toThrow(message);
    }
  });

  test("applies base URL validation when no publish override is set", () => {
    expect(() =>
      cloudPublishUrl({
        CODEX_SECURITY_CLOUD_BASE_URL:
          "http://cloud.example.test/backend-api/aardvark",
      }),
    ).toThrow("CODEX_SECURITY_CLOUD_BASE_URL requires HTTPS");
    expect(cloudBaseUrl({})).toBe(DEFAULT_CLOUD_BASE_URL);
  });
});
