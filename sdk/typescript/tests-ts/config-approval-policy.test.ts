import { describe, expect, test } from "bun:test";
import { scanApprovalPolicy } from "../src/config.js";

describe("scan approval policy", () => {
  test("lets the selected profile override the root approval policy", () => {
    expect(
      scanApprovalPolicy({
        approval_policy: "never",
        profile: "interactive",
        profiles: {
          interactive: { approval_policy: "on-request" },
        },
      }),
    ).toBe("on-request");

    expect(
      scanApprovalPolicy({
        approval_policy: "on-request",
        profile: "unattended",
        profiles: {
          unattended: { approval_policy: "never" },
        },
      }),
    ).toBe("never");
  });

  test("falls back to the root policy when the profile does not set one", () => {
    expect(
      scanApprovalPolicy({
        approval_policy: "never",
        profile: "review",
        profiles: { review: { model: "gpt-5.6-terra" } },
      }),
    ).toBe("never");
  });
});
