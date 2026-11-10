import { describe, expect, test } from "bun:test";
import { scanApprovalPolicy } from "../src/config.js";

describe("scan approval policy", () => {
  test("lets the selected profile override the root approval policy", () => {
    expect(
      scanApprovalPolicy({
        approval_policy: "never",
        profile: "review",
        profiles: {
          review: { approval_policy: "on-request" },
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

  test.each([undefined, null])(
    "falls back to the root policy when the profile policy is %p",
    (policy) => {
      expect(
        scanApprovalPolicy({
          approval_policy: "never",
          profile: "review",
          profiles: {
            review: policy === undefined ? {} : { approval_policy: policy },
          },
        }),
      ).toBe("never");
    },
  );

  test("ignores unselected profiles and preserves the default policy", () => {
    expect(
      scanApprovalPolicy({
        profiles: { unattended: { approval_policy: "never" } },
      }),
    ).toBe("on-request");
  });
});
