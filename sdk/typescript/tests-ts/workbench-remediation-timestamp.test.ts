import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const remediationLeaseProbe = `
import json, sys
from datetime import datetime, timezone
sys.path.insert(0, sys.argv[1])
import workbench_remediation as remediation

class Python310DateTime(datetime):
    @classmethod
    def fromisoformat(cls, value):
        if value.endswith(("Z", "z")):
            raise ValueError("Python 3.10 rejects Z-suffixed timestamps")
        return datetime.fromisoformat(value)

    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)

remediation.datetime = Python310DateTime
case = json.loads(sys.argv[2])
print(json.dumps(remediation.remediation_claim_is_active({
    "pending_action_claim_token": case.get("token"),
    "pending_action_delivered_at": case.get("deliveredAt"),
    "pending_action_claimed_at": case.get("claimedAt"),
})))
`;

interface RemediationClaim {
  token: string | null;
  claimedAt?: string;
  deliveredAt?: string;
}

function isClaimActive(claim: RemediationClaim): boolean {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");

  const result = Bun.spawnSync(
    [
      python,
      "-I",
      "-B",
      "-c",
      remediationLeaseProbe,
      join(PLUGIN_ROOT, "scripts"),
      JSON.stringify(claim),
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
  expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout)) as boolean;
}

describe("workbench remediation timestamps on Python 3.10", () => {
  test.each([
    [
      "expires at the claim deadline",
      { claimedAt: "2026-08-15T11:58:00Z" },
      false,
    ],
    ["accepts lowercase UTC", { claimedAt: "2026-08-15T11:58:00z" }, false],
    [
      "preserves explicit offsets",
      { claimedAt: "2026-08-15T13:58:00+02:00" },
      false,
    ],
    ["keeps a fresh claim", { claimedAt: "2026-08-15T11:58:01Z" }, true],
    [
      "expires at the delivery deadline",
      {
        claimedAt: "2026-08-15T11:30:00Z",
        deliveredAt: "2026-08-15T11:45:00Z",
      },
      false,
    ],
    [
      "keeps a fresh delivery after an older claim",
      {
        claimedAt: "2026-08-15T11:30:00Z",
        deliveredAt: "2026-08-15T11:45:01Z",
      },
      true,
    ],
    ["has no claim without a token", { token: null }, false],
    ["preserves an invalid timestamp", { claimedAt: "not-a-timestamp" }, true],
    ["preserves a naive timestamp", { claimedAt: "2026-08-15T11:00:00" }, true],
  ] as const)("%s", (_label, fields, active) => {
    expect(isClaimActive({ token: "claim", ...fields })).toBe(active);
  });
});
