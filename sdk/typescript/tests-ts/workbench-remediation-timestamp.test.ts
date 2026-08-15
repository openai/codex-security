import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const remediationLeaseProbe = [
  "import json, sqlite3, sys",
  "from datetime import datetime, timezone",
  "sys.path.insert(0, sys.argv[1])",
  "import workbench_remediation as remediation",
  "",
  "class Python310DateTime(datetime):",
  "    @classmethod",
  "    def fromisoformat(cls, value):",
  "        if value.endswith(('Z', 'z')):",
  "            raise ValueError(f'Invalid isoformat string: {value!r}')",
  "        return datetime.fromisoformat(value)",
  "",
  "    @classmethod",
  "    def now(cls, tz=None):",
  "        return datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)",
  "",
  "remediation.datetime = Python310DateTime",
  "case = json.loads(sys.argv[2])",
  "connection = sqlite3.connect(':memory:')",
  "connection.row_factory = sqlite3.Row",
  "row = connection.execute('SELECT ? AS pending_action_claim_token, ? AS pending_action_delivered_at, ? AS pending_action_claimed_at', (case.get('token'), case.get('deliveredAt'), case.get('claimedAt'))).fetchone()",
  "print(json.dumps({'active': remediation.remediation_claim_is_active(row)}))",
].join("\n");

interface RemediationClaim {
  token: string;
  claimedAt?: string;
  deliveredAt?: string;
}

function isClaimActive(claim: RemediationClaim): boolean {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) {
    throw new Error("A Python interpreter is required for remediation tests.");
  }

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
  expect(new TextDecoder().decode(result.stderr)).toBe("");
  expect(result.exitCode).toBe(0);
  return (
    JSON.parse(new TextDecoder().decode(result.stdout)) as {
      active: boolean;
    }
  ).active;
}

describe("workbench remediation timestamps on Python 3.10", () => {
  test.each([
    {
      description: "an abandoned Z-suffixed claim",
      claim: { token: "abandoned", claimedAt: "2026-08-15T11:57:59Z" },
    },
    {
      description: "an abandoned lowercase-z claim",
      claim: { token: "abandoned", claimedAt: "2026-08-15T11:57:59z" },
    },
    {
      description: "an abandoned delivered action",
      claim: {
        token: "abandoned",
        claimedAt: "2026-08-15T11:30:00Z",
        deliveredAt: "2026-08-15T11:44:59Z",
      },
    },
  ])("expires $description", ({ claim }) => {
    expect(isClaimActive(claim)).toBe(false);
  });

  test.each([
    {
      description: "a fresh claim",
      claim: { token: "active", claimedAt: "2026-08-15T11:58:01Z" },
    },
    {
      description: "a fresh delivery after an older claim",
      claim: {
        token: "active",
        claimedAt: "2026-08-15T11:30:00Z",
        deliveredAt: "2026-08-15T11:45:01Z",
      },
    },
  ])("preserves $description", ({ claim }) => {
    expect(isClaimActive(claim)).toBe(true);
  });
});
