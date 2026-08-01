import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

// The workbench writes every timestamp with a trailing "Z" (now()), but
// datetime.fromisoformat only accepts that suffix from Python 3.11 onward.
// This probe forces the pre-3.11 behavior on any interpreter so the lease
// check is exercised the way Python 3.10 would run it.
const leaseProbe = [
  "import json, sys",
  "from datetime import datetime, timedelta, timezone",
  "sys.path.insert(0, sys.argv[1])",
  "import workbench_db as workbench",
  "",
  "class LegacyDateTime(datetime):",
  "    @classmethod",
  "    def fromisoformat(cls, value):",
  "        if value.endswith(('Z', 'z')):",
  "            raise ValueError(f'Invalid isoformat string: {value!r}')",
  "        return datetime.fromisoformat(value)",
  "",
  "workbench.datetime = LegacyDateTime",
  "age = timedelta(seconds=int(sys.argv[2]))",
  "claimed_at = (datetime.now(timezone.utc) - age).isoformat().replace('+00:00', 'Z')",
  "row = {",
  "    'pending_action_claim_token': 'tok_abandoned',",
  "    'pending_action_delivered_at': None,",
  "    'pending_action_claimed_at': claimed_at,",
  "}",
  "print(json.dumps({",
  "    'claimedAt': claimed_at,",
  "    'leaseSeconds': workbench.CLAIM_LEASE_SECONDS,",
  "    'active': workbench.remediation_claim_is_active(row),",
  "}))",
].join("\n");

function runPythonProbe(
  program: string,
  ...args: string[]
): Record<string, unknown> {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) {
    throw new Error(
      "A Python interpreter is required for workbench lease tests.",
    );
  }

  const result = Bun.spawnSync(
    [python, "-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts"), ...args],
    { stdout: "pipe", stderr: "pipe" },
  );
  expect(new TextDecoder().decode(result.stderr)).toBe("");
  expect(result.exitCode).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout)) as Record<
    string,
    unknown
  >;
}

describe("bundled workbench remediation leases", () => {
  test("expires an abandoned claim when the interpreter cannot parse a trailing Z", () => {
    const expired = runPythonProbe(leaseProbe, "2592000"); // 30 days
    expect(expired["claimedAt"]).toMatch(/Z$/u);
    expect(expired["active"]).toBe(false);
  });

  test("keeps a fresh claim active when the interpreter cannot parse a trailing Z", () => {
    const fresh = runPythonProbe(leaseProbe, "0");
    expect(fresh["claimedAt"]).toMatch(/Z$/u);
    expect(fresh["active"]).toBe(true);
  });
});
