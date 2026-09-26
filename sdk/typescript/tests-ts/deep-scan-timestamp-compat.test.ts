import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const timestampProbe = `
import json, sqlite3, sys, tempfile
from datetime import datetime as native_datetime
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import deep_scan_workbench as deep_scan

class Python310Datetime:
    @staticmethod
    def fromisoformat(value):
        if isinstance(value, str) and value.endswith(("Z", "z")):
            raise ValueError("Python 3.10 rejects Z-suffixed timestamps")
        return native_datetime.fromisoformat(value)

if sys.version_info >= (3, 11):
    deep_scan.datetime = Python310Datetime
case = json.loads(sys.argv[2])
deep_scan.now = lambda: case["now"]
connection = sqlite3.connect(":memory:")
connection.execute("CREATE TABLE deep_scan_workers (scan_id TEXT, status TEXT)")
if case.get("activeWorker"):
    connection.execute("INSERT INTO deep_scan_workers VALUES ('scan', 'running')")
run = {
    "scan_id": "scan",
    "created_at": case.get("createdAt"),
    "updated_at": case.get("updatedAt"),
    "max_time_hours": case.get("maxTimeHours"),
    "coordinator_generation": case.get("generation", 1),
}
with tempfile.TemporaryDirectory() as scan_dir:
    if "heartbeat" in case:
        heartbeat_path = Path(scan_dir) / "artifacts" / "deep_discovery" / f"coordinator-heartbeat-{run['coordinator_generation']}.json"
        heartbeat_path.parent.mkdir(parents=True)
        heartbeat_path.write_text(json.dumps(case["heartbeat"]), encoding="utf-8")
    if case["operation"] == "deadline":
        result = deep_scan.deep_scan_deadline_reached(run)
    else:
        result = deep_scan.coordinator_lease_is_live(connection, run, {"scan_dir": scan_dir}, case["now"])
    print(json.dumps(result))
`;

interface TimestampProbe {
  operation: "deadline" | "coordinator";
  now: string;
  createdAt?: string;
  updatedAt?: string;
  maxTimeHours?: number;
  generation?: number;
  activeWorker?: boolean;
  heartbeat?: { coordinatorGeneration: number; updatedAt: unknown };
}

function runTimestampProbe(probe: TimestampProbe): boolean {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");

  const result = Bun.spawnSync(
    [
      python,
      "-I",
      "-B",
      "-c",
      timestampProbe,
      join(PLUGIN_ROOT, "scripts"),
      JSON.stringify(probe),
    ],
    { stdout: "pipe", stderr: "pipe" },
  );

  expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout)) as boolean;
}

describe("Python 3.10 Deep Scan timestamps", () => {
  test.each([
    [
      "before the deadline",
      "2026-08-15T00:00:00Z",
      "2026-08-15T00:59:59Z",
      false,
    ],
    ["at the deadline", "2026-08-15T00:00:00Z", "2026-08-15T01:00:00Z", true],
    [
      "with lowercase UTC suffixes",
      "2026-08-15T00:00:00z",
      "2026-08-15T01:00:00z",
      true,
    ],
    [
      "with explicit UTC offsets",
      "2026-08-15T02:00:00+02:00",
      "2026-08-15T01:00:00Z",
      true,
    ],
  ] as const)("evaluates timestamps %s", (_label, createdAt, now, reached) => {
    expect(
      runTimestampProbe({
        operation: "deadline",
        createdAt,
        maxTimeHours: 1,
        now,
      }),
    ).toBe(reached);
  });

  test.each([
    ["fresh legacy", 1, "2026-08-15T00:09:59Z", true],
    ["expired legacy", 1, "2026-08-15T00:08:00Z", false],
    ["fresh current", 2, "2026-08-15T00:09:59Z", true],
    ["expired current", 2, "2026-08-15T00:09:30Z", false],
  ] as const)(
    "evaluates %s coordinator leases",
    (_label, generation, updatedAt, live) => {
      expect(
        runTimestampProbe({
          operation: "coordinator",
          generation,
          activeWorker: generation === 1,
          updatedAt,
          now: "2026-08-15T00:10:00Z",
        }),
      ).toBe(live);
    },
  );

  test.each([
    ["current", 2, "2026-08-15T00:09:45Z", true],
    ["older generation", 1, "2026-08-15T00:09:45Z", false],
    ["invalid", 2, null, false],
  ] as const)(
    "uses the %s coordinator heartbeat",
    (_label, coordinatorGeneration, updatedAt, live) => {
      expect(
        runTimestampProbe({
          operation: "coordinator",
          generation: 2,
          updatedAt: "2026-08-15T00:09:00Z",
          now: "2026-08-15T00:10:00Z",
          heartbeat: { coordinatorGeneration, updatedAt },
        }),
      ).toBe(live);
    },
  );
});
