import { expect, test } from "bun:test";
import { join } from "node:path";
import { stripVTControlCharacters } from "node:util";
import { createDependencyProgress } from "../src/dependency-progress.js";

test.each([false, true])(
  "aligns elapsed time and content across progress rows (interactive=%s)",
  (interactive) => {
    let now = 0;
    const writes: string[] = [];
    const progress = createDependencyProgress({
      output: { write: (text) => writes.push(text), columns: 90 },
      now: () => now,
      interactive,
      color: interactive,
    });
    const subject = "CVE-2024-1000";
    const path = join("some  folder", "output".repeat(20), "report.json");
    try {
      progress.emit({ type: "started", subject, checkout: "example" });
      now = 1_200;
      progress.emit({ type: "stage", subject, stage: "osv" });
      progress.emit({
        type: "advisories_loaded",
        subject,
        count: 2,
      });
      now = 2_040;
      progress.emit({
        type: "advisory_summary",
        subject,
        summary: "The decoder accepts malformed input.",
      });
      progress.emit({ type: "stage", subject, stage: "investigate" });
      progress.emit({ type: "access_program", subject, program: "standard" });
      progress.emit({
        type: "proposed_sink",
        subject,
        function: "decode",
        origin: "advisory_record",
      });
      now = 19_900;
      const finish = progress.begin(subject, "opengrep", {
        files: ["src/reader.ts"],
      });
      finish("returned", ["src/helpers"]);
      now = 20_050;
      progress.emit({ type: "stage", subject, stage: "review" });
      now = 21_000;
      progress.emit({
        type: "reviewed",
        subject,
        location: "src/reader.ts:42",
        locationKind: "caller",
        verdict: "ruled_out",
        reason: "Input is validated.",
        component: "decoder",
      });
      progress.emit({ type: "assessment_finished", subject, uses: 1 });
      progress.emit({
        type: "report_ready",
        subject,
        verdicts: {
          ruled_out: 1,
          unknown: 0,
          potentially_exploitable: 0,
          exploitable: 0,
        },
        limitations: 1,
        path,
      });
      progress.emit({ type: "finished", subject, outcome: "completed" });
    } finally {
      progress.close();
    }

    const output = writes.map(stripVTControlCharacters).join("");
    const rows = output.split("\n").flatMap((line) => {
      const row = line.split("\r").at(-1)!;
      return /^.\s+\d+:\d{2}  \S/u.test(row) ? [row] : [];
    });
    expect(
      rows.map((row) => [row[0], row.slice(1, 10).trim(), row.slice(10)]),
    ).toEqual([
      ["›", "0:00", "Preparing the checkout"],
      ["›", "0:01", "Looking up advisories in OSV"],
      ["✓", "0:01", "Loaded 2 advisory records"],
      ["·", "0:02", "Advisory   The decoder accepts malformed input."],
      ["›", "0:02", "Starting source investigation"],
      ["!", "0:02", "WARNING: DAYBREAK IS NOT ACTIVE"],
      ["·", "0:02", "Sink       decode · named by advisory"],
      ["›", "0:19", "Searching with OpenGrep · src/reader.ts"],
      ["✓", "0:19", "Searched   src/helpers"],
      ["›", "0:20", "Reviewing evidence"],
      ["◆", "0:21", "RULED OUT  src/reader.ts:42"],
      ["✓", "0:21", "Investigation summary · 1 reviewed use"],
    ]);
    expect(output).toContain("\n            Input is validated.\n");
    expect(output).toContain(
      `1 ruled out\n          1 limitation in the report\n          Report saved  ${path}\n`,
    );
    const liveSearch = writes
      .map(stripVTControlCharacters)
      .find((chunk) => /^\r\S\s+0:19  Searching with OpenGrep/u.test(chunk));
    expect(Boolean(liveSearch)).toBe(interactive);
  },
);
