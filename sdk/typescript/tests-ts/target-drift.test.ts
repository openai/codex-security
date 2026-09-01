import { describe, expect, test } from "bun:test";
import { startHeadDriftMonitor } from "../src/target-drift.js";

describe("head drift monitor", () => {
  test("warns once after the repository revision changes", async () => {
    const controller = new AbortController();
    let revision = "before";
    const warnings: string[] = [];
    const monitor = startHeadDriftMonitor({
      expectedRevision: "before",
      readRevision: async () => revision,
      signal: controller.signal,
      onDrift: () => warnings.push("changed"),
      intervalMs: 60_000,
    });

    try {
      await monitor.ready;
      expect(warnings).toEqual([]);

      revision = "after";
      await monitor.check();
      await monitor.check();

      expect(warnings).toEqual(["changed"]);
    } finally {
      monitor.stop();
    }
  });

  test("ignores an unavailable revision and stops cleanly", async () => {
    const controller = new AbortController();
    const warnings: string[] = [];
    const monitor = startHeadDriftMonitor({
      expectedRevision: "before",
      readRevision: async () => null,
      signal: controller.signal,
      onDrift: () => warnings.push("changed"),
      intervalMs: 60_000,
    });

    await monitor.ready;
    monitor.stop();
    await monitor.check();

    expect(warnings).toEqual([]);
  });
});
