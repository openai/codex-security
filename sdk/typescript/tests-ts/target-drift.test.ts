import { afterEach, describe, expect, test } from "bun:test";
import { repositoryRevision } from "../src/targets.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { gitText } from "./support/shell.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures("target-drift-");
afterEach(cleanup);
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
  test.each(["stop", "abort"] as const)(
    "%s cancels an in-flight revision read",
    async (operation) => {
      const parent = new AbortController();
      const started = Promise.withResolvers<AbortSignal>();
      const cancelled = Promise.withResolvers<unknown>();
      let warnings = 0;
      const monitor = startHeadDriftMonitor({
        expectedRevision: "before",
        signal: parent.signal,
        readRevision: (signal) => {
          started.resolve(signal);
          return new Promise((_resolve, reject) => {
            signal.addEventListener(
              "abort",
              () => {
                cancelled.resolve(signal.reason);
                reject(signal.reason);
              },
              { once: true },
            );
          });
        },
        onDrift: () => {
          warnings++;
        },
      });
      try {
        const signal = await started.promise;
        const reason = new Error("Synthetic scan cancellation");
        if (operation === "stop") monitor.stop();
        else parent.abort(reason);
        const actualReason = await cancelled.promise;
        await monitor.ready;
        expect(signal.aborted).toBe(true);
        if (operation === "abort") expect(actualReason).toBe(reason);
        else expect(parent.signal.aborted).toBe(false);
        await monitor.check();
        expect(warnings).toBe(0);
      } finally {
        monitor.stop();
      }
    },
  );

  test("retries failed reads without overlapping them and ignores observer failure", async () => {
    const parent = new AbortController();
    const first = Promise.withResolvers<string | null>();
    let reads = 0;
    let warnings = 0;
    const monitor = startHeadDriftMonitor({
      expectedRevision: "before",
      signal: parent.signal,
      intervalMs: 60_000,
      readRevision: async () => {
        reads++;
        if (reads === 1) return first.promise;
        return "after";
      },
      onDrift: () => {
        warnings++;
        throw new Error("Synthetic observer failure");
      },
    });
    try {
      await monitor.check();
      expect(reads).toBe(1);
      first.reject(new Error("Synthetic transient Git failure"));
      await monitor.ready;
      await monitor.check();
      await monitor.check();
      expect(reads).toBe(2);
      expect(warnings).toBe(1);
    } finally {
      monitor.stop();
    }
  });

  test("detects a real Git HEAD change", async () => {
    const repository = await temporaryDirectory();
    gitText(["init", "-q"], { cwd: repository });
    const commit = () =>
      gitText(
        [
          "-c",
          "user.name=Synthetic Test",
          "-c",
          "user.email=synthetic@example.com",
          "commit",
          "--allow-empty",
          "-qm",
          "Synthetic revision",
        ],
        { cwd: repository },
      );
    commit();
    const expectedRevision = await repositoryRevision(repository);
    expect(expectedRevision).not.toBeNull();
    let warnings = 0;
    const monitor = startHeadDriftMonitor({
      expectedRevision: expectedRevision!,
      readRevision: (signal) => repositoryRevision(repository, signal),
      signal: new AbortController().signal,
      intervalMs: 60_000,
      onDrift: () => {
        warnings++;
      },
    });
    try {
      await monitor.ready;
      expect(warnings).toBe(0);
      commit();
      await monitor.check();
      expect(warnings).toBe(1);
    } finally {
      monitor.stop();
    }
  });
});
