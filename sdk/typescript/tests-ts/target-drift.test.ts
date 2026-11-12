import { afterEach, describe, expect, jest, test } from "bun:test";
import { startHeadDriftMonitor } from "../src/target-drift.js";
import { repositoryRevision } from "../src/targets.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { gitText } from "./support/shell.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures("target-drift-");
afterEach(cleanup);

describe("head drift monitor", () => {
  test.each(["stop", "abort"] as const)(
    "%s cancels an in-flight revision read",
    async (operation) => {
      const parent = new AbortController();
      const started = Promise.withResolvers<AbortSignal>();
      const cancelled = Promise.withResolvers<unknown>();
      let warnings = 0;
      const stop = startHeadDriftMonitor({
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
        if (operation === "stop") stop();
        else parent.abort(reason);
        const actualReason = await cancelled.promise;
        expect(signal.aborted).toBe(true);
        if (operation === "abort") expect(actualReason).toBe(reason);
        else expect(parent.signal.aborted).toBe(false);
        expect(warnings).toBe(0);
      } finally {
        stop();
      }
    },
  );

  test("retries failed reads without overlapping them and ignores observer failure", async () => {
    const parent = new AbortController();
    jest.useFakeTimers();
    const first = Promise.withResolvers<string | null>();
    const revisions = [first.promise, null, "before", "after"];
    let reads = 0;
    let warnings = 0;
    const stop = startHeadDriftMonitor({
      expectedRevision: "before",
      signal: parent.signal,
      readRevision: () => Promise.resolve(revisions[reads++]!),
      onDrift: () => {
        warnings++;
        throw new Error("Synthetic observer failure");
      },
    });
    try {
      jest.advanceTimersByTime(5_000);
      expect(reads).toBe(1);
      first.reject(new Error("Synthetic transient Git failure"));
      await Promise.resolve();
      const nextPoll = async () => {
        jest.advanceTimersByTime(1_000);
        await Promise.resolve();
      };
      await nextPoll(); // Missing revision.
      await nextPoll(); // Unchanged revision.
      expect(warnings).toBe(0);
      await nextPoll(); // Changed revision.
      jest.advanceTimersByTime(5_000);
      expect(reads).toBe(4);
      expect(warnings).toBe(1);
    } finally {
      stop();
      jest.useRealTimers();
    }
  });

  test("warns after a real Git HEAD change", async () => {
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
    const warned = Promise.withResolvers<void>();
    const stop = startHeadDriftMonitor({
      expectedRevision: expectedRevision!,
      readRevision: (signal) => repositoryRevision(repository, signal),
      signal: new AbortController().signal,
      onDrift: () => warned.resolve(),
    });
    try {
      commit();
      await warned.promise;
    } finally {
      stop();
    }
  });
});
