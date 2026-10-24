import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { lstat, readFile, symlink, utimes, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import {
  coordinatorFixture,
  FakeExecutor,
  recordingClock,
  runCoordinator,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";

test(
  "same-thread retry snapshots retain evidence and omit non-copyable FIFOs",
  { skip: process.platform === "win32" },
  async () => {
    const { fixture, store } = await coordinatorFixture();
    const executor = new FakeExecutor({ invalidDiscoveryAttempts: 1 });
    const execute = executor.run.bind(executor);
    const savedTime = new Date("2020-01-02T03:04:05.000Z");
    const contents = "Synthetic saved analysis.\n";
    executor.run = async (request) => {
      if (request.kind === "discovery") {
        const note = path.join(request.workingDirectory, "saved-analysis.txt");
        if (request.resumeThreadId) {
          assert.equal(await readFile(note, "utf8"), contents);
          assert.equal((await lstat(note)).mtimeMs, savedTime.getTime());
        } else {
          await writeFile(note, contents);
          await utimes(note, savedTime, savedTime);
          await symlink(
            "saved-analysis.txt",
            path.join(request.workingDirectory, "analysis-link"),
          );
          execFileSync("mkfifo", [
            path.join(request.workingDirectory, "worker.pipe"),
          ]);
        }
      }
      return execute(request);
    };
    try {
      const terminal = await runCoordinator(fixture, store, executor, {
        random: () => 0,
        retryDelaysMs: [1],
        clock: recordingClock([]),
      });
      assert.equal(terminal?.status, "succeeded");
      assert.deepEqual(executor.discoveryResumeThreadIds, [
        undefined,
        executor.discoveryThreadIds[0],
      ]);
      assert.equal(executor.discoveryWorkingDirectories.size, 1);
      const workspace = [...executor.discoveryWorkingDirectories][0]!;
      const archive = path.join(path.dirname(workspace), "attempts/attempt-01");
      for (const directory of [workspace, archive]) {
        assert.equal(
          await readFile(path.join(directory, "saved-analysis.txt"), "utf8"),
          contents,
        );
        assert.equal(
          (await lstat(path.join(directory, "saved-analysis.txt"))).mtimeMs,
          savedTime.getTime(),
        );
        assert.ok(
          (await lstat(path.join(directory, "analysis-link"))).isSymbolicLink(),
        );
        assert.equal(
          await readFile(path.join(directory, "analysis-link"), "utf8"),
          contents,
        );
      }
      const resumedContents = "Synthetic resumed analysis.\n";
      await writeFile(
        path.join(workspace, "saved-analysis.txt"),
        resumedContents,
      );
      assert.equal(
        await readFile(path.join(workspace, "analysis-link"), "utf8"),
        resumedContents,
      );
      assert.equal(
        await readFile(path.join(archive, "saved-analysis.txt"), "utf8"),
        contents,
      );
      assert.equal(
        await readFile(path.join(archive, "analysis-link"), "utf8"),
        contents,
      );
      assert.ok((await lstat(path.join(workspace, "worker.pipe"))).isFIFO());
      await assert.rejects(lstat(path.join(archive, "worker.pipe")), {
        code: "ENOENT",
      });
    } finally {
      await temporaryDirectories.cleanup();
    }
  },
);
