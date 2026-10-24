import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import { dependencies } from "./cli-fixtures.js";
import { captureCli, createCliTest } from "./support/cli-run.js";
import { writeJsonLines } from "./support/json.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-observed-files-",
);
afterEach(cleanup);

async function writeSession(
  home: string,
  repository: string,
  threadId: string,
  paths: string[],
  parent?: string,
  timestamp = "2026-10-22T12:01:00Z",
  outputTimestamp = timestamp,
) {
  const directory = join(home, "sessions", "2026", "10", "22");
  await mkdir(directory, { recursive: true });
  await writeJsonLines(join(directory, `${threadId}.jsonl`), [
    {
      type: "session_meta",
      timestamp,
      payload: {
        id: threadId,
        cwd: repository,
        timestamp,
        ...(parent === undefined
          ? {}
          : {
              source: {
                subagent: { thread_spawn: { parent_thread_id: parent } },
              },
            }),
      },
    },
    {
      type: "event_msg",
      timestamp,
      payload: {
        type: "task_started",
        turn_id: `${threadId}-turn`,
        started_at: Date.parse(timestamp) / 1000,
      },
    },
    ...paths.flatMap((path, index) => [
      {
        type: "response_item",
        timestamp: outputTimestamp,
        payload: {
          type: "function_call",
          name: "exec_command",
          call_id: `call-${index}`,
          arguments: JSON.stringify({
            cmd: `cat ${path}`,
            workdir: repository,
          }),
        },
      },
      {
        type: "response_item",
        timestamp: outputTimestamp,
        payload: {
          type: "function_call_output",
          call_id: `call-${index}`,
          output:
            "Wall time: 0.01 seconds\nExit code: 0\nOutput:\nexport const fixture = 1;\n",
        },
      },
    ]),
  ]);
}

describe("scans show observed files", () => {
  test("preserves the saved count when observation storage fails", async () => {
    const directory = await temporaryDirectory();
    const repository = join(directory, "repository");
    const home = join(directory, "home");
    await writeSession(home, repository, "parent", ["src/read.ts"]);
    const cli = createCliTest(main);
    const code = await cli.runCli(
      ["scans", "show", "scan-example", "--json"],
      dependencies({
        environment: {
          CODEX_HOME: home,
          CODEX_SECURITY_STATE_DIR: join(directory, "state"),
        },
        onWorkbench: (args) => {
          if (args[0] === "record-observed-files")
            throw new Error("database is locked");
          return {
            scan: {
              scanId: "scan-example",
              targetPath: repository,
              startedAt: "2026-10-22T12:00:00Z",
              continuationThreadId: "parent",
              observedFilesRead: {
                count: 7,
                observedAt: "2026-10-22T12:01:00Z",
              },
            },
          };
        },
      }),
    );
    expect(code).toBe(0);
    expect(JSON.parse(cli.stdout.text()).observedFilesRead.count).toBe(7);
    expect(cli.stderr.text()).toContain(
      "Could not update observed files read: database is locked",
    );
  });

  test.each([true, false])(
    "persists a parent/worker union and keeps it when logs disappear (dedicated=%p)",
    async (dedicated) => {
      const directory = await temporaryDirectory();
      const home = join(directory, "home");
      const repository = join(directory, "repository");
      await writeSession(home, repository, "parent", ["src/shared.ts"]);
      await writeSession(
        home,
        repository,
        "worker",
        ["src/shared.ts", "src/worker.ts"],
        "parent",
      );
      await writeSession(
        home,
        repository,
        "earlier-worker",
        ["src/unrelated.ts"],
        "parent",
        "2026-10-22T11:59:00Z",
        "2026-10-22T12:02:00Z",
      );
      await writeSession(
        home,
        repository,
        "later-worker",
        ["src/unrelated.ts"],
        "parent",
        "2026-10-22T12:06:00Z",
      );
      const scan: JsonObject = {
        scanId: "scan-example",
        targetPath: repository,
        startedAt: "2026-10-22T12:00:00Z",
        completedAt: "2026-10-22T12:05:00Z",
        continuationThreadId: "parent",
        executionThreadIds: dedicated ? ["parent"] : [],
        progress: { status: "complete", updatedAt: "2026-10-22T12:05:00Z" },
        observedFilesRead: { count: null, observedAt: null },
      };
      const evidence = new Map<string, unknown>();
      let writes = 0;
      const deps = dependencies({
        environment: {
          CODEX_HOME: home,
          CODEX_SECURITY_STATE_DIR: join(directory, "state"),
        },
        onWorkbench: (args, input) => {
          if (args[0] === "get-scan") return { scan };
          expect(args).toEqual([
            "record-observed-files",
            "--scan-id",
            "scan-example",
          ]);
          writes += 1;
          for (const file of JSON.parse(input!).files)
            evidence.set(file.path, file);
          scan["observedFilesRead"] = {
            count: evidence.size,
            observedAt: "2026-10-22T12:06:00Z",
          };
          return scan["observedFilesRead"] as JsonObject;
        },
      });
      for (let iteration = 0; iteration < 2; iteration += 1) {
        const stdout = captureCli(main, "stdout");
        expect(
          await stdout.run(["scans", "show", "scan-example", "--json"], deps),
        ).toBe(0);
        expect(JSON.parse(stdout.text()).observedFilesRead.count).toBe(2);
      }
      expect([...evidence.keys()].sort()).toEqual([
        "src/shared.ts",
        "src/worker.ts",
      ]);
      expect(writes).toBe(2);
      await rm(join(home, "sessions"), { recursive: true });
      const stdout = captureCli(main, "stdout");
      expect(
        await stdout.run(["scans", "show", "scan-example", "--json"], deps),
      ).toBe(0);
      expect(JSON.parse(stdout.text()).observedFilesRead.count).toBe(2);
      expect(writes).toBe(2);
    },
  );

  test("keeps missing observations unavailable without failing show", async () => {
    const directory = await temporaryDirectory();
    const stdout = captureCli(main, "stdout");
    expect(
      await stdout.run(
        ["scans", "show", "scan-example", "--json"],
        dependencies({
          environment: {
            CODEX_HOME: join(directory, "home"),
            CODEX_SECURITY_STATE_DIR: join(directory, "state"),
          },
          onWorkbench: () => ({
            scan: {
              scanId: "scan-example",
              targetPath: join(directory, "repository"),
              startedAt: "2026-10-22T12:00:00Z",
              continuationThreadId: "parent",
              observedFilesRead: { count: null, observedAt: null },
            },
          }),
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text()).observedFilesRead.count).toBeNull();
  });
});
