import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { zstdCompressSync } from "node:zlib";
import { afterEach, beforeAll, expect, test } from "bun:test";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-compressed-cost-node-",
);
afterEach(cleanup);

let moduleSource: string;
beforeAll(async () => {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      "build",
      fileURLToPath(new URL("../src/cost.ts", import.meta.url)),
      "--target=node",
      "--format=esm",
    ],
    { encoding: "utf8" },
  );
  moduleSource = stdout;
});

test.each([
  ["native", "ordinary"],
  ["native", "reverted"],
  ["without zstd", "ordinary"],
  ["without zstd", "reverted"],
] as const)(
  "accounts for archived worker costs with Node's %s capabilities: %s rollout",
  async (capabilities, layout) => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    const workerHome = join(root, "recorded-home");
    const sessions = join(home, "sessions");
    const archive = join(workerHome, "archived_sessions");
    await Promise.all([
      mkdir(sessions, { recursive: true }),
      mkdir(archive, { recursive: true }),
    ]);
    const at = "2026-09-01T00:00:02Z";
    const workerThreadId = "0198ff20-1b40-7000-8000-000000000001";
    const response = (
      threadId: string,
      responseId: string,
      inputTokens: number,
    ) => ({
      type: "token_usage_record",
      timestamp: at,
      payload: {
        thread_id: threadId,
        turn_id: "turn",
        response_id: responseId,
        model: "gpt-5.6-sol",
        usage: { input_tokens: inputTokens, output_tokens: 0 },
      },
    });
    const rollout = (threadId: string, inputTokens: number) =>
      [
        {
          type: "session_meta",
          payload: { id: threadId, timestamp: at, cwd: root },
        },
        response(threadId, `${threadId}-response`, inputTokens),
      ]
        .map((event) => JSON.stringify(event))
        .join("\n") + "\n";
    await writeFile(
      join(sessions, "rollout-parent.jsonl"),
      rollout("parent", 100),
    );
    const filename = `rollout-2026-09-01T00-00-02-${workerThreadId}${layout === "reverted" ? "_0198ff20-1b40-7000-8000-000000000002" : ""}.jsonl.zst`;
    const worker = join(archive, filename);
    await writeFile(worker, zstdCompressSync(rollout(workerThreadId, 1_000)));
    const extended = join(root, "extended.zst");
    await writeFile(
      extended,
      zstdCompressSync(
        rollout(workerThreadId, 1_000) +
          JSON.stringify(response(workerThreadId, "later-response", 500)) +
          "\n",
      ),
    );
    const module = join(root, "cost.mjs");
    await writeFile(module, moduleSource);
    const { stdout } = await promisify(execFile)(
      "node",
      [
        "--input-type=module",
        "--eval",
        `
      import zlib from "node:zlib";
      import { copyFile } from "node:fs/promises";
      import { syncBuiltinESMExports } from "node:module";
      if (${JSON.stringify(capabilities)} === "without zstd") {
        delete zlib.createZstdDecompress;
        syncBuiltinESMExports();
      }
      const { ScanCostTracker } = await import(${JSON.stringify(pathToFileURL(module).href)});
      const tracker = new ScanCostTracker({ codexHome: ${JSON.stringify(home)}, model: "gpt-5.6-sol", maxCostUsd: 0.003 });
      tracker.recordUsage({ input_tokens: 1, output_tokens: 0 }, ${JSON.stringify(workerThreadId)});
      tracker.setAttributionReader(async () => ({ formatVersion: 1, codexHome: ${JSON.stringify(workerHome)}, executionThreadIds: ["parent", ${JSON.stringify(workerThreadId)}], owner: { threadId: "parent", turnId: "turn", startedAt: ${JSON.stringify(at)} }, startedAt: ${JSON.stringify(at)}, completedAt: null }));
      tracker.start("parent");
      const snapshots = [];
      let error = null;
      try {
        snapshots.push(await tracker.refresh());
        snapshots.push(await tracker.refresh());
        await copyFile(${JSON.stringify(extended)}, ${JSON.stringify(worker)});
        snapshots.push(await tracker.refresh());
      } catch (caught) { error = caught.message; }
      finally { await tracker.stop().catch(() => {}); }
      console.log(JSON.stringify({ supported: typeof zlib.createZstdDecompress === "function", snapshots, error }));
    `,
      ],
      { encoding: "utf8" },
    );
    const result = JSON.parse(stdout);
    if (result.supported) {
      expect(result.error).toBeNull();
      expect(
        result.snapshots.map(
          (snapshot: { cost: { inputTokens: number } }) =>
            snapshot.cost.inputTokens,
        ),
      ).toEqual([1_100, 1_100, 1_600]);
      expect(result.snapshots[0].cost.estimatedUsd).toBeGreaterThan(0.003);
    } else {
      expect(result.snapshots).toEqual([]);
      expect(result.error).toContain("Cannot enforce the scan cost limit");
      expect(result.error).toContain(filename);
    }
  },
);
