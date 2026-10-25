import { runTestInSubprocess } from "./support/test-subprocess.js";
import { execFile } from "node:child_process";
import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { zstdCompressSync } from "node:zlib";
import { afterEach, beforeAll, expect, test } from "bun:test";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-scan-logs-node-",
);

afterEach(cleanup);

let moduleSource: string;
let costModuleSource: string;
beforeAll(async () => {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      "build",
      fileURLToPath(new URL("../src/scan-logs.ts", import.meta.url)),
      "--target=node",
      "--format=esm",
    ],
    { encoding: "utf8" },
  );
  moduleSource = stdout;
  costModuleSource = (
    await promisify(execFile)(
      process.execPath,
      [
        "build",
        fileURLToPath(new URL("../src/cost.ts", import.meta.url)),
        "--target=node",
        "--format=esm",
      ],
      { encoding: "utf8" },
    )
  ).stdout;
});

test.each(["native", "without zstd"])(
  "reads saved logs with Node's %s capabilities",
  async (capabilities) => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    const sessions = join(home, "sessions");
    await mkdir(sessions, { recursive: true });
    const parent = {
      type: "session_meta",
      payload: { id: "parent", cwd: root },
    };
    const worker = {
      type: "session_meta",
      payload: { id: "worker", parent_thread_id: "parent", cwd: root },
    };
    await writeFile(
      join(sessions, "rollout-parent.jsonl"),
      `${JSON.stringify(parent)}\n`,
    );
    const receipt = {
      type: "token_usage_record",
      payload: {
        response_id: "worker-response",
        thread_id: "worker",
        model: "gpt-5.6-sol",
        usage: { input_tokens: 1000, output_tokens: 0 },
      },
    };
    await writeFile(
      join(sessions, "rollout-worker.jsonl.zst"),
      zstdCompressSync(
        `${JSON.stringify(worker)}\n${JSON.stringify(receipt)}\n`,
      ),
    );

    const module = join(root, "scan-logs.mjs");
    await writeFile(module, moduleSource);
    const costModule = join(root, "cost.mjs");
    await writeFile(costModule, costModuleSource);
    const { stdout } = await promisify(execFile)(
      "node",
      [
        "--input-type=module",
        "--eval",
        `
          import zlib from "node:zlib";
          import { syncBuiltinESMExports } from "node:module";
          if (${JSON.stringify(capabilities)} === "without zstd") {
            delete zlib.createZstdDecompress;
            syncBuiltinESMExports();
          }
          const { findScanSession, readScanLogs } = await import(${JSON.stringify(pathToFileURL(module).href)});
          const home = ${JSON.stringify(home)};
          const { ScanCostTracker } = await import(${JSON.stringify(pathToFileURL(costModule).href)});
          const tracker = new ScanCostTracker({ codexHome: home, model: "gpt-5.6-sol" });
          tracker.start("parent");
          const usage = await tracker.stop({ input_tokens: 0, output_tokens: 0 });
          console.log(JSON.stringify({
            usage,
            compressed: typeof zlib.createZstdDecompress === "function",
            parent: await findScanSession(home, "parent"),
            worker: await findScanSession(home, "worker"),
            logs: await readScanLogs({ scanId: "scan-1", threadId: "parent", codexHome: home }),
          }));
        `,
      ],
      { encoding: "utf8" },
    );
    const result = JSON.parse(stdout);
    if (capabilities === "without zstd") {
      expect(result.compressed).toBe(false);
    }
    expect(result.parent).toMatchObject({
      threadId: "parent",
      workingDirectory: root,
    });
    expect(result.worker).toEqual(
      result.compressed
        ? expect.objectContaining({
            threadId: "worker",
            workingDirectory: root,
          })
        : null,
    );
    expect(result.usage.usage.input_tokens).toBe(result.compressed ? 1000 : 0);
    expect(result.usage.cost.estimatedUsd).toBeCloseTo(
      result.compressed ? 0.004 : 0,
      10,
    );
    expect(result.logs.events).toEqual([
      { threadId: "parent", event: parent },
      ...(result.compressed
        ? [
            { threadId: "worker", event: worker },
            { threadId: "worker", event: receipt },
          ]
        : []),
    ]);
  },
);

for (const directory of ["sessions", "archived_sessions"]) {
  const name = `Node reads recorded homes through directory links in ${directory}`;
  test(name, async () => {
    if (runTestInSubprocess(import.meta.path, name)) return;
    const root = await temporaryDirectory();
    const current = join(root, "current");
    const original = join(root, "original");
    await mkdir(current);
    await mkdir(join(original, "child"), { recursive: true });
    await mkdir(join(original, directory));
    const link = join(current, "original-home-link");
    const windows = process.platform === "win32";
    await symlink(
      windows ? original : join(original, "child"),
      link,
      windows ? "junction" : "dir",
    );
    const recorded = windows ? link : `${link}${sep}..`;
    const timestamp = "2026-08-11T12:01:00.000Z";
    const event = {
      type: "response_item",
      timestamp,
      payload: {
        type: "message",
        role: "assistant",
        content: [{ type: "output_text", text: "saved original activity" }],
      },
    };
    await writeFile(
      join(original, directory, "owner.jsonl"),
      [
        { type: "session_meta", payload: { id: "owner" } },
        { type: "turn_context", timestamp, payload: { turn_id: "scan-turn" } },
        event,
      ]
        .map((value) => JSON.stringify(value) + "\n")
        .join(""),
    );
    const built = await Bun.build({
      entrypoints: [
        fileURLToPath(new URL("../src/scan-logs.ts", import.meta.url)),
      ],
      target: "node",
      format: "esm",
    });
    expect(built.success).toBe(true);
    const modulePath = join(root, "scan-logs.mjs");
    await writeFile(modulePath, await built.outputs[0]!.text());
    const { stdout } = await promisify(execFile)("node", [
      "--input-type=module",
      "--eval",
      `
      import assert from "node:assert/strict";
      import { realpath } from "node:fs/promises";
      assert.equal(await realpath(${JSON.stringify(recorded)}), await realpath(${JSON.stringify(original)}));
      const { readSavedScanLogs } = await import(${JSON.stringify(pathToFileURL(modulePath).href)});
      const attribution = { formatVersion: 1, workerCodexHome: ${JSON.stringify(recorded)}, executionThreadIds: [],
        owner: { threadId: "owner", turnId: "scan-turn", startedAt: ${JSON.stringify(timestamp)} },
        startedAt: ${JSON.stringify(timestamp)}, completedAt: ${JSON.stringify(timestamp)},
      };
      const logs = await readSavedScanLogs({ scanId: "scan-1", mode: "deep", scanDir: ${JSON.stringify(root)}, continuationThreadId: "owner", executionAttribution: attribution }, ${JSON.stringify(current)});
      assert.equal(logs.sessions.length, 1);
      assert.equal(logs.sessions[0].path, ${JSON.stringify(join(original, directory, "owner.jsonl"))});
      assert.deepEqual(logs.events.at(-1).event, ${JSON.stringify(event)});
      assert.equal(attribution.workerCodexHome, ${JSON.stringify(recorded)});
      console.log("original logs recovered");
    `,
    ]);
    expect(stdout.trim()).toBe("original logs recovered");
  });
}
