import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { constants, zstdCompressSync } from "node:zlib";
import { afterEach, expect, test } from "bun:test";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

for (const decoder of ["available", "portable"] as const) {
  const name = `Node cost accounting preserves owned compressed receipts with the ${decoder} decoder`;
  test(name, async () => {
    if (runTestInSubprocess(import.meta.path, name)) return;
    const root = await temporaryDirectory();
    const built = await Bun.build({
      entrypoints: [fileURLToPath(new URL("../src/cost.ts", import.meta.url))],
      target: "node",
      format: "cjs",
    });
    expect(built.success).toBe(true);
    const modulePath = join(root, "cost.cjs");
    await writeFile(modulePath, await built.outputs[0]!.text());
    const lines = (values: unknown[]) =>
      values.map((value) => JSON.stringify(value) + "\n").join("");
    const before = lines([
      {
        type: "session_meta",
        payload: { id: "root", timestamp: "2026-07-26T12:00:00Z", cwd: root },
      },
      {
        type: "event_msg",
        payload: {
          type: "token_count",
          info: { total_token_usage: { input_tokens: 100, output_tokens: 10 } },
        },
      },
      { type: "event_msg", payload: { type: "task_complete" } },
    ]);
    const after = lines([
      {
        type: "event_msg",
        payload: {
          type: "token_count",
          info: { total_token_usage: { input_tokens: 150, output_tokens: 15 } },
        },
      },
      { type: "event_msg", payload: { type: "task_complete" } },
    ]);
    const compress = (text: string) =>
      zstdCompressSync(Buffer.from(text), {
        params: { [constants.ZSTD_c_checksumFlag]: 1 },
      });
    const valid = Buffer.concat([compress(before), compress(after)]);
    const checksum = Buffer.from(valid);
    checksum[checksum.length - 1]! ^= 1;
    for (const [kind, contents] of [
      ["valid", valid],
      ["truncated", valid.subarray(0, -2)],
      ["checksum", checksum],
    ] as const) {
      const home = join(root, kind);
      await mkdir(join(home, "sessions"), { recursive: true });
      await mkdir(join(home, "archived_sessions"));
      await writeFile(join(home, "sessions/root.jsonl"), before);
      await writeFile(join(home, "prepared.zst"), contents);
    }
    const { stdout } = await promisify(execFile)("node", [
      "--input-type=module",
      "--eval",
      `
      import assert from "node:assert/strict";
      import zlib from "node:zlib";
      import { createRequire, syncBuiltinESMExports } from "node:module";
      import { copyFile, rm } from "node:fs/promises";
      import { join } from "node:path";
      if (${JSON.stringify(decoder)} === "portable") { delete zlib.createZstdDecompress; syncBuiltinESMExports(); }
      const { ScanCostTracker } = createRequire(import.meta.url)(${JSON.stringify(modulePath)});
      for (const kind of ["valid", "truncated", "checksum"]) {
        const home = join(${JSON.stringify(root)}, kind);
        const live = join(home, "sessions/root.jsonl");
        const archived = join(home, "archived_sessions/root.jsonl.zst");
        let owned = live;
        const tracker = new ScanCostTracker({ codexHome: home, model: "gpt-5.6-sol", maxCostUsd: 1,
          resolveOwnedSessionPaths: async () => new Map([[owned, "root"]]),
        });
        tracker.start("root");
        try {
          assert.equal((await tracker.refresh()).cost.inputTokens, 100);
          await copyFile(join(home, "prepared.zst"), archived);
          await rm(live);
          owned = archived;
          if (kind === "valid") {
            const snapshot = await tracker.stop();
            assert.equal(snapshot.cost.inputTokens, 150);
            assert.equal(snapshot.cost.outputTokens, 15);
            assert.equal(snapshot.cost.estimatedUsd, 0.0009);
          } else await assert.rejects(tracker.stop());
        } finally { await tracker.stop().catch(() => {}); }
      }
      console.log(JSON.stringify({ decoder: ${JSON.stringify(decoder)}, cases: 3 }));
    `,
    ]);
    expect(JSON.parse(stdout)).toEqual({ decoder, cases: 3 });
  });
}
