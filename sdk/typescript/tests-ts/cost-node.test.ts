import { execFile } from "node:child_process";
import { copyFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { zstdCompressSync } from "node:zlib";
import { afterEach, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { writeSession } from "./support/usage-rollout.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-cost-node-",
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

for (const capabilities of ["native", "without zstd"]) {
  test.each([
    ["complete", false],
    ["complete", true],
    ["truncated", false],
    ["truncated", true],
  ] as const)(
    `accounts for every compressed frame in Node with ${capabilities} capabilities (%s; session events=%p)`,
    async (tail, observeSessionEvents) => {
      const root = await temporaryDirectory();
      const home = join(root, "home");
      await writeSession(home, "parent", {
        input_tokens: 100,
        output_tokens: 10,
      });
      const frame = (records: unknown[]) =>
        zstdCompressSync(
          `${records.map((record) => JSON.stringify(record)).join("\n")}\n`,
        );
      const usage = (input: number, output: number) => ({
        type: "event_msg",
        payload: {
          type: "token_count",
          info: {
            total_token_usage: { input_tokens: input, output_tokens: output },
          },
        },
      });
      const firstFrame = frame([
        {
          type: "session_meta",
          payload: { id: "worker", parent_thread_id: "parent" },
        },
        usage(900, 90),
      ]);
      const lastFrame = frame([usage(1_900, 190)]);
      await writeFile(
        join(home, "sessions", "rollout-worker.jsonl.zst"),
        Buffer.concat([
          firstFrame,
          tail === "truncated"
            ? lastFrame.subarray(0, lastFrame.length - 3)
            : lastFrame,
        ]),
      );

      for (const relativePath of [
        ".codex-plugin/plugin.json",
        "mcp/session-decompression.mjs",
      ]) {
        const destination = join(root, "_bundled_plugin", relativePath);
        await mkdir(dirname(destination), { recursive: true });
        await copyFile(join(PLUGIN_ROOT, relativePath), destination);
      }
      const module = join(root, "dist", "cost.mjs");
      await mkdir(dirname(module), { recursive: true });
      await writeFile(module, moduleSource);
      const { stdout } = await promisify(execFile)(
        "node",
        [
          "--input-type=module",
          "--eval",
          `
            import zlib from "node:zlib";
            if (${JSON.stringify(capabilities)} === "without zstd") {
              delete zlib.createZstdDecompress;
            }
            const { ScanCostTracker } = await import(${JSON.stringify(pathToFileURL(module).href)});
            let measurement;
            const tracker = new ScanCostTracker({
              codexHome: ${JSON.stringify(home)},
              model: "gpt-5.6-sol",
              onMeasurement: (value) => { measurement = value; },
              onError: () => {},
              ${observeSessionEvents ? "onSessionEvent: () => {}," : ""}
            });
            tracker.start("parent");
            let error = null;
            try {
              await tracker.stop();
            } catch (caught) {
              error = String(caught);
            }
            console.log(JSON.stringify({ measurement, error }));
          `,
        ],
        { encoding: "utf8" },
      );
      const result = JSON.parse(stdout);
      if (tail === "truncated") {
        expect(result.error).not.toBeNull();
        expect(result.measurement.coverage).toBe("partial");
        expect(result.measurement.missingThreadCount).toBeGreaterThan(0);
        expect(result.measurement.usage).toMatchObject({
          input_tokens: 1_000,
          output_tokens: 100,
        });
        expect(result.measurement.cost).toMatchObject({
          inputTokens: 1_000,
          outputTokens: 100,
        });
      } else {
        expect(result.error).toBeNull();
        expect(result.measurement).toMatchObject({
          coverage: "complete",
          threadCount: 2,
          missingThreadCount: 0,
          usage: { input_tokens: 2_000, output_tokens: 200 },
          cost: { inputTokens: 2_000, outputTokens: 200 },
        });
      }
    },
  );
}
