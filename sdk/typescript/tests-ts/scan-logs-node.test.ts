import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { zstdCompressSync } from "node:zlib";
import { afterEach, expect, test } from "bun:test";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-scan-logs-node-",
);

afterEach(cleanup);

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
    await writeFile(
      join(sessions, "rollout-worker.jsonl.zst"),
      zstdCompressSync(`${JSON.stringify(worker)}\n`),
    );

    const built = await Bun.build({
      entrypoints: [
        fileURLToPath(new URL("../src/scan-logs.ts", import.meta.url)),
      ],
      target: "node",
      format: "esm",
    });
    expect(built.success).toBe(true);
    const module = join(root, "scan-logs.mjs");
    await writeFile(module, await built.outputs[0]!.text());
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
          console.log(JSON.stringify({
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
    expect(result.logs.events).toEqual([
      { threadId: "parent", event: parent },
      ...(result.compressed ? [{ threadId: "worker", event: worker }] : []),
    ]);
  },
);
