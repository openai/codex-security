import { afterEach, expect, test } from "bun:test";
import { build } from "esbuild";
import { execFileSync } from "node:child_process";
import { copyFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { pythonExecutable } from "./support/python.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "workbench-compressed-usage-",
);
afterEach(cleanup);

const sourcePlugin = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);

// Native level-3 frames keep these integration cases available on Node 22.13,
// which has no compressor. The first two frames report cumulative 12 then 34.
const firstFrame = Buffer.from(
  "KLUv/WBoAP0FAOLLIx1wp9UB1jFCE/GD0iiS1GouFgZXn8F8ajAPQAM9JkSMMZ5i0uGYS1VHXM7C/DLEICXjA0stF1Mg68Ln2A+lMBnU5qaAYy5eB3Mld4LcQ1ta94KfhIjR6wc38hcCU10cUCBjAApDKAyhcMwx8mtq9Y2ti42rHnktl5EN5gTZUGk4qOditW/JJVO9GvnvsE4CEQB4BKBhOOxn96XiBlC+dhIAT6kAapxW/0yReiGCZpZh8h7GAax3Vt2PgTMD",
  "base64",
);
const laterFrame = Buffer.from(
  "KLUv/SD/zQQA8kgdHmA1bgPwywwJHq2g6RyLxSJlTFGwGID4zQMiAIZcDoL33jsQKmXXckttjo52rL2aAaUSBUASOcJBemvHdv1JVyWbU0s282HX0XsdI2o1gPtJT5IXJ9nRlcaoXhXQpytz+ugGIyEWCiQKJAgGGk9nTHZTZvWfDAB4BKBhOOxn96XiBlC+dhIAT6ngxOrnaEDdoKCIYODy",
  "base64",
);
const workerFrames = {
  first:
    "KLUv/WBuADUGADJMJR5gZ9sGBqGhvdpM+qNbLXaX7jcEObew2na8jABwIXjFe+8hB5PCFltObT9Iu9VeDZFSogMq1Q8e6NyOYUuVZJcO2dtbYOvnzdyqxNSwrfCSmimBHk3x3pUW6NFVNbf8cwFEZIAQAwhoENAAOPA4OrNksy6rf97U0BZhNLdVOHqy3qAnuYdEMj/P1iWxXczKR1cm0W8CEQB4BKBhOOxn96XiBlC+dhIAT6kAapxW/0zxeiGCZlZi8irGIav12lWPyMtFAQ==",
  child:
    "KLUv/WBvAQUIAOKOKx5gR9wGQQuHRBuJ4LvoY7FlzhiCXM3Jv4oDEQAeCRiEw+HZuTRmlyGQzgcpRJkuY7ofo99mM9copI5MFq6fgHTu15QhyE8t2NtbUPbz1rdLaSprnFD3sh02K4WxEWYM0kA4nGh2rKBa02HTBhurA9Ml3ZoIFjzO5d7yzwmKhNBAgYgCEQAGMp7eGGxOhvXPj4Uli3CpuG2efrAb0g/c5QDbz7GTUbqMOfnp2Q76hh8AgynE7UMYhsN+dl8qbgDlC2TXTvlxUK/QRn6w1D9rA3ToQGxmSfcFyGPG0lwPmoWkyaCCIdPckA6E8YXpwHJDAzrdzNz0Wk6E9cjVnQE=",
  boundary:
    "KLUv/WB0AFUGAJJMJh9gSdsGCHYYtH22+2PTLPZb5n+KgmUM2I0hUBHkEjgBhffew2MwIbuWWyq7wdOOtRdDpHTogUp1g3jQWztllyLZXDpkc7PBrpv3OlZp1cCNtCT1KoIaicJ7V5qgR1fFHLebEyAGACDEgYPFwULAQOPoSpLdNFl9c6YGxohiYXms44KjH+sJ9CP5sKRy82xN0vJqTdvRVVn6iREAegTgYTgMqE5JxQ2gfO0kgJ6yAnw47fsZSPaCBc1WxaRgjK+sVmFXPSgvFwU=",
};

async function fixture() {
  const root = await temporaryDirectory();
  const plugin = join(root, "plugin");
  const paths = [
    "scripts/workbench_scan_usage.py",
    "scripts/windows_scan_local_files.py",
    "scripts/read_codex_session.mjs",
    "scripts/workbench/__init__.py",
    "scripts/workbench/storage.py",
  ];
  for (const path of paths) {
    await mkdir(dirname(join(plugin, path)), { recursive: true });
    await copyFile(join(sourcePlugin, path), join(plugin, path));
  }
  await build({
    entryPoints: [join(sourcePlugin, "mcp-app/src/session-decompression.ts")],
    outfile: join(plugin, "mcp/session-decompression.mjs"),
    bundle: true,
    platform: "node",
    format: "esm",
  });
  return { root, plugin };
}

function collect(
  root: string,
  plugin: string,
  options: {
    owner: string;
    workerKind?: "discovery" | "dedup";
    threads: Array<{
      id: string;
      path: string;
      cwd?: string;
      createdAt?: number;
    }>;
    edges?: string[][];
  },
) {
  const python = pythonExecutable();
  const node = Bun.which("node");
  expect(python).not.toBeNull();
  expect(node).not.toBeNull();
  const script = `
import json, os, sqlite3, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))
from workbench_scan_usage import collect_scan_usage
root = Path(sys.argv[2])
options = json.loads(sys.argv[3])
with sqlite3.connect(os.environ["CODEX_STATE_DB"]) as native:
    native.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, cwd TEXT, created_at INTEGER)")
    native.execute("CREATE TABLE thread_spawn_edges (parent_thread_id TEXT, child_thread_id TEXT)")
    native.executemany("INSERT INTO threads VALUES (?, ?, ?, ?)", [(t["id"], t["path"], t.get("cwd"), t.get("createdAt")) for t in options["threads"]])
    native.executemany("INSERT INTO thread_spawn_edges VALUES (?, ?)", options.get("edges", []))
with sqlite3.connect(":memory:") as db:
    db.row_factory = sqlite3.Row
    db.execute("CREATE TABLE workspaces (id TEXT, thread_id TEXT)")
    db.execute("INSERT INTO workspaces VALUES ('workspace', ?)", (options["owner"],))
    db.execute("CREATE TABLE deep_scan_worker_threads (scan_id TEXT, sdk_thread_id TEXT)")
    db.execute("CREATE TABLE deep_scan_workers (scan_id TEXT, kind TEXT, artifact_dir TEXT)")
    mode = "deep" if options.get("workerKind") else "standard"
    if mode == "deep":
        db.execute("INSERT INTO deep_scan_workers VALUES ('scan', ?, ?)", (options["workerKind"], str(root / "artifacts" / "worker")))
        db.execute("INSERT INTO deep_scan_worker_threads VALUES ('scan', 'current-worker')")
    scan = db.execute("SELECT 'scan' AS id, 'workspace' AS workspace_id, ? AS mode, ? AS scan_dir, '2026-01-01T00:00:00.500123Z' AS started_at, '2026-01-01T00:00:05Z' AS completed_at, NULL AS deep_scan_owner_thread_id", (mode, str(root))).fetchone()
    print(json.dumps(collect_scan_usage(db, scan)))
`;
  return JSON.parse(
    execFileSync(
      python!,
      ["-I", "-B", "-c", script, plugin, root, JSON.stringify(options)],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          CODEX_STATE_DB: join(root, "native.sqlite"),
          CODEX_HOME: join(root, "home"),
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          CODEX_MCP_NODE_PATH: node!,
        },
      },
    ),
  );
}

test.each([
  ["single", firstFrame, 12],
  ["concatenated", Buffer.concat([firstFrame, laterFrame]), 34],
  ["truncated first", firstFrame.subarray(0, -3), null],
  [
    "truncated later",
    Buffer.concat([firstFrame, laterFrame.subarray(0, -3)]),
    null,
  ],
] as const)(
  "Python collector reads %s Zstandard frames",
  async (_kind, contents, total) => {
    const { root, plugin } = await fixture();
    const path = join(root, "compressed.jsonl.zst");
    await writeFile(path, contents);
    const usage = collect(root, plugin, {
      owner: "compressed",
      threads: [{ id: "compressed", path }],
    });
    if (total === null) {
      expect(usage.coverage).toBe("unavailable");
      expect(usage.warnings).toContain("rollout_unavailable");
      expect(usage).not.toHaveProperty("totalTokens");
    } else {
      expect(usage).toMatchObject({
        coverage: "complete",
        inputTokens: total === 12 ? 10 : 30,
        cachedInputTokens: 0,
        cacheWriteInputTokens: 0,
        outputTokens: total === 12 ? 2 : 4,
        reasoningOutputTokens: 0,
        totalTokens: total,
        threadCount: 1,
      });
    }
  },
);

test.each(["discovery", "dedup"] as const)(
  "Python collector discovers compressed replaced %s workers by cwd",
  async (workerKind) => {
    const { root, plugin } = await fixture();
    const cwd =
      workerKind === "discovery"
        ? join(root, "artifacts", "worker")
        : join(root, "artifacts");
    const threads: Parameters<typeof collect>[2]["threads"] = [];
    for (const [id, frame] of [
      ["first-worker", workerFrames.first],
      ["worker-child", workerFrames.child],
      ["boundary-worker", workerFrames.boundary],
    ] as const) {
      const path = join(root, `${id}.jsonl.zst`);
      await writeFile(path, Buffer.from(frame, "base64"));
      threads.push({ id, path, cwd, createdAt: 1767225600 });
    }
    for (const [id, input, output, counts, createdAt] of [
      ["scan-parent", 10, 3, 1, 1767225600],
      ["current-worker", 30, 8, 2, 1767139200],
      ["other-worker", 80000, 20000, 1, 1767225600],
      ["archived-worker", 100, 10, 1, 1767139200],
      ["later-worker", 100, 10, 1, 1767312000],
    ] as const) {
      const path = join(root, `${id}.jsonl`);
      const token = (input: number, output: number) => ({
        timestamp: "2026-01-01T00:00:02Z",
        type: "event_msg",
        payload: {
          type: "token_count",
          info: {
            total_token_usage: {
              input_tokens: input,
              cached_input_tokens: 0,
              cache_write_input_tokens: 0,
              output_tokens: output,
              reasoning_output_tokens: 0,
              total_tokens: input + output,
            },
          },
        },
      });
      await writeFile(
        path,
        [
          {
            type: "session_meta",
            payload: { id, timestamp: "2025-12-31T00:00:00Z", source: "exec" },
          },
          ...(counts === 2 ? [token(20, 5)] : []),
          token(input, output),
        ]
          .map((record) => `${JSON.stringify(record)}\n`)
          .join(""),
      );
      threads.push({
        id,
        path,
        cwd: id === "other-worker" ? join(root, "other-scan") : cwd,
        createdAt,
      });
    }
    for (const [id, createdAt] of [
      ["boundary-child", 1767225600],
      ["archived-missing", 1767139200],
      ["later-missing", 1767312000],
    ] as const)
      threads.push({
        id,
        path: join(root, `${id}.jsonl`),
        cwd: id === "boundary-child" ? undefined : cwd,
        createdAt,
      });
    const usage = collect(root, plugin, {
      owner: "scan-parent",
      workerKind,
      threads,
      edges: [
        ["first-worker", "worker-child"],
        ["boundary-worker", "boundary-child"],
      ],
    });
    expect(usage).toMatchObject({
      coverage: "complete",
      source: "codex_rollout",
      inputTokens: 67,
      cachedInputTokens: 0,
      cacheWriteInputTokens: 0,
      outputTokens: 18,
      reasoningOutputTokens: 0,
      totalTokens: 85,
      threadCount: 4,
    });
  },
);
