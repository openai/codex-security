import { appendFile, cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

// Synthetic Codex child: real workbench state and native-shaped saved records.
// No model requests, scan analysis, or mocked workbench ownership.
const {
  environment: env,
  threadId,
  turnId,
  outcome,
  draft,
} = JSON.parse(await readFile(0, "utf8"));
const home = env.CODEX_HOME;
const scanDir = env.CODEX_SECURITY_SCAN_DIR;
const scanId = env.CODEX_SECURITY_SCAN_ID;
const path = join(home, "sessions", `rollout-${threadId}.jsonl`);
await mkdir(join(home, "sessions"), { recursive: true });
const record = async (type, payload) =>
  appendFile(
    path,
    JSON.stringify({ timestamp: new Date().toISOString(), type, payload }) +
      "\n",
  );
try {
  await readFile(path);
} catch {
  await record("session_meta", {
    id: threadId,
    cwd: scanDir,
    timestamp: new Date().toISOString(),
  });
}
await record("event_msg", {
  type: "task_started",
  turn_id: turnId,
  started_at: Date.now() / 1000,
});
console.log(JSON.stringify({ type: "thread.started", thread_id: threadId }));
console.log(JSON.stringify({ type: "turn.started" }));
if (draft) {
  await cp(
    join(env.CODEX_SECURITY_PLUGIN_ROOT, "examples", "completed-scan"),
    scanDir,
    { recursive: true },
  );
  for (const name of ["scan-manifest.json", "findings.json", "coverage.json"]) {
    const file = join(scanDir, name);
    const doc = JSON.parse(await readFile(file, "utf8"));
    if (name === "scan-manifest.json") {
      doc.scan.id = scanId;
      doc.scan.target = { kind: env.CODEX_SECURITY_TARGET_KIND };
      delete doc.scan.sealedAt;
      delete doc.scan.artifacts;
    } else {
      doc.scanId = scanId;
      if (name === "findings.json") doc.findings = [];
    }
    await writeFile(file, JSON.stringify(doc));
  }
  // Complete inside the scan task so its tool output and final reply follow the seal.
  const completed = execFileSync(
    env.PYTHON,
    [
      "-I",
      "-B",
      join(env.CODEX_SECURITY_PLUGIN_ROOT, "scripts", "workbench_db.py"),
      "complete-scan",
      "--scan-id",
      scanId,
    ],
    { env, encoding: "utf8" },
  );
  await record("response_item", {
    type: "function_call_output",
    call_id: `${turnId}-completion`,
    output: completed,
  });
}
await record("response_item", {
  type: "message",
  role: "assistant",
  content: [{ type: "output_text", text: `${turnId} reply` }],
});
await record("event_msg", {
  type: outcome === "failed" ? "error" : "task_complete",
  turn_id: turnId,
  message: `${turnId} ${outcome}`,
});
console.log(
  JSON.stringify(
    outcome === "failed"
      ? { type: "turn.failed", error: { message: `${turnId} failed` } }
      : {
          type: "turn.completed",
          usage: { input_tokens: 10, cached_input_tokens: 0, output_tokens: 3 },
        },
  ),
);
