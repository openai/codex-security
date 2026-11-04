import { globSync } from "node:fs";
import { pipeline } from "node:stream/promises";
import { run } from "node:test";
import report from "../../../plugins/codex-security/mcp-app/scripts/test_reporter.mts";
import { partitionTests } from "./test-shards.mts";

// Rounded Linux JUnit seconds from main run 40152086428. The remaining
// files had a median under one second; discovery also picks up new files.
const slowFiles: Record<string, number> = {
  "test_artifact_discovery.ts": 11,
  "test_artifact_scan_draft_recovery.ts": 26,
  "test_artifact_scan_identity.ts": 68,
  "test_artifact_scan_publication_recovery.ts": 14,
  "test_artifact_storage.ts": 19,
  "test_artifact_storage_regressions.ts": 34,
  "test_compact_artifact_server.ts": 84,
  "test_coverage_provenance.ts": 60,
  "test_deep_scan_coordinator.ts": 18,
  "test_deep_scan_executor.ts": 40,
  "test_deep_scan_publication_integration.ts": 153,
  "test_deep_scan_stdio_lifecycle.ts": 23,
  "test_deep_scan_store_integration.ts": 51,
  "test_deep_scan_terminal_race.ts": 22,
  "test_mcp_app_smoke.ts": 45,
  "test_retry_coverage_dispositions.ts": 96,
  "test_retry_coverage_receipts_namespaces.ts": 135,
  "test_retry_coverage_receipts_ownership.ts": 145,
  "test_retry_coverage_receipts_shared.ts": 150,
  "test_workbench_database.ts": 10,
};

const [shard, count] = process.argv.slice(2).map(Number);
if (
  !shard ||
  !count ||
  !Number.isInteger(shard) ||
  !Number.isInteger(count) ||
  shard < 1 ||
  shard > count
) {
  throw new Error("Expected a shard number and count");
}
const files = globSync("tests/test_*.ts");
const timings = Object.fromEntries(
  files.map((file) => [
    file,
    { linux: slowFiles[file.slice("tests/".length)] ?? 1 },
  ]),
);
const selected = partitionTests(files, count, timings, "linux")[shard - 1]!;
if (!selected.length) throw new Error(`Empty MCP test shard ${shard}/${count}`);
// Start long files while both workers are available. Equal estimates keep
// the lexical order returned by the partitioner.
selected.sort((left, right) => timings[right]!.linux - timings[left]!.linux);
console.error(`MCP test shard ${shard}/${count}: ${selected.join(" ")}`);
// Pass literal files: the Node CLI interprets explicit arguments as globs again.
const controller = new AbortController();
const cancel = () => {
  process.exitCode = 1;
  controller.abort();
};
process.once("SIGINT", cancel);
process.once("SIGTERM", cancel);
const events = run({
  files: selected,
  concurrency: 2,
  signal: controller.signal,
});
events.on("test:summary", ({ success }) => {
  if (!success) process.exitCode = 1;
});
await pipeline(events, report, process.stdout, { end: false });
