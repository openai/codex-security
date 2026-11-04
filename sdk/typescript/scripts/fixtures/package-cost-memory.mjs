import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
const [, , installedRoot, temporaryRoot] = process.argv;
const { ScanCostTracker } = await import(
  pathToFileURL(join(installedRoot, "dist", "cost.js")).href
);
const root = await mkdtemp(join(temporaryRoot, "package-cost-history-"));
try {
  const sessions = join(root, "sessions");
  await mkdir(sessions);
  await writeFile(
    join(sessions, "a-scan.jsonl"),
    JSON.stringify({ type: "session_meta", payload: { id: "scan-thread" } }) +
      "\n",
  );
  const padding = "x".repeat(3 * 1024 * 1024);
  for (const related of [false, true]) {
    for (let index = 0; index < 40; index++)
      await writeFile(
        join(sessions, `history-${index}.jsonl`),
        [
          JSON.stringify({
            type: "session_meta",
            payload: {
              id: `history-${index}`,
              ...(related ? { parent_thread_id: "scan-thread" } : {}),
            },
          }),
          JSON.stringify({
            type: "synthetic_history",
            payload: { output: String(index) + padding },
          }),
          "",
        ].join("\n"),
      );
    let events = 0;
    const options = { codexHome: root, model: "gpt-5.6-sol" };
    const tracker = new ScanCostTracker(options);
    // Set the observer after start so this fixture drives every refresh.
    tracker.start("scan-thread");
    options.onSessionEvent = () => events++;
    await tracker.refresh();
    await tracker.stop();
    assert.equal(events, related ? 81 : 1);
  }
} finally {
  await rm(root, { recursive: true, force: true });
}
