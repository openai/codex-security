import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { packageSmokeTimeouts } from "../package-smoke-timeouts.mjs";

const installedRoot = await realpath(process.argv[2]);
const temporaryRoot = await realpath(tmpdir());
const root = await realpath(
  await mkdtemp(join(temporaryRoot, "package-cost-history-")),
);
assert.equal(dirname(root), temporaryRoot);
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
    const expectedEvents = related ? 81 : 1;
    const code = `import {ScanCostTracker} from ${JSON.stringify(pathToFileURL(join(installedRoot, "dist", "cost.js")).href)};let events=0;const options={codexHome:process.argv[1],model:"gpt-5.6-sol"};const tracker=new ScanCostTracker(options);tracker.start("scan-thread");options.onSessionEvent=()=>events++;await tracker.refresh();await tracker.stop();if(events!==${expectedEvents})throw new Error("Scan events were lost or duplicated: "+events);`;
    const result = spawnSync(
      process.execPath,
      ["--max-old-space-size=96", "--input-type=module", "--eval", code, root],
      {
        cwd: installedRoot,
        encoding: "utf8",
        windowsHide: true,
        timeout: packageSmokeTimeouts().commandTimeoutMs,
      },
    );
    assert.equal(result.status, 0, result.stderr || result.error?.message);
  }
} finally {
  await rm(root, { recursive: true, force: true });
}
