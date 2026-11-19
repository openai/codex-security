import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { test } from "bun:test";

test("Node runs the browser monitor example tests", async () => {
  await promisify(execFile)("node", ["--test", "monitor.test.mjs"], {
    cwd: new URL("../../../examples/browser-monitor/", import.meta.url),
    windowsHide: true,
  });
});
