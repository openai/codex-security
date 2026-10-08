import { mkdir, mkdtemp } from "node:fs/promises";
import path from "node:path";
import { runReducerPagingEval } from "../../plugins/codex-security/mcp-app/tests/support/reducer-paging/deep-reducer-paging.ts";

const reports = path.join(import.meta.dirname, "reports/");
await mkdir(reports, { recursive: true });
const root = await mkdtemp(path.join(reports, "deep-reducer-paging-"));
console.log(`Eval artifacts: ${root}`);
const { report } = await runReducerPagingEval({
  root,
  mode: "model",
  model: process.argv[2],
});
console.log(JSON.stringify(report, null, 2));
