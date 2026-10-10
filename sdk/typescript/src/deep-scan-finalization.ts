import { join } from "node:path";
import { pathToFileURL } from "node:url";

type WorkbenchRunner = (args: string[]) => Promise<Record<string, unknown>>;

/** Load the same publisher used by native Deep from the installed plugin. */
export async function resumeSelectedDeepScan(input: {
  scanId: string;
  threadId: string;
  pluginRoot: string;
  runWorkbench: WorkbenchRunner;
  signal: AbortSignal;
}): Promise<void> {
  const helper = (
    await import(pathToFileURL(join(input.pluginRoot, "mcp/helpers.mjs")).href)
  ).default as {
    resumeSelectedDeepScan: (input: {
      scanId: string;
      threadId: string;
      pluginRoot: string;
      runWorkbench: WorkbenchRunner;
      signal: AbortSignal;
    }) => Promise<void>;
  };
  await helper.resumeSelectedDeepScan(input);
}
