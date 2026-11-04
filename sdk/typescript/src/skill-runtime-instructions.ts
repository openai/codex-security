import { join } from "node:path";
import { pathToFileURL } from "node:url";

/** The installed plugin owns both its selector and its instruction fragments. */
export async function readSkillRuntimeInstructions(
  pluginRoot: string,
  topic: string,
): Promise<string> {
  const runtime = await import(
    pathToFileURL(join(pluginRoot, "scripts", "skill_runtime.mjs")).href
  );
  return runtime.readSkillRuntimeInstructions(pluginRoot, topic);
}
