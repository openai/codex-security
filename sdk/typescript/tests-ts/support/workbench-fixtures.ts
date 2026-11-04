import { join } from "node:path";
import type { JsonObject } from "../../src/config.js";
import { PLUGIN_ROOT } from "../plugin-root.js";
import { runCommand } from "./shell.js";

const setupProgram = String.raw`
import contextlib, io, json, runpy, sys
script = sys.argv[1]
commands = json.load(sys.stdin)
workbench = runpy.run_path(script)
results = []
for arguments in commands:
    sys.argv = [script, *arguments]
    sys.stdin = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        workbench["main"]()
    results.append(json.loads(output.getvalue()))
print(json.dumps(results))
`;

/** Run fixture setup through the real parser and transitions, sharing Python startup. */
export async function runWorkbenchFixtureCommands(
  python: string,
  environment: NodeJS.ProcessEnv,
  commands: readonly (readonly string[])[],
): Promise<JsonObject[]> {
  const result = await runCommand(
    python,
    [
      "-I",
      "-X",
      "utf8",
      "-B",
      "-c",
      setupProgram,
      join(PLUGIN_ROOT, "scripts", "workbench_db.py"),
    ],
    { env: environment, input: JSON.stringify(commands), timeout: 0 },
  );
  if (result.status !== 0)
    throw new Error(result.stderr || "Workbench fixture setup failed.", {
      cause: result.error,
    });
  return JSON.parse(result.stdout) as JsonObject[];
}
