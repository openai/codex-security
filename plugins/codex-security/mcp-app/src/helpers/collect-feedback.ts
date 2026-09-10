import { spawn } from "node:child_process";
import { join } from "node:path";
import { executablePathForSpawn } from "../deep-scan/executable-path.js";
import { resolvePythonCommand } from "../python_command.js";

export async function collectFeedbackCommand(pluginRoot: string): Promise<number> {
  const python = await resolvePythonCommand();
  const child = spawn(
    executablePathForSpawn(python),
    [join(pluginRoot, "scripts", "collect_feedback.py")],
    {
      env: { ...process.env, PYTHONUTF8: "1" },
      stdio: "inherit",
      windowsHide: true
    }
  );
  const onInterrupt = () => { child.kill("SIGINT"); };
  const onTerminate = () => { child.kill("SIGTERM"); };
  process.once("SIGINT", onInterrupt);
  process.once("SIGTERM", onTerminate);
  try {
    return await new Promise<number>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => {
        resolve(code ?? (signal === "SIGINT" ? 130 : signal === "SIGTERM" ? 143 : 1));
      });
    });
  } finally {
    process.removeListener("SIGINT", onInterrupt);
    process.removeListener("SIGTERM", onTerminate);
  }
}
