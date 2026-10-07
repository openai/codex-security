import { spawnSync } from "node:child_process";
import { workflowBashCommand } from "./shell.js";

export function runWorkflowScript(
  directory: string,
  script: unknown,
  env: Record<string, string>,
  shellOptions: string[] = [],
  argumentsPath = "$ARGUMENTS_PATH",
) {
  const result = spawnSync(
    workflowBashCommand(),
    [
      "--noprofile",
      "--norc",
      ...shellOptions,
      "-c",
      `codex-security() {
  printf '%s\\0' "$@" > "${argumentsPath}"
  printf '{"mock":true}\\n'
  return "$MOCK_EXIT_CODE"
}
${script}`,
    ],
    {
      cwd: directory,
      encoding: "utf8",
      env: {
        PATH: process.env["PATH"],
        SYSTEMROOT: process.env["SYSTEMROOT"],
        BEDROCK_MODEL_ID: "example.model",
        MOCK_EXIT_CODE: "0",
        ...env,
      },
    },
  );
  if (result.error) throw result.error;
  return result;
}
