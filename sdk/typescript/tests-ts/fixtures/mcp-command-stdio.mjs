import { join } from "node:path";
import { runCodexSkillCommand } from "../../src/cli.ts";
import {
  buildCliMcpCommands,
  runCliMcpCommand,
} from "../../src/cli-mcp-commands.ts";

async function main() {
  if (process.argv[2] !== "runner") {
    process.stderr.write(JSON.stringify({ cli: process.pid }) + "\n");
    process.exitCode = await runCodexSkillCommand(
      ["login", "status"],
      undefined,
      { command: join(process.cwd(), "codex.mjs") },
      process.env,
    );
    return;
  }

  const controller = new AbortController();
  process.on("message", () => controller.abort());
  const [command] = buildCliMcpCommands({ commands: [{ name: "login" }] });
  const result = await runCliMcpCommand(
    command,
    {},
    {
      executable: process.execPath,
      entrypoint: process.argv[1],
      cwd: process.cwd(),
      environment: process.env,
      signal: controller.signal,
      onStderr: (chunk) => process.send({ chunk }),
    },
  );
  process.send({ result }, () => process.disconnect());
}

void main();
