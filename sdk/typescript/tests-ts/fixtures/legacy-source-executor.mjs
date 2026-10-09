import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

// Keep the real executor protocol, advertising the older host-bearer behavior.
const child = spawn(process.argv[2], ["exec-server", "--listen", "stdio"], {
  stdio: ["pipe", "pipe", "inherit"],
});
process.stdin.pipe(child.stdin);
createInterface({ input: child.stdout }).on("line", (line) => {
  const message = JSON.parse(line);
  const capabilities = message.result?.environmentInfo?.capabilities;
  if (capabilities) capabilities.httpHeaderEnvVars = false;
  process.stdout.write(`${JSON.stringify(message)}\n`);
});
process.on("SIGTERM", () => child.stdin.end());
child.stdin.on("error", () => {});
child.on("error", (error) => {
  process.stderr.write(String(error));
  process.exitCode = 1;
});
child.on("close", (code) => {
  process.stdin.unpipe(child.stdin);
  process.stdin.destroy();
  process.exitCode = code ?? 0;
});
