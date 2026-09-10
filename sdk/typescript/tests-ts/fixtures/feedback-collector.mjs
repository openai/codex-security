import { createInterface } from "node:readline";

for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (process.env.COLLECTOR_SCENARIO === "cancel") {
    process.stdout.write('{"scans":[');
    process.stderr.write("collecting\n");
    setInterval(() => undefined, 1000);
    break;
  }
  console.log(
    JSON.stringify({
      request,
      codexHome: process.env.CODEX_HOME,
      stateDirectory: process.env.CODEX_SECURITY_STATE_DIR,
      utf8: process.env.PYTHONUTF8,
      hasApiKey: "OPENAI_API_KEY" in process.env,
    }),
  );
}
