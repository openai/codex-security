import childProcess from "node:child_process";
import { once } from "node:events";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { mock } from "bun:test";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

const spawn = childProcess.spawn;
let workerArgs;
let workerProcess;
// Capture actual worker arguments in this isolated coordinator process.
const recordedSpawn = (command, args, options) => {
  const child = spawn(command, args, options);
  if (args[0] === "exec") {
    workerArgs = args;
    workerProcess = child;
  }
  return child;
};
for (const name of ["node:child_process", "child_process"])
  mock.module(name, () => ({ ...childProcess, spawn: recordedSpawn }));
const executorSource = pathToFileURL(process.argv[2]);
const { CodexSdkWorkerExecutor } = await import(executorSource.href);
const { readDeepScanRuntimeConfig } = await import(
  new URL("./permission-profile-preflight.ts", executorSource).href
);
const requests = [];
const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  async fetch(request) {
    if (new URL(request.url).pathname !== "/v1/responses")
      return Response.json({});
    if (request.method !== "POST") return new Response(null, { status: 426 });
    requests.push(await request.json());
    return new Response(
      'event: response.completed\ndata: {"type":"response.completed","response":{"id":"synthetic-response","output":[],"usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}}\n\n',
      { headers: { "content-type": "text/event-stream" } },
    );
  },
});
process.env.OPENAI_BASE_URL = `${server.url}v1`;
if (process.argv[4] === "--local-provider") {
  await writeFile(
    join(process.env.CODEX_HOME, "config.toml"),
    `openai_base_url = "${server.url}v1"\nchatgpt_base_url = "${server.url}"\n`,
  );
}
const executor = new CodexSdkWorkerExecutor({
  model: "gpt-test",
  parentSandbox: { filesystemDenies: [] },
});
process.stdout.write(
  JSON.stringify({ baseUrl: process.env.OPENAI_BASE_URL }) + "\n",
);
let previousThreadId;
try {
  for await (const line of createInterface({ input: process.stdin })) {
    const request = JSON.parse(line);
    if (request.resumePrevious) request.resumeThreadId = previousThreadId;
    const requestCount = requests.length;
    workerArgs = undefined;
    workerProcess = undefined;
    const signal = new AbortController().signal;
    let threadId;
    if (request.kind === "compare") {
      await executor.compareFindings(
        "Compare the reports.",
        process.cwd(),
        signal,
        {
          type: "object",
          properties: {},
          required: [],
          additionalProperties: false,
        },
      );
    } else {
      const result = await executor.run({
        ...request,
        promptPath: process.argv[3],
        workingDirectory: process.cwd(),
        subagents: 0,
        signal,
      });
      threadId = result.threadId;
      previousThreadId = threadId;
    }
    if (!workerArgs)
      throw new Error("Native worker arguments were not captured");
    if (requests.length === requestCount)
      throw new Error("Worker completed without a synthetic Responses request");
    // Turn completion can precede exec's exit. Release its SQLite handles before
    // this fixture starts a separate app-server against the same Codex home.
    if (workerProcess.exitCode === null && workerProcess.signalCode === null)
      await once(workerProcess, "exit");
    const config = await readDeepScanRuntimeConfig({
      codexPath: process.env.CODEX_CLI_PATH,
      cwd: process.cwd(),
      configOverrides: workerArgs.flatMap((arg, index) =>
        arg === "--config" || arg === "-c" ? [workerArgs[index + 1]] : [],
      ),
      env: process.env,
      signal: new AbortController().signal,
    });
    process.stdout.write(
      JSON.stringify({
        threadId,
        resumed: workerArgs.includes("resume"),
        ...(request.kind === "compare" && {
          tools: requests.at(-1)?.tools ?? [],
        }),
        program: requests.at(-1)?.access_programs?.cyber,
        requestedProgram: workerArgs.includes("--cyber-access-program")
          ? workerArgs[workerArgs.indexOf("--cyber-access-program") + 1]
          : null,
        daybreak: config.daybreak ?? null,
        telemetry: {
          analyticsEnabled: config.analytics?.enabled ?? null,
          environment: config.otel?.environment ?? null,
          metadataTag: config.responses_api_metadata?.["synthetic.tag"] ?? null,
        },
        daybreakFeatures: Object.fromEntries(
          [
            "cli_daybreak",
            "api_key_cyber_access_programs",
            "api_key_model_discovery",
          ].map((key) => [key, config.features?.[key] ?? null]),
        ),
      }) + "\n",
    );
  }
} finally {
  server.stop(true);
}
