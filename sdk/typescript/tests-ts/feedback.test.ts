import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, toNamespacedPath } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { sendFeedback } from "../src/feedback.js";
import { codexSecurityCredentialHome } from "../src/runtime.js";
import { VERSION, BUNDLED_PLUGIN_VERSION } from "../src/version.js";

const fixture = fileURLToPath(
  new URL("fixtures/feedback.mjs", import.meta.url),
);
const directories: string[] = [];
afterEach(async () => {
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
});

async function setup() {
  const directory = await mkdtemp(join(tmpdir(), "feedback-test-"));
  directories.push(directory);
  const environment = {
    CODEX_HOME: join(directory, "ambient"),
    CODEX_SECURITY_STATE_DIR: join(directory, "state"),
    CODEX_CLI_PATH: process.execPath,
    FEEDBACK_REQUEST_FILE: join(directory, "requests.json"),
    FEEDBACK_SCENARIO: "success",
  };
  const home = codexSecurityCredentialHome(environment);
  await mkdir(join(home, "sessions"), { recursive: true });
  const root = { type: "session_meta", payload: { id: "thread-1" } };
  const worker = {
    type: "session_meta",
    payload: {
      id: "worker-1",
      source: { subagent: { thread_spawn: { parent_thread_id: "thread-1" } } },
    },
  };
  await writeFile(
    join(home, "sessions", "rollout-root.jsonl"),
    JSON.stringify(root),
  );
  await writeFile(
    join(home, "sessions", "rollout-worker.jsonl"),
    JSON.stringify(worker),
  );
  await writeFile(
    join(home, "sessions", "rollout-unrelated.jsonl"),
    JSON.stringify({ type: "session_meta", payload: { id: "unrelated" } }),
  );
  let child: ChildProcessWithoutNullStreams | undefined;
  const startCodex: NonNullable<Parameters<typeof sendFeedback>[1]> = (
    command,
    args,
    options,
  ) => {
    expect(command).toBe(toNamespacedPath(process.execPath));
    expect(args).toEqual(["app-server", "--stdio"]);
    expect(options.env?.["CODEX_HOME"]).toBe(home);
    child = spawn(process.execPath, [fixture], options);
    return child;
  };
  return {
    directory,
    environment,
    home,
    startCodex,
    options: {
      reason: "Scan stopped",
      includeLogs: true,
      scan: { scanId: "scan-1", continuationThreadId: "thread-1" },
      environment,
      workingDirectory: directory,
    },
    transcript: async () =>
      JSON.parse(await readFile(environment.FEEDBACK_REQUEST_FILE, "utf8")),
    expectClosed: () =>
      expect(child!.exitCode !== null || child!.signalCode !== null).toBe(true),
  };
}

test("uploads selected scan and worker logs through Codex and removes temporary files", async () => {
  const context = await setup();
  expect(await sendFeedback(context.options, context.startCodex)).toEqual({
    feedbackId: "feedback-1",
    scanId: "scan-1",
    includedLogs: true,
  });
  const { requests, attachments } = await context.transcript();
  expect(requests.map((request: { method: string }) => request.method)).toEqual(
    ["initialize", "initialized", "feedback/upload"],
  );
  expect(requests[2].params).toMatchObject({
    classification: "bug",
    reason: "Scan stopped",
    threadId: "thread-1",
    includeLogs: true,
    tags: {
      codex_security_version: VERSION,
      codex_security_plugin_version: BUNDLED_PLUGIN_VERSION,
      codex_security_scan_id: "scan-1",
    },
  });
  expect(attachments).toHaveLength(1);
  expect(
    JSON.parse(attachments[0].content).sessions.map(
      (session: { threadId: string }) => session.threadId,
    ),
  ).toEqual(["thread-1", "worker-1"]);
  expect(existsSync(attachments[0].path)).toBe(false);
  context.expectClosed();
});

test("without log opt-in, does not read or attach saved sessions", async () => {
  const context = await setup();
  await rm(join(context.home, "sessions"), { recursive: true });
  expect(
    (
      await sendFeedback(
        { ...context.options, includeLogs: false },
        context.startCodex,
      )
    ).includedLogs,
  ).toBe(false);
  const { requests, attachments } = await context.transcript();
  expect(requests[2].params.includeLogs).toBe(false);
  expect(requests[2].params.extraLogFiles).toEqual([]);
  expect(attachments).toEqual([]);
});

for (const [scenario, message] of [
  ["error", "Upload failed"],
  ["exit", "Codex exited before feedback was uploaded"],
  ["missing-id", "Codex did not return a feedback ID"],
  ["malformed", "JSON"],
]) {
  test(`upload ${scenario} leaves no temporary logs or running child`, async () => {
    const context = await setup();
    context.environment.FEEDBACK_SCENARIO = scenario!;
    await expect(
      sendFeedback(context.options, context.startCodex),
    ).rejects.toThrow(message);
    const { attachments } = await context.transcript();
    expect(existsSync(attachments[0].path)).toBe(false);
    context.expectClosed();
  });
}

test("respects disabled feedback without starting Codex", async () => {
  const context = await setup();
  await mkdir(context.environment.CODEX_HOME);
  await writeFile(
    join(context.environment.CODEX_HOME, "config.toml"),
    "[feedback]\nenabled = false\n",
  );
  await expect(
    sendFeedback(context.options, () => {
      throw new Error("Must not start Codex");
    }),
  ).rejects.toThrow("disabled by configuration");
});

test("reports missing session logs without sending an incomplete log report", async () => {
  const context = await setup();
  await rm(join(context.home, "sessions"), { recursive: true });
  await expect(
    sendFeedback(context.options, () => {
      throw new Error("Must not start Codex");
    }),
  ).rejects.toThrow("No saved session logs");
});

test("reports failure to start Codex", async () => {
  const context = await setup();
  await expect(
    sendFeedback(
      { ...context.options, includeLogs: false },
      (_command, _args, options) =>
        spawn(join(context.directory, "missing-executable"), [], options),
    ),
  ).rejects.toThrow("ENOENT");
});

test("cancellation stops the Codex process", async () => {
  const context = await setup();
  const controller = new AbortController();
  await expect(
    sendFeedback(
      { ...context.options, signal: controller.signal },
      (...args) => {
        const child = context.startCodex(...args);
        child.stdout.once("data", () => controller.abort());
        return child;
      },
    ),
  ).rejects.toThrow("abort");
  context.expectClosed();
});
