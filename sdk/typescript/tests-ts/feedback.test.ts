import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, toNamespacedPath } from "node:path";
import { fileURLToPath } from "node:url";
import { PassThrough } from "node:stream";
import { afterEach, expect, test } from "bun:test";
import { sendFeedback } from "../src/feedback.js";
import { codexSecurityCredentialHome } from "../src/runtime.js";
import { VERSION, BUNDLED_PLUGIN_VERSION } from "../src/version.js";
import { throwing } from "./support/errors.js";

const fixture = fileURLToPath(
  new URL("fixtures/feedback.mjs", import.meta.url),
);
const directories: string[] = [];
const diagnostic = "Synthetic configuration failure: café 日本語";
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
    FEEDBACK_STDERR: `${diagnostic}\n`,
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
      scan: {
        scanId: "scan-1",
        continuationThreadId: "thread-1",
        threadIds: ["thread-1"],
        executionThreadIds: ["thread-1"],
      },
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

for (const missingParent of [false, true]) {
  test(`uploads only the selected Desktop scan logs with parent ${missingParent ? "missing" : "available"}`, async () => {
    const context = await setup();
    const archived = join(context.environment.CODEX_HOME, "archived_sessions");
    await mkdir(archived, { recursive: true });
    const sessions: [string, string, string | null][] = [
      [archived, "sdk-worker", null],
      [join(context.home, "sessions"), "worker-child", "sdk-worker"],
    ];
    if (!missingParent) sessions.unshift([archived, "desktop-owner", null]);
    for (const [directory, id, parent] of sessions) {
      await writeFile(
        join(directory, `rollout-${id}.jsonl`),
        JSON.stringify({
          type: "session_meta",
          payload: { id, parent_thread_id: parent },
        }),
      );
    }
    for (const payload of [
      {
        id: "unrelated-before",
        timestamp: "2026-09-10T09:00:00Z",
        source: {
          subagent: { thread_spawn: { parent_thread_id: "desktop-owner" } },
        },
      },
      {
        id: "unrelated-after",
        timestamp: "2026-09-10T13:00:00Z",
        parent_thread_id: "desktop-owner",
      },
      {
        id: "unrelated-fork",
        timestamp: "2026-09-10T11:30:00Z",
        forked_from_id: "desktop-owner",
      },
      {
        id: "unrelated-grandchild",
        timestamp: "2026-09-10T11:45:00Z",
        parent_thread_id: "unrelated-fork",
      },
    ]) {
      await writeFile(
        join(archived, `rollout-${payload.id}.jsonl`),
        JSON.stringify({
          type: "session_meta",
          payload: { ...payload, cwd: join(context.directory, "other-repo") },
        }),
      );
    }
    await sendFeedback(
      {
        ...context.options,
        scan: {
          scanId: "desktop-scan",
          mode: "deep",
          scanDir: join(context.directory, "scan"),
          progress: { status: "complete", updatedAt: "2026-09-10T12:00:00Z" },
          threadIds: ["desktop-owner", "sdk-worker"],
          executionThreadIds: ["sdk-worker"],
        },
      },
      context.startCodex,
    );
    const { requests, attachments } = await context.transcript();
    expect(requests[2].params.tags.codex_security_scan_id).toBe("desktop-scan");
    expect(attachments).toHaveLength(1);
    expect(
      JSON.parse(attachments[0].content).sessions.map(
        (session: { threadId: string }) => session.threadId,
      ),
    ).toEqual([
      ...(!missingParent ? ["desktop-owner"] : []),
      "sdk-worker",
      "worker-child",
    ]);
    expect(existsSync(attachments[0].path)).toBe(false);
    context.expectClosed();
  });
}

for (const recordedExecutionRoots of [false, true]) {
  test(`does not infer standard scan workers from a Desktop continuation (${recordedExecutionRoots})`, async () => {
    const context = await setup();
    await sendFeedback(
      {
        ...context.options,
        scan: {
          scanId: "desktop-standard",
          mode: "standard",
          continuationThreadId: "thread-1",
          threadIds: ["thread-1"],
          ...(recordedExecutionRoots ? { executionThreadIds: [] } : {}),
        },
      },
      context.startCodex,
    );
    const { requests, attachments } = await context.transcript();
    expect(requests[2].params.threadId).toBeUndefined();
    expect(
      JSON.parse(attachments[0].content).sessions.map(
        (session: { threadId: string }) => session.threadId,
      ),
    ).toEqual(["thread-1"]);
    context.expectClosed();
  });
}

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

for (const [index, [scenario, message, stderr]] of [
  ["error", "Upload failed"],
  ["exit", "Codex exited before feedback was uploaded", ""],
  ["exit-diagnostic", `  ${diagnostic}\n  `, `  ${diagnostic}\n  `],
  ["exit-diagnostic", " \n\t", " \n\t"],
  ["missing-id", "Codex did not return a feedback ID"],
  ["malformed", "JSON"],
].entries()) {
  test(`upload ${scenario} case ${index + 1} leaves no temporary logs or running child`, async () => {
    const context = await setup();
    context.environment.FEEDBACK_SCENARIO = scenario!;
    if (stderr !== undefined) context.environment.FEEDBACK_STDERR = stderr;
    await expect(
      sendFeedback(context.options, context.startCodex),
    ).rejects.toThrow(message);
    const { attachments } = await context.transcript();
    expect(existsSync(attachments[0].path)).toBe(false);
    context.expectClosed();
  });
}

for (const [index, stderr] of [
  diagnostic,
  `  ${diagnostic}\n  `,
  " \n\t",
  "",
].entries()) {
  test(`stdin failure case ${index + 1} preserves ${stderr ? "stderr through cleanup" : "the transport error without stderr"}`, async () => {
    const context = await setup();
    const error = Object.assign(new Error("write EPIPE"), { code: "EPIPE" });
    const bytes = Buffer.from(stderr);
    const split = bytes.indexOf(0xc3) + 1;
    let closed = false;
    const child = Object.assign(new EventEmitter(), {
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      kill: () => {
        queueMicrotask(() => {
          child.stderr.end(bytes.subarray(split));
          child.stdout.end();
          closed = true;
          child.emit("close", 1, null);
        });
        return true;
      },
    });
    const operation = sendFeedback(context.options, () => {
      queueMicrotask(() => {
        child.stderr.write(bytes.subarray(0, split));
        child.stdin.emit("error", error);
      });
      return child as unknown as ChildProcessWithoutNullStreams;
    });
    if (stderr) {
      await expect(operation).rejects.toMatchObject({
        name: "CodexSecurityError",
        message: stderr,
        cause: error,
      });
    } else {
      await expect(operation).rejects.toBe(error);
    }
    expect(closed).toBe(true);
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
    sendFeedback(context.options, throwing("Must not start Codex")),
  ).rejects.toThrow("disabled by configuration");
});

test("sends feedback when saved session logs are unavailable", async () => {
  const context = await setup();
  await rm(join(context.home, "sessions"), { recursive: true });
  expect(await sendFeedback(context.options, context.startCodex)).toEqual({
    feedbackId: "feedback-1",
    scanId: "scan-1",
    includedLogs: true,
  });
  const { requests, attachments } = await context.transcript();
  expect(requests[2].params.includeLogs).toBe(true);
  expect(requests[2].params.extraLogFiles).toEqual([]);
  expect(attachments).toEqual([]);
  context.expectClosed();
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
