import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";
import { collectFeedbackLogs } from "../src/feedback-logs.js";
import {
  codexSecurityCredentialHome,
  codexSecurityStateDirectory,
} from "../src/runtime.js";

const fixture = fileURLToPath(
  new URL("fixtures/feedback-collector.mjs", import.meta.url),
);

test("collector streams to a private attachment with both resolved homes and helper environment", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-security-feedback-logs-"));
  try {
    const environment = {
      PATH: process.env["PATH"],
      CODEX_HOME: join(root, "original-home"),
      OPENAI_API_KEY: "SYNTHETIC_FEEDBACK_CREDENTIAL",
    };
    const path = join(root, "attachment.json");
    const collected = await collectFeedbackLogs(
      { scanId: "scan-1", path, environment, workingDirectory: root },
      (_command, args, options) => {
        expect(args.map((arg) => basename(arg))).toEqual([
          "collect_feedback.py",
        ]);
        return spawn(process.execPath, [fixture], options);
      },
    );
    expect(collected).toBe(true);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual({
      request: { scanIds: ["scan-1"] },
      codexHome: codexSecurityCredentialHome(environment),
      stateDirectory: codexSecurityStateDirectory(environment),
      utf8: "1",
      hasApiKey: false,
    });
    if (process.platform !== "win32")
      expect((await stat(path)).mode & 0o777).toBe(0o600);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("canceling collection stops the process before returning", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-security-feedback-cancel-"));
  try {
    const controller = new AbortController();
    let child: ChildProcess | undefined;
    await expect(
      collectFeedbackLogs(
        {
          scanId: "scan-1",
          path: join(root, "attachment.json"),
          environment: {
            PATH: process.env["PATH"],
            CODEX_HOME: join(root, "home"),
            COLLECTOR_SCENARIO: "cancel",
          },
          workingDirectory: root,
          signal: controller.signal,
        },
        (_command, _args, options) => {
          const started = spawn(process.execPath, [fixture], options);
          child = started;
          started.stderr!.once("data", () => controller.abort());
          return started;
        },
      ),
    ).rejects.toThrow("abort");
    expect(child!.exitCode !== null || child!.signalCode !== null).toBe(true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
