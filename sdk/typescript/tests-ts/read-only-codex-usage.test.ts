import { afterEach, expect, spyOn, test } from "bun:test";
import type { Usage } from "@openai/codex-sdk";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import {
  createReadOnlyCodexSession,
  runReadOnlyCodex,
} from "../src/scan-comparison.js";
import * as runtimeCommands from "../src/runtime.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../src/thread-source.js";
import { nodeCommand } from "./support/shell.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const directories = createTemporaryDirectories();
afterEach(directories.cleanup);

const runtime = {
  surface: "cli",
  command: "exploitability check",
  threadSource: CODEX_SECURITY_THREAD_SOURCES.scan,
} as const;

function usage(
  input: number,
  cached: number,
  written: number,
  output: number,
  reasoning: number,
): Usage {
  return {
    input_tokens: input,
    cached_input_tokens: cached,
    cache_write_input_tokens: written,
    output_tokens: output,
    reasoning_output_tokens: reasoning,
  };
}

async function nativeFixture() {
  const home = await directories.create("codex-security-read-only-usage-");
  const fixture = join(home, "native-fixture.mjs");
  await writeFile(
    fixture,
    [
      'if (!process.argv.includes("--experimental-json")) process.exit(2);',
      'let prompt = "";',
      "for await (const chunk of process.stdin) prompt += chunk;",
      "const { thread, resumed, usage, fail } = JSON.parse(prompt);",
      'const resume = process.argv.indexOf("resume");',
      "if ((resume === -1 ? null : process.argv[resume + 1]) !== resumed) process.exit(3);",
      "const send = (event) => console.log(JSON.stringify(event));",
      'send({ type: "thread.started", thread_id: thread });',
      'if (fail) send({ type: "turn.failed", error: { message: "synthetic failure" } });',
      "else {",
      '  send({ type: "item.completed", item: { type: "agent_message", id: "reply", text: "{}" } });',
      '  if (usage) send({ type: "turn.completed", usage });',
      "}",
      "process.exit(0);",
    ].join("\n"),
  );
  const callbacks: Usage[] = [];
  return {
    callbacks,
    options: {
      workingDirectory: home,
      selectedEnvironment: {
        PATH: process.env["PATH"] ?? "",
        ...(process.env["SystemRoot"] === undefined
          ? {}
          : { SystemRoot: process.env["SystemRoot"] }),
        CODEX_HOME: home,
        CODEX_SECURITY_STATE_DIR: join(home, "state"),
        CODEX_CLI_PATH: nodeCommand().command,
        NODE_OPTIONS: "--import=" + pathToFileURL(fixture).href,
      },
      onUsage: (value: Usage) => callbacks.push(value),
    },
  };
}

async function withEmptyMcpPreflight<T>(run: () => Promise<T>): Promise<T> {
  const command = spyOn(runtimeCommands, "runCodexCommand").mockImplementation(
    async (_command, args) => {
      expect(args.slice(-3)).toEqual(["mcp", "list", "--json"]);
      return { success: true, exitCode: 0, stdout: "[]", stderr: "" };
    },
  );
  try {
    return await run();
  } finally {
    command.mockRestore();
  }
}

function prompt(
  thread: string,
  resumed: string | null,
  usage: Usage | null,
  fail = false,
) {
  return JSON.stringify({ thread, resumed, usage, fail });
}

test("native resumed read-only sessions report the difference between usage snapshots", async () => {
  const { callbacks, options } = await nativeFixture();
  const session = await withEmptyMcpPreflight(() =>
    createReadOnlyCodexSession(options, runtime),
  );
  const thread = "catalog";
  try {
    const first = usage(140, 75, 15, 25, 6);
    const second = usage(210, 105, 25, 44, 8);
    const zero = usage(0, 0, 0, 0, 0);
    await expect(session.run(prompt(thread, null, first), {})).resolves.toBe(
      "{}",
    );
    await session.run(prompt(thread, thread, second), {});
    await session.run(prompt(thread, thread, second), {});
    await session.run(prompt(thread, thread, null), {});
    await session.run(prompt(thread, thread, zero), {});
    await expect(
      session.run(prompt(thread, thread, null, true), {}),
    ).rejects.toThrow("synthetic failure");
    await session.run(prompt(thread, thread, usage(263, 136, 31, 60, 15)), {});
    expect(callbacks).toEqual([
      first,
      usage(70, 30, 10, 19, 2),
      zero,
      zero,
      usage(53, 31, 6, 16, 7),
    ]);
  } finally {
    await session.close();
  }
  await expect(session.run("{}", {})).rejects.toThrow("closed");
});

test("read-only usage starts a new baseline after a native counter or thread reset", async () => {
  const { callbacks, options } = await nativeFixture();
  const session = await withEmptyMcpPreflight(() =>
    createReadOnlyCodexSession(options, runtime),
  );
  const original = usage(140, 75, 15, 25, 6);
  const reset = usage(25, 10, 1, 7, 2);
  const replacement = usage(50, 20, 5, 20, 4);
  try {
    await session.run(prompt("first", null, original), {});
    await session.run(prompt("first", "first", reset), {});
    await session.run(prompt("first", "first", usage(36, 16, 2, 12, 3)), {});
    await session.run(prompt("replacement", "first", replacement), {});
    await session.run(
      prompt("replacement", "replacement", usage(69, 27, 7, 23, 5)),
      {},
    );
    await withEmptyMcpPreflight(() =>
      runReadOnlyCodex(
        prompt("one-shot", null, original),
        {},
        options,
        runtime,
      ),
    );
    expect(callbacks).toEqual([
      original,
      reset,
      usage(11, 6, 1, 5, 1),
      replacement,
      usage(19, 7, 2, 3, 1),
      original,
    ]);
  } finally {
    await session.close();
  }
});

test("read-only injected clients keep their per-turn usage callback contract", async () => {
  const turns = [usage(100, 25, 15, 8, 3), usage(160, 40, 20, 13, 5)];
  const callbacks: Usage[] = [];
  const session = await createReadOnlyCodexSession(
    {
      codex: {
        startThread() {
          const remaining = [...turns];
          return {
            id: "per-turn",
            run: async () => ({
              finalResponse: "{}",
              usage: remaining.shift() ?? null,
            }),
          };
        },
      },
      onUsage: (value) => callbacks.push(value),
    },
    runtime,
  );
  try {
    await session.run("first", {});
    await session.run("second", {});
    expect(callbacks).toEqual(turns);
  } finally {
    await session.close();
  }
});
