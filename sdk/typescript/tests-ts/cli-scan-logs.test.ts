import { writeJsonLines } from "./support/json.js";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Cli, Formatter, z } from "incur";
import { main } from "../src/cli.js";
import { scanLogsJson } from "../src/cli-scan-logs-json.js";
import { readSavedScanLogs } from "../src/scan-logs.js";
import { runWorkbench } from "../src/runtime.js";
import { VERSION } from "../src/version.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { pythonExecutable } from "./support/python.js";
import { throwing } from "./support/errors.js";
import { createCliTest } from "./support/cli-run.js";

async function fixture(desktop = false, archived = false, continuation = true) {
  const state = await realpath(await mkdtemp(join(tmpdir(), "saved-logs-")));
  const home = join(state, desktop ? "desktop-home" : "codex-home");
  const sessions = join(home, archived ? "archived_sessions" : "sessions");
  await mkdir(sessions, { recursive: true });
  const events = [
    { type: "session_meta", payload: { id: "thread-1" } },
    {
      type: "event_msg",
      payload: {
        message: 'full values: \" \\ \n \u0000 😀',
        nested: [null, false, 2],
      },
    },
  ];
  await writeJsonLines(join(sessions, "rollout.jsonl"), events);
  const scan = {
    scanId: "scan-1",
    ...(continuation ? { continuationThreadId: "thread-1" } : {}),
    threadIds: ["thread-1"],
  };
  const logs = await readSavedScanLogs(scan, home, { allowMissingRoot: true });
  const deps = dependencies({
    environment: {
      CODEX_SECURITY_STATE_DIR: state,
      CODEX_HOME: home,
    },
    onWorkbench: () => ({ scan }),
  });
  deps.createSecurity = throwing("Reading logs must not start Codex");
  return { state, home, sessions, logs, deps };
}

async function referenceOutput(args: string[], logs: unknown) {
  let text = "";
  await Cli.create("codex-security", { version: VERSION, update: false })
    .command(
      Cli.create("scans").command("logs", {
        args: z.object({ scanId: z.string() }),
        run: () => logs,
      }),
    )
    .serve(["scans", "logs", "scan-1", ...args], {
      stdout: (value) => {
        text += value;
      },
    });
  return text;
}

function withoutDuration(text: string) {
  const value = JSON.parse(text);
  value.meta.duration = "duration";
  return value;
}

describe("saved logs JSON output", () => {
  let dataHome: string;
  let previousDataHome: string | undefined;

  beforeEach(async () => {
    previousDataHome = process.env["XDG_DATA_HOME"];
    dataHome = await mkdtemp(join(tmpdir(), "saved-logs-data-"));
    process.env["XDG_DATA_HOME"] = dataHome;
  });

  afterEach(async () => {
    if (previousDataHome === undefined) delete process.env["XDG_DATA_HOME"];
    else process.env["XDG_DATA_HOME"] = previousDataHome;
    await rm(dataHome, { recursive: true, force: true });
  });

  test.each([
    [false, true],
    [true, true],
    [false, false],
    [true, false],
  ])(
    "reads Desktop logs archived=%p continuation=%p",
    async (archived, continuation) => {
      const f = await fixture(true, archived, continuation);
      try {
        await writeJsonLines(join(f.sessions, "unrelated.jsonl"), [
          {
            type: "session_meta",
            payload: {
              id: "unrelated",
              source: {
                subagent: { thread_spawn: { parent_thread_id: "thread-1" } },
              },
            },
          },
        ]);
        const { stdout, stderr, runCli } = createCliTest(main);
        expect(
          await runCli(["scans", "logs", "scan-1", "--json"], f.deps),
        ).toBe(0);
        expect(JSON.parse(stdout.text())).toEqual(f.logs);
        expect(stderr.text()).toBe("");
        await rm(f.sessions, { recursive: true });
        const absent = createCliTest(main);
        expect(await absent.runCli(["scans", "logs", "scan-1"], f.deps)).toBe(
          2,
        );
        expect(absent.stderr.text()).toContain("No saved session logs");
      } finally {
        await rm(f.state, { recursive: true, force: true });
      }
    },
  );

  test("preserves the stale installed-skills CTA after saved logs", async () => {
    const f = await fixture();
    try {
      const skillPath = join(f.state, "skills", "codex-security-scans");
      await mkdir(join(dataHome, "incur"), { recursive: true });
      await mkdir(skillPath, { recursive: true });
      await writeFile(
        join(skillPath, "SKILL.md"),
        "Previously installed skill.",
      );
      await writeFile(
        join(dataHome, "incur", "codex-security.json"),
        JSON.stringify({
          hash: "previous-command-hash",
          skills: ["codex-security-scans"],
          paths: [skillPath],
        }),
      );
      for (const args of [
        ["--json"],
        ["--format", "json"],
        ["--format=json"],
      ]) {
        const { stdout, stderr, runCli } = createCliTest(main);

        expect(await runCli(["scans", "logs", "scan-1", ...args], f.deps)).toBe(
          0,
        );
        const expected = await referenceOutput(["--json"], f.logs);
        expect(Object.keys(JSON.parse(expected))).toEqual([
          "scanId",
          "threadId",
          "sessions",
          "events",
          "cta",
        ]);
        expect(stdout.text()).toBe(expected);
        expect(stderr.text()).toBe("");
      }
    } finally {
      await rm(f.state, { recursive: true, force: true });
    }
  });

  test.each(
    [
      [],
      ["--json"],
      ["--format", "json"],
      ["--format=json"],
      ["--format", "toon"],
      ["--format", "jsonl"],
      ["--format", "yaml"],
      ["--format", "md"],
      ["--json", "--format", "toon"],
      ["--format", "toon", "--json"],
      ["--json", "--filter-output", "scanId"],
      ["--json", "--filter-output", "events[0,1]"],
      ["--json", "--filter-output", "missing"],
      ["--json", "--filter-output", "scanId,threadId"],
      ["--json", "--token-count"],
      ["--json", "--token-limit", "4"],
      ["--json", "--token-offset", "1", "--token-limit", "4"],
      ["--json", "--token-offset", "999999"],
      ["--json", "--token-limit", "999999"],
      ["--json", "--full-output"],
      ["--json", "--full-output", "--filter-output", "scanId"],
      ["--json", "--full-output", "--token-limit", "4"],
      ["--json", "--full-output", "--token-count"],
    ].map((args) => [args]),
  )("preserves Incur output for %j", async (args) => {
    const f = await fixture();
    try {
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(await runCli(["scans", "logs", "scan-1", ...args], f.deps)).toBe(
        0,
      );
      const expected = await referenceOutput(
        args.flatMap((arg) =>
          arg === "--format=json" ? ["--format", "json"] : [arg],
        ),
        f.logs,
      );
      if (args.includes("--full-output") && !args.includes("--token-count")) {
        expect(withoutDuration(stdout.text())).toEqual(
          withoutDuration(expected),
        );
      } else {
        expect(stdout.text()).toBe(expected);
      }
      if (args.length === 0) {
        expect(stderr.text()).toContain("scans show scan-1");
        expect(stderr.text()).toContain("scans logs scan-1");
      } else {
        expect(stderr.text()).toBe("");
      }
    } finally {
      await rm(f.state, { recursive: true, force: true });
    }
  });

  test.each(
    [
      ["--format", "invalid"],
      ["--format=invalid"],
      ["--json", "--token-limit", "invalid"],
      ["--json", "--token-offset", "invalid"],
      ["--json", "--filter-output"],
    ].map((args) => [args]),
  )("preserves invalid-option failure for %j", async (args) => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(["scans", "logs", "scan-1", ...args], dependencies()),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).not.toBe("");
  });

  test("formats empty session and event lists", async () => {
    const logs = {
      scanId: "scan-1",
      threadId: "thread-1",
      sessions: [],
      events: [],
    };
    const chunks = [];
    for await (const chunk of scanLogsJson(logs)) chunks.push(chunk);
    expect(Buffer.concat(chunks).toString()).toBe(
      `${Formatter.format(logs, "json")}\n`,
    );
  });

  test("waits for output backpressure and leaves the stream open", async () => {
    const f = await fixture();
    try {
      const chunks: Buffer[] = [];
      const output = new Writable({
        highWaterMark: 1,
        write(chunk, _encoding, callback) {
          setImmediate(() => {
            chunks.push(Buffer.from(chunk));
            callback();
          });
        },
      });
      expect(
        await main(
          ["scans", "logs", "scan-1", "--json"],
          output,
          capture().stream,
          f.deps,
        ),
      ).toBe(0);
      expect(Buffer.concat(chunks).toString()).toBe(
        `${Formatter.format(f.logs, "json")}\n`,
      );
      expect(output.writableEnded).toBe(false);
      expect(output.listenerCount("error")).toBe(0);
    } finally {
      await rm(f.state, { recursive: true, force: true });
    }
  });

  test("reports a failed output write", async () => {
    const f = await fixture();
    try {
      const stderr = capture();
      const output = new Writable({
        write(_chunk, _encoding, callback) {
          callback(new Error("synthetic write failure"));
        },
      });
      expect(
        await main(
          ["scans", "logs", "scan-1", "--json"],
          output,
          stderr.stream,
          f.deps,
        ),
      ).toBe(2);
      expect(stderr.text()).toContain("synthetic write failure");
    } finally {
      await rm(f.state, { recursive: true, force: true });
    }
  });

  test("writes a complete document larger than Node's maximum string", async () => {
    // Keep the bundle beneath the SDK so external dependencies resolve normally.
    const bundle = await mkdtemp(
      join(import.meta.dir, "..", ".logs-boundary-"),
    );
    const state = await mkdtemp(join(tmpdir(), "large-saved-logs-"));
    try {
      const built = await Bun.build({
        entrypoints: [join(import.meta.dir, "support", "cli-logs-large.mts")],
        outdir: bundle,
        target: "node",
        packages: "external",
      });
      expect(built.success).toBe(true);
      const result = await promisify(execFile)(
        "node",
        [
          "--input-type=module",
          "--eval",
          `await import(${JSON.stringify(pathToFileURL(built.outputs[0]!.path).href)})`,
          "synthetic-launcher",
          state,
        ],
        { encoding: "utf8" },
      );
      const proof = JSON.parse(result.stdout);
      expect(proof.exitCode).toBe(0);
      expect(proof.bytes).toBeGreaterThan(proof.maximumStringLength);
      expect(proof.bytes).toBe(proof.expectedBytes);
      expect(proof.sha256).toBe(proof.expectedSha256);
      expect(result.stderr).toBe("");
    } finally {
      await rm(bundle, { recursive: true, force: true });
      await rm(state, { recursive: true, force: true });
    }
  });
});

test("saved logs include the privately recorded worker home after recovery", async () => {
  const f = await fixture();
  try {
    const workerHome = join(f.state, "original-worker-home");
    await mkdir(join(workerHome, "sessions"), { recursive: true });
    const start = "2026-01-01T00:00:00Z";
    await writeJsonLines(join(workerHome, "sessions", "worker.jsonl"), [
      {
        type: "session_meta",
        payload: {
          id: "original-worker",
          source: {
            subagent: { thread_spawn: { parent_thread_id: "thread-1" } },
          },
        },
      },
      {
        type: "event_msg",
        timestamp: start,
        payload: { type: "task_started", turn_id: "worker-turn" },
      },
      {
        type: "event_msg",
        timestamp: start,
        payload: {
          type: "agent_message",
          message: "Synthetic original worker activity",
        },
      },
    ]);
    const scan = {
      scanId: "scan-1",
      continuationThreadId: "thread-1",
      mode: "deep",
      executionAttribution: {
        formatVersion: 1,
        executionThreadIds: ["thread-1", "original-worker"],
        owner: {
          threadId: "thread-1",
          turnId: "parent-turn",
          startedAt: start,
        },
        startedAt: start,
        completedAt: null,
      },
    };
    let privateSettingsRequested = false;
    f.deps.runWorkbench = async (
      _args,
      _input,
      _signal,
      _python,
      privateSettings,
    ) => {
      privateSettingsRequested = privateSettings === true;
      return {
        scan: {
          ...scan,
          executionAttribution: {
            ...scan.executionAttribution,
            ...(privateSettings ? { codexHome: workerHome } : {}),
          },
        },
      };
    };
    const { stdout, stderr, runCli } = createCliTest(main);
    expect(await runCli(["scans", "logs", "scan-1", "--json"], f.deps)).toBe(0);
    expect(privateSettingsRequested).toBe(true);
    const logs = JSON.parse(stdout.text());
    expect(
      logs.sessions.map((session: { threadId: string }) => session.threadId),
    ).toEqual(["thread-1", "original-worker"]);
    expect(
      logs.events.some(
        (entry: { threadId: string }) => entry.threadId === "original-worker",
      ),
    ).toBe(true);
    expect(logs).not.toHaveProperty("codexHome");
    expect(stderr.text()).toBe("");
  } finally {
    await rm(f.state, { recursive: true, force: true });
  }
});

test("saved logs remain readable for a future workflow without admitting execution", async () => {
  const f = await fixture();
  const target = await mkdtemp(join(tmpdir(), "saved-future-target-"));
  const python = pythonExecutable()!;
  const environment = {
    ...process.env,
    CODEX_SECURITY_STATE_DIR: f.state,
    CODEX_HOME: join(f.state, "codex-home"),
  };
  const options = { pluginRoot: PLUGIN_ROOT, python, environment };
  try {
    const begun = await runWorkbench(options, [
      "begin-deep-scan",
      "--thread-id",
      "thread-1",
      "--target-path",
      target,
      "--scan-root",
      join(f.state, "scans"),
    ]);
    const deepScan = begun["deepScan"] as { scanId: string; createdAt: string };
    const scanId = deepScan.scanId;
    await runWorkbench(options, [
      "set-scan-thread",
      "--scan-id",
      scanId,
      "--thread-id",
      "thread-1",
    ]);
    f.deps.environment = environment;
    await promisify(execFile)(
      python,
      [
        "-I",
        "-B",
        "-c",
        "import sqlite3, sys; connection = sqlite3.connect(sys.argv[1]); connection.execute(\"UPDATE deep_scan_runs SET workflow_version = 'future/v99', usage_owner_json = ?, execution_settings_json = ? WHERE scan_id = ?\", (sys.argv[3], sys.argv[4], sys.argv[2])); connection.commit(); connection.close()",
        join(f.state, "workbench.sqlite3"),
        scanId,
        JSON.stringify({
          threadId: "thread-1",
          turnId: "original",
          startedAt: deepScan.createdAt,
          dedicated: false,
        }),
        JSON.stringify({
          version: 1,
          settings: { codexHome: environment.CODEX_HOME, codexPath: python },
        }),
      ],
      { env: environment },
    );
    let privateSettingsRequested = false;
    f.deps.runWorkbench = async (
      args,
      input,
      signal,
      _python,
      privateSettings,
    ) => {
      privateSettingsRequested ||= privateSettings === true;
      return runWorkbench(
        { ...options, signal, withExecutionSettings: privateSettings },
        args,
        input,
      );
    };
    const { stdout, stderr, runCli } = createCliTest(main);
    const code = await runCli(["scans", "logs", scanId, "--json"], f.deps);
    expect(stderr.text()).toBe("");
    expect(code).toBe(0);
    expect(privateSettingsRequested).toBe(true);
    const logs = JSON.parse(stdout.text());
    expect(logs.scanId).toBe(scanId);
    expect(
      logs.sessions.map((session: { threadId: string }) => session.threadId),
    ).toEqual(["thread-1"]);
    expect(logs).not.toHaveProperty("codexHome");
    expect(stderr.text()).toBe("");
    await expect(
      runWorkbench(options, [
        "claim-deep-scan-coordinator",
        "--scan-id",
        scanId,
        "--thread-id",
        "thread-1",
      ]),
    ).rejects.toThrow("unsupported workflow");
  } finally {
    await rm(target, { recursive: true, force: true });
    await rm(f.state, { recursive: true, force: true });
  }
});
