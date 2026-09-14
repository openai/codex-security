import { execFile } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { describe, expect, test } from "bun:test";
import { Cli, Formatter, z } from "incur";
import { main } from "../src/cli.js";
import { scanLogsJson } from "../src/cli-scan-logs-json.js";
import { readSavedScanLogs } from "../src/scan-logs.js";
import { VERSION } from "../src/version.js";
import { capture, dependencies } from "./cli-fixtures.js";

async function fixture(attributedOwner = false) {
  const state = await realpath(await mkdtemp(join(tmpdir(), "saved-logs-")));
  const home = join(state, "codex-home");
  await mkdir(join(home, "sessions"), { recursive: true });
  const events: Record<string, unknown>[] = [
    { type: "session_meta", payload: { id: "thread-1" } },
    {
      type: "event_msg",
      payload: {
        message: 'full values: \" \\ \n \u0000 😀',
        nested: [null, false, 2],
      },
    },
  ];
  const timestamp = "2026-08-11T12:01:00.000Z";
  if (attributedOwner) {
    events.splice(1, 0, {
      type: "turn_context",
      timestamp,
      payload: { turn_id: "scan-turn" },
    });
    Object.assign(events.at(-1)!, { timestamp });
  }
  await writeFile(
    join(home, "sessions", "rollout.jsonl"),
    events.map((event) => JSON.stringify(event)).join("\n"),
  );
  const originalHome = join(state, "original-home");
  const scanDir = join(state, "scan");
  const settingsDirectory = join(scanDir, "artifacts", "deep_discovery");
  await mkdir(settingsDirectory, { recursive: true });
  await mkdir(join(originalHome, "sessions"), { recursive: true });
  let ownerEvents = events;
  if (attributedOwner) {
    const repeated = {
      type: "event_msg",
      timestamp,
      payload: { message: "repeated scan occurrence" },
    };
    ownerEvents = [
      ...events,
      repeated,
      repeated,
      {
        type: "event_msg",
        timestamp,
        payload: { message: "recorded non-usage suffix" },
      },
    ];
    await writeFile(
      join(home, "sessions", "rollout.jsonl"),
      [
        ...events,
        { type: "turn_context", timestamp, payload: { turn_id: "other-turn" } },
        {
          type: "event_msg",
          timestamp,
          payload: { message: "unrelated first-copy suffix" },
        },
      ]
        .map((event) => JSON.stringify(event))
        .join("\n"),
    );
    await writeFile(
      join(originalHome, "sessions", "owner.jsonl"),
      ownerEvents.map((event) => JSON.stringify(event)).join("\n"),
    );
  }
  await writeFile(
    join(settingsDirectory, "execution-settings.json"),
    JSON.stringify({
      version: 1,
      settings: {
        codexHome: originalHome,
        codexPath: join(originalHome, "codex"),
      },
    }),
  );
  await writeFile(
    join(home, "sessions", "worker.jsonl"),
    JSON.stringify({ type: "session_meta", payload: { id: "worker" } }) + "\n",
  );
  await writeFile(
    join(originalHome, "sessions", "worker.jsonl"),
    [
      { type: "session_meta", payload: { id: "worker" } },
      { type: "event_msg", payload: { message: "recorded worker suffix" } },
    ]
      .map((event) => JSON.stringify(event) + "\n")
      .join(""),
  );
  const scan = {
    scanId: "scan-1",
    continuationThreadId: "thread-1",
    mode: "deep",
    scanDir,
    executionThreadIds: ["worker"],
    ...(attributedOwner
      ? {
          executionAttribution: {
            formatVersion: 1 as const,
            executionThreadIds: ["worker"],
            owner: {
              threadId: "thread-1",
              turnId: "scan-turn",
              startedAt: timestamp,
            },
            startedAt: timestamp,
            completedAt: timestamp,
          },
        }
      : {}),
  };
  const logs = await readSavedScanLogs(scan, [home, originalHome]);
  const deps = dependencies({
    environment: { CODEX_SECURITY_STATE_DIR: state },
    onWorkbench: () => ({ scan }),
  });
  deps.createSecurity = () => {
    throw new Error("Reading logs must not start Codex");
  };
  return { state, logs, deps, ownerEvents };
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
  test("selects the recorded owner suffix after scan attribution through the saved logs command", async () => {
    const f = await fixture(true);
    try {
      const stdout = capture();
      expect(
        await main(
          ["scans", "logs", "scan-1", "--json"],
          stdout.stream,
          capture().stream,
          f.deps,
        ),
      ).toBe(0);
      const result = JSON.parse(stdout.text());
      expect(
        result.sessions.map(({ threadId }: { threadId: string }) => threadId),
      ).toEqual(["worker", "thread-1"]);
      expect(
        result.events
          .filter(
            ({ threadId }: { threadId: string }) => threadId === "thread-1",
          )
          .map(({ event }: { event: unknown }) => event),
      ).toEqual(f.ownerEvents);
    } finally {
      await rm(f.state, { recursive: true, force: true });
    }
  });

  test("loads the same-thread recorded worker suffix through the saved logs command", async () => {
    const f = await fixture();
    try {
      const stdout = capture();
      expect(
        await main(
          ["scans", "logs", "scan-1", "--json"],
          stdout.stream,
          capture().stream,
          f.deps,
        ),
      ).toBe(0);
      expect(
        JSON.parse(stdout.text()).sessions.map(
          ({ threadId }: { threadId: string }) => threadId,
        ),
      ).toEqual(["thread-1", "worker"]);
      expect(JSON.parse(stdout.text()).events).toContainEqual({
        threadId: "worker",
        event: {
          type: "event_msg",
          payload: { message: "recorded worker suffix" },
        },
      });
    } finally {
      await rm(f.state, { recursive: true, force: true });
    }
  });

  test("preserves the stale installed-skills CTA after saved logs", async () => {
    const f = await fixture();
    const previousDataHome = process.env["XDG_DATA_HOME"];
    try {
      const dataHome = join(f.state, "data");
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
      process.env["XDG_DATA_HOME"] = dataHome;
      for (const args of [
        ["--json"],
        ["--format", "json"],
        ["--format=json"],
      ]) {
        const stdout = capture();
        const stderr = capture();
        expect(
          await main(
            ["scans", "logs", "scan-1", ...args],
            stdout.stream,
            stderr.stream,
            f.deps,
          ),
        ).toBe(0);
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
      if (previousDataHome === undefined) delete process.env["XDG_DATA_HOME"];
      else process.env["XDG_DATA_HOME"] = previousDataHome;
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
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          ["scans", "logs", "scan-1", ...args],
          stdout.stream,
          stderr.stream,
          f.deps,
        ),
      ).toBe(0);
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
      expect(stderr.text()).toBe("");
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
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["scans", "logs", "scan-1", ...args],
        stdout.stream,
        stderr.stream,
        dependencies(),
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).not.toBe("");
  });

  test("preserves JSON conversion and empty arrays", async () => {
    const f = await fixture();
    try {
      f.logs.events.push({
        threadId: "thread-1",
        event: {
          bigint: 42n,
          missing: undefined,
          values: [NaN, Infinity, -0],
        },
      });
      for (const logs of [f.logs, { ...f.logs, sessions: [], events: [] }]) {
        const chunks = [];
        for await (const chunk of scanLogsJson(logs))
          chunks.push(Buffer.from(chunk));
        expect(Buffer.concat(chunks).toString()).toBe(
          `${Formatter.format(logs, "json")}\n`,
        );
      }
    } finally {
      await rm(f.state, { recursive: true, force: true });
    }
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
