import { fixtureSpawn } from "./support/codex-process.js";
import { expect, spyOn, test } from "bun:test";
import * as childProcess from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPermissionCheckedCodex } from "../src/permission-profile.js";
import { ScanPermissionError } from "../src/scan-execution.js";

test("cancellation drains a preflight child that ignores graceful termination", async () => {
  const root = await mkdtemp(join(tmpdir(), "permission-stop-"));
  const executable = join(root, "synthetic-codex.exe");
  const script = join(root, "preflight.cjs");
  await writeFile(
    script,
    `
    process.on("SIGTERM", () => {});
    require("node:readline").createInterface({ input: process.stdin }).on("line", line => {
      const request = JSON.parse(line);
      if (request.method === "initialize") console.log(JSON.stringify({ id: request.id, result: {} }));
      if (request.method === "config/read") process.stderr.write("ready\\n");
    });
    setInterval(() => {}, 1000);
  `,
  );
  const ready = Promise.withResolvers<void>();
  let child: childProcess.ChildProcess | undefined;
  const spawning = spyOn(childProcess, "spawn").mockImplementation(
    fixtureSpawn(executable, script, (spawned) => {
      child = spawned;
      spawned.stderr!.on("data", (bytes: Buffer) => {
        if (bytes.toString().includes("ready")) ready.resolve();
      });
    }),
  );
  const controller = new AbortController();
  const codex = createPermissionCheckedCodex({
    codexPathOverride: executable,
    env: { PATH: process.env["PATH"] ?? "" },
    config: {
      default_permissions: "fixture",
      permissions: {
        fixture: { filesystem: { "/": "read" }, network: { enabled: false } },
      },
    },
  });
  const pending = codex
    .startThread({ workingDirectory: root })
    .runStreamed("inert fixture", { signal: controller.signal });
  // Observe the rejection immediately, including cleanup failures.
  const settled = pending.then(
    () => new Error("Unexpected scan execution"),
    (error) => error,
  );
  try {
    await ready.promise;
    const reason = new Error("synthetic cancellation");
    controller.abort(reason);
    expect(await settled).toBe(reason);
    expect(child!.exitCode !== null || child!.signalCode !== null).toBe(true);
  } finally {
    child?.kill("SIGKILL");
    await settled;
    spawning.mockRestore();
    await rm(root, { recursive: true, force: true });
  }
}, 10000);

test.each(
  [false, true].flatMap((resumed) =>
    ["exit", "RPC"].map((failure) => ({ resumed, failure })),
  ),
)(
  "preserves preflight diagnostics and drains children ($failure, resumed: $resumed)",
  async ({ resumed, failure: failureKind }) => {
    const root = await mkdtemp(join(tmpdir(), "permission-exit-"));
    const executable = join(root, "synthetic-codex.exe");
    const script = join(root, "preflight.cjs");
    await writeFile(
      script,
      `
      require("node:readline").createInterface({ input: process.stdin }).on("line", line => {
        const request = JSON.parse(line);
        if (request.method === "initialize") console.log(JSON.stringify({ id: request.id, result: {} }));
        if (request.method === "config/read") {
          process.stderr.write("synthetic preflight detail\\n");
          if (${JSON.stringify(failureKind)} === "RPC") {
            console.log(JSON.stringify({ id: request.id, error: { code: -32001, message: "synthetic RPC detail" } }));
            return;
          }
          const descendant = require("node:child_process").spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: ["ignore", "inherit", "inherit"] });
          process.stderr.write("descendant:" + descendant.pid + "\\n", () => process.exit(1));
        }
      });
    `,
    );
    let child: childProcess.ChildProcess | undefined;
    let descendantPid: number | undefined;
    let stderr = "";
    const spawning = spyOn(childProcess, "spawn").mockImplementation(
      fixtureSpawn(executable, script, (spawned) => {
        child = spawned;
        spawned.stderr!.on("data", (bytes: Buffer) => {
          stderr += bytes.toString();
          const match = /descendant:(\d+)\n/u.exec(stderr);
          if (match) descendantPid = Number(match[1]);
        });
      }),
    );
    const codex = createPermissionCheckedCodex({
      codexPathOverride: executable,
      env: { PATH: process.env["PATH"] ?? "" },
      config: {
        default_permissions: "fixture",
        permissions: {
          fixture: { filesystem: { "/": "read" }, network: { enabled: false } },
        },
      },
    });
    const threadOptions = { workingDirectory: root };
    const thread = resumed
      ? codex.resumeThread("synthetic-saved-thread", threadOptions)
      : codex.startThread(threadOptions);
    const pending = thread.runStreamed("inert fixture");
    const watchdog = Promise.withResolvers<never>();
    const timeout = setTimeout(
      () => watchdog.reject(new Error("Preflight did not stop after exiting")),
      5_000,
    );
    try {
      const failure = await Promise.race([pending, watchdog.promise]).catch(
        (error: unknown) => error,
      );
      expect(failure).toBeInstanceOf(Error);
      expect(failure).not.toBeInstanceOf(ScanPermissionError);
      expect((failure as Error).message).toContain(
        "synthetic preflight detail",
      );
      if (failureKind === "RPC") {
        expect((failure as Error).message).toContain('"code":-32001');
        expect((failure as Error).message).toContain("synthetic RPC detail");
      } else {
        expect((failure as Error).message).toContain(
          "Codex permission preflight ended before its response.",
        );
        expect(child!.exitCode).toBe(1);
        expect(descendantPid).toBeDefined();
      }
      expect(child!.exitCode !== null || child!.signalCode !== null).toBe(true);
      expect(child!.stdout!.destroyed).toBe(true);
      expect(spawning).toHaveBeenCalledTimes(1);
      expect(spawning.mock.calls[0]?.[2]).toMatchObject({
        cwd: root,
        windowsHide: true,
        env: expect.objectContaining({ PATH: process.env["PATH"] ?? "" }),
      });
    } finally {
      spawning.mockRestore();
      clearTimeout(timeout);
      child?.kill("SIGKILL");
      if (descendantPid !== undefined) {
        try {
          process.kill(descendantPid, "SIGKILL");
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
        }
      }
      await pending.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }
  },
  10000,
);
