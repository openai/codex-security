import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { sendFeedback } from "../src/feedback.js";
import { readSavedScanLogs } from "../src/scan-logs.js";
import { capture, dependencies } from "./cli-fixtures.js";
import {
  completedAt,
  terminalScanEvents,
  laterTurnEvents,
} from "./support/terminal-rollout.js";

const permissionFixture =
  process.platform !== "win32" && process.getuid?.() !== 0;

for (const fault of ["ENOTDIR", "EACCES"] as const) {
  for (const boundary of ["saved logs", "CLI", "feedback"] as const) {
    test.skipIf(fault === "EACCES" && !permissionFixture)(
      `${boundary} retains native logs after optional attribution ${fault}`,
      async () => {
        const state = await mkdtemp(join(tmpdir(), "scan-log-read-"));
        const home = join(state, "codex-home");
        const scan = {
          scanId: "scan-1",
          continuationThreadId: "thread-1",
          executionThreadIds: [],
          progress: { status: "complete", updatedAt: completedAt },
        };
        const directory = join(home, "scan-log-turns");
        const sidecar = join(
          directory,
          createHash("sha256").update(scan.scanId).digest("hex") + ".jsonl",
        );
        try {
          await mkdir(join(home, "sessions"), { recursive: true });
          const metadata = {
            type: "session_meta",
            payload: { id: "thread-1" },
          };
          const rollout = join(home, "sessions", "rollout.jsonl");
          await writeFile(
            rollout,
            [metadata, ...terminalScanEvents, ...laterTurnEvents]
              .map((event) => JSON.stringify(event))
              .join("\n"),
          );
          const original = await readFile(rollout);
          const expected = await readSavedScanLogs(scan, home);
          expect(expected.events.map(({ event }) => event)).toEqual([
            metadata,
            ...terminalScanEvents,
          ]);
          if (fault === "ENOTDIR")
            await writeFile(directory, "optional write destination is a file");
          else {
            await mkdir(directory);
            await writeFile(sidecar, "");
            await chmod(sidecar, 0);
          }
          await expect(readFile(sidecar)).rejects.toMatchObject({
            code: fault,
          });
          if (boundary === "saved logs") {
            expect(await readSavedScanLogs(scan, home)).toEqual(expected);
          } else if (boundary === "CLI") {
            const stdout = capture();
            const stderr = capture();
            const deps = dependencies({
              environment: { CODEX_SECURITY_STATE_DIR: state },
              onWorkbench: () => ({ scan }),
            });
            deps.createSecurity = () => {
              throw new Error("Saved logs must not start Codex");
            };
            expect(
              await main(
                ["scans", "logs", scan.scanId, "--json"],
                stdout.stream,
                stderr.stream,
                deps,
              ),
              stderr.text(),
            ).toBe(0);
            expect(JSON.parse(stdout.text())).toMatchObject(expected);
            expect(stderr.text()).toBe("");
          } else {
            const requestFile = join(state, "feedback.json");
            await sendFeedback(
              {
                reason: "Synthetic log read failure",
                includeLogs: true,
                scan,
                workingDirectory: state,
                environment: {
                  CODEX_SECURITY_STATE_DIR: state,
                  CODEX_HOME: home,
                  CODEX_CLI_PATH: process.execPath,
                  FEEDBACK_REQUEST_FILE: requestFile,
                  FEEDBACK_SCENARIO: "success",
                },
              },
              (_command, _args, options) =>
                spawn(
                  process.execPath,
                  [
                    fileURLToPath(
                      new URL("./fixtures/feedback.mjs", import.meta.url),
                    ),
                  ],
                  options,
                ),
            );
            const { attachments } = JSON.parse(
              await readFile(requestFile, "utf8"),
            );
            expect(attachments).toHaveLength(1);
            expect(JSON.parse(attachments[0].content)).toEqual(expected);
          }
          expect(await readFile(rollout)).toEqual(original);
        } finally {
          if (fault === "EACCES") await chmod(sidecar, 0o600).catch(() => {});
          await rm(state, { recursive: true, force: true });
        }
      },
    );
  }
}

test.skipIf(!permissionFixture)(
  "native rollout EACCES remains an error",
  async () => {
    const home = await mkdtemp(join(tmpdir(), "scan-native-read-"));
    const rollout = join(home, "sessions", "rollout.jsonl");
    try {
      await mkdir(join(home, "sessions"));
      await writeFile(
        rollout,
        JSON.stringify({ type: "session_meta", payload: { id: "root" } }),
      );
      await chmod(rollout, 0);
      await expect(
        readSavedScanLogs(
          { scanId: "scan-1", continuationThreadId: "root" },
          home,
        ),
      ).rejects.toMatchObject({ code: "EACCES" });
    } finally {
      await chmod(rollout, 0o600);
      await rm(home, { recursive: true, force: true });
    }
  },
);
