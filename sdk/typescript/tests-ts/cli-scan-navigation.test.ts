import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import { dependencies, fakeResult } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { writeJsonLines } from "./support/json.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

const completedId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const latestId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const startedAt = "2026-01-02T12:00:00Z";

describe("scan navigation", () => {
  test.each(["failed", "running"])(
    "identifies different default result and log selections when the latest scan is %s",
    async (status) => {
      const root = await temporaryDirectory("scan-navigation-");
      try {
        const home = join(root, "codex-home");
        await mkdir(join(home, "sessions"), { recursive: true });
        await writeJsonLines(join(home, "sessions", "rollout.jsonl"), [
          { type: "session_meta", payload: { id: "latest-thread" } },
          { type: "event_msg", payload: { message: "Saved scan activity" } },
        ]);
        const completed = {
          scanId: completedId,
          targetPath: join(root, "repository"),
          mode: "deep",
          startedAt: "2026-01-01T12:00:00Z",
          progress: { status: "complete" },
          findings: [],
        };
        const latest = {
          ...completed,
          scanId: latestId,
          continuationThreadId: "latest-thread",
          startedAt,
          progress: { status },
        };
        const calls: string[][] = [];
        const deps = dependencies({
          environment: { CODEX_HOME: home, CODEX_SECURITY_STATE_DIR: root },
          onWorkbench: (args): JsonObject => {
            calls.push([...args]);
            if (args[0] === "list-scans")
              return {
                scans: args.includes("complete")
                  ? [completed]
                  : [latest, completed],
              };
            return {
              scan: completedId.startsWith(args[2]!) ? completed : latest,
            };
          },
        });
        for (const interactive of [false, true]) {
          const show = createCliTest(main, { stdout: interactive });
          expect(await show.runCli(["scans", "show"], deps)).toBe(0);
          expect(show.stderr.text()).toContain(
            `Scan ${completedId} · complete`,
          );
          expect(show.stderr.text()).toContain(
            "Selected latest completed scan",
          );
          expect(show.stderr.text()).toContain(completed.startedAt);
          expect(show.stderr.text()).toContain(`scans logs ${completedId}`);
          expect(show.stderr.text()).not.toContain(latestId);

          const logs = createCliTest(main, { stdout: interactive });
          expect(await logs.runCli(["scans", "logs"], deps)).toBe(0);
          expect(logs.stderr.text()).toContain(`Scan ${latestId} · ${status}`);
          expect(logs.stderr.text()).toContain(
            "including failed and active runs",
          );
          expect(logs.stderr.text()).toContain(startedAt);
          expect(logs.stderr.text()).toContain(`scans show ${latestId}`);
          expect(logs.stderr.text()).not.toContain(completedId);
        }
        expect(
          calls.filter((args) => args[0] === "get-scan").map((args) => args[2]),
        ).toEqual([completedId, latestId, completedId, latestId]);

        for (const command of ["show", "logs"]) {
          const explicit = createCliTest(main);
          expect(
            await explicit.runCli(
              ["scans", command, latestId.slice(0, 8)],
              deps,
            ),
          ).toBe(0);
          expect(explicit.stderr.text()).toContain(`scans show ${latestId}`);
          expect(explicit.stderr.text()).toContain(`scans logs ${latestId}`);
          expect(explicit.stderr.text()).not.toContain("Selected latest");
        }
        const json = createCliTest(main);
        expect(await json.runCli(["scans", "show", "--json"], deps)).toBe(0);
        expect(JSON.parse(json.stdout.text())).toEqual(completed);
        expect(json.stderr.text()).toBe("");
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test("points to saved history when there are no completed scans", async () => {
    const cli = createCliTest(main);
    expect(await cli.runCli(["scans", "show"], dependencies())).toBe(2);
    expect(cli.stderr.text()).toContain("No completed scans");
    expect(cli.stderr.text()).toContain("codex-security scans list");
    expect(cli.stderr.text()).toContain("failed or active scans");
  });

  test("completion navigation uses the complete scan ID without changing JSON", async () => {
    const result = fakeResult(["high"], "partial");
    result.manifest.scan.id = completedId;
    const cli = createCliTest(main);
    expect(await cli.runCli(["scan", "--json"], dependencies({ result }))).toBe(
      2,
    );
    expect(JSON.parse(cli.stdout.text())).toEqual(result.toJSON());
    expect(cli.stderr.text()).toContain(`Scan ${completedId} · complete`);
    expect(cli.stderr.text()).toContain(result.manifest.scan.startedAt);
    expect(cli.stderr.text()).toContain(`scans show ${completedId}`);
    expect(cli.stderr.text()).toContain(`scans logs ${completedId}`);
    expect(cli.stderr.text()).toContain(result.scanDir);
  });

  test.each([false, true])(
    "identifies only the registered scan without a history lookup (custom prompts: %p)",
    async (customPrompts) => {
      const root = await temporaryDirectory("failed-scan-navigation-");
      try {
        const scanDir = join(root, "results");
        const repository = join(root, "repository");
        await mkdir(repository);
        const promptFile = join(root, "instructions.md");
        await writeFile(promptFile, "Review the authorized source.");
        const failure = "Reducer could not record its result";
        const cli = createCliTest(main);
        let lookups = 0;
        const deps = dependencies({
          currentDirectory: repository,
          onTurn: (_repository, options) => {
            options.onOutputDirReady?.(scanDir);
            options.onScanRegistered?.({
              scanId: latestId,
              scanDir,
              startedAt,
            });
            options.onProgress?.({
              phase: "discovery",
              filesCompleted: 1,
              filesTotal: 2,
            });
            throw new Error(failure);
          },
          onWorkbench: () => {
            lookups += 1;
            throw new Error("History unavailable");
          },
        });
        expect(
          await cli.runCli(
            [
              "scan",
              "--json",
              ...(customPrompts
                ? [
                    "--scan-prompt-file",
                    promptFile,
                    "--validation-prompt-file",
                    promptFile,
                  ]
                : []),
            ],
            deps,
          ),
        ).toBe(2);
        expect(lookups).toBe(0);
        expect(cli.stderr.text()).toContain(failure);
        expect(cli.stderr.text()).toContain(`Scan ${latestId}`);
        expect(cli.stderr.text()).toContain(startedAt);
        expect(cli.stderr.text()).toContain(
          "Last observed phase: reviewing files",
        );
        expect(cli.stderr.text()).toContain(`Retained results: ${scanDir}`);
        expect(cli.stderr.text()).toContain(`scans show ${latestId}`);
        expect(cli.stderr.text()).toContain(`scans logs ${latestId}`);
        expect(cli.stderr.text()).toContain("Inspect the saved scan status");
        expect(cli.stderr.text()).not.toContain("scans rerun");
        expect(cli.stderr.text()).not.toContain("scans resume");
        if (customPrompts) {
          expect(cli.stderr.text()).toContain(
            "original instructions via --scan-prompt-file and --validation-prompt-file",
          );
        }
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test.each([false, true])(
    "does not adopt another scan before registration (output ready: %p)",
    async (outputReady) => {
      const scanDir = join("/tmp", "shared-output-directory");
      const cli = createCliTest(main);
      let lookups = 0;
      const deps = dependencies({
        onTurn: (_repository, options) => {
          if (outputReady) options.onOutputDirReady?.(scanDir);
          throw new Error("Original scan registration failed");
        },
        onWorkbench: () => {
          lookups += 1;
          return { scans: [{ scanId: completedId, scanDir, startedAt }] };
        },
      });
      expect(await cli.runCli(["scan", "--json"], deps)).toBe(2);
      expect(cli.stderr.text()).toContain("Original scan registration failed");
      expect(cli.stderr.text()).not.toContain("scans show");
      expect(cli.stderr.text()).not.toContain(completedId);
      expect(lookups).toBe(0);
    },
  );
});
