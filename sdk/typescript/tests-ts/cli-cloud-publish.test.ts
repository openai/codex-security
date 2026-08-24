import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  capture,
  dependencies,
  FakeSignals,
  SYNTHETIC_CREDENTIALS,
} from "./cli-fixtures.js";

const receipt = {
  scanId: "scan-1",
  findingIds: ["finding-1"],
  findingCount: 1,
};

describe("publish scan to Cloud", () => {
  test("publishes multiple explicit scans in order and deduplicates resolved paths", async () => {
    for (const dryRun of [false, true]) {
      const deps = dependencies({
        onWorkbench: () => {
          throw new Error("must not inspect scan history");
        },
      });
      deps.createSecurity = () => {
        throw new Error("must not initialize Codex");
      };
      deps.publishScan = async () => {
        throw new Error("must not publish to Linear");
      };
      const directories = ["scan one", "scan-two"].map((path) =>
        resolve(deps.currentDirectory(), path),
      );
      const calls: string[] = [];
      let publishing = false;
      const results = directories.map((scanDir, index) => ({
        scanDir,
        scanId: `scan-${index + 1}`,
        findingIds: dryRun ? [] : [`finding-${index + 1}`],
        findingCount: 1,
        ...(dryRun ? { dryRun: true as const, findings: [] } : {}),
      }));
      deps.publishScanToCloud = async (directory, options) => {
        expect(publishing).toBe(false);
        publishing = true;
        expect(directory).toBe(directories[calls.length]!);
        expect(options).toEqual({
          environment: deps.environment,
          dryRun,
          signal: expect.any(AbortSignal),
        });
        const { scanDir: _, ...result } = results[calls.length]!;
        calls.push(directory);
        await Promise.resolve();
        publishing = false;
        return result;
      };
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          [
            "publish",
            "scan",
            "scan one",
            "--to=cloud",
            "scan-two",
            "./scan one",
            "--json",
            ...(dryRun ? ["--dry-run"] : []),
          ],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
      expect(calls).toEqual(directories);
      expect(JSON.parse(stdout.text())).toEqual({
        results,
        failed: [],
        notAttempted: [],
      });
      expect(stderr.text()).toBe("");
    }
  });

  test("keeps receipts and continues after a failed scan without retrying", async () => {
    const deps = dependencies();
    const directories = ["scan-one", "scan-two", "scan-three"].map((path) =>
      resolve(deps.currentDirectory(), path),
    );
    const calls: string[] = [];
    deps.publishScanToCloud = async (directory) => {
      calls.push(directory);
      if (directory === directories[1]) {
        throw new Error(`Cloud failed: ${SYNTHETIC_CREDENTIALS}`);
      }
      return {
        ...receipt,
        scanId: directory === directories[0] ? "scan-1" : "scan-3",
      };
    };
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["publish", "scan", ...directories, "--to", "cloud", "--json"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(calls).toEqual(directories);
    expect(JSON.parse(stdout.text())).toEqual({
      results: [
        { scanDir: directories[0], ...receipt },
        { scanDir: directories[2], ...receipt, scanId: "scan-3" },
      ],
      failed: [{ scanDir: directories[1], error: "[redacted]" }],
      notAttempted: [],
    });
    expect(stderr.text()).toContain("[redacted]");
    expect(stderr.text()).not.toContain(SYNTHETIC_CREDENTIALS);
  });

  test.each([false, true])(
    "preserves batch receipts on cancellation with a confirmed response: %s",
    async (confirmed) => {
      for (const [signal, code] of [
        ["SIGINT", 130],
        ["SIGTERM", 143],
      ] as const) {
        const signals = new FakeSignals();
        const deps = dependencies({ signals });
        const directories = ["scan-one", "scan-two", "scan-three"].map((path) =>
          resolve(deps.currentDirectory(), path),
        );
        const calls: string[] = [];
        deps.publishScanToCloud = async (directory, options) => {
          calls.push(directory);
          if (directory === directories[1]) {
            signals.emit(signal);
            expect(options?.signal?.aborted).toBe(true);
            if (confirmed) return { ...receipt, scanId: "scan-2" };
            throw new Error(
              "Cloud publication was not confirmed. Check acceptance before resubmitting.",
            );
          }
          return receipt;
        };
        const stdout = capture();
        const stderr = capture();
        expect(
          await main(
            ["publish", "scan", ...directories, "--to", "cloud", "--json"],
            stdout.stream,
            stderr.stream,
            deps,
          ),
        ).toBe(code);
        expect(calls).toEqual(directories.slice(0, 2));
        expect(JSON.parse(stdout.text())).toEqual({
          results: [
            { scanDir: directories[0], ...receipt },
            ...(confirmed
              ? [{ scanDir: directories[1], ...receipt, scanId: "scan-2" }]
              : []),
          ],
          failed: confirmed
            ? []
            : [
                {
                  scanDir: directories[1],
                  error:
                    "Cloud publication was not confirmed. Check acceptance before resubmitting.",
                },
              ],
          notAttempted: [directories[2]],
        });
        expect(stderr.text()).toContain(
          signal === "SIGINT" ? "canceled" : "terminated",
        );
        expect(
          [...signals.listeners.values()].every(
            (listeners) => listeners.size === 0,
          ),
        ).toBe(true);
      }
    },
  );

  test("rejects multiple scans for Linear before publishing any findings", async () => {
    const deps = dependencies();
    let calls = 0;
    deps.publishScan = async () => {
      calls++;
      throw new Error("unexpected publication");
    };
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        [
          "publish",
          "scan",
          "scan-one",
          "scan-two",
          "--to",
          "linear",
          "--linear-team",
          "synthetic-team",
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(calls).toBe(0);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Multiple scan directories");
  });

  test("routes explicit scans to Cloud without initializing Codex or Linear", async () => {
    for (const destination of [["--to=cloud"], ["--to", "cloud"]]) {
      for (const dryRun of [false, true]) {
        const currentDirectory = join(tmpdir(), "cloud-publish-current");
        const deps = dependencies({
          currentDirectory,
          environment: { CODEX_SECURITY_LINEAR_API_KEY: " " },
          onWorkbench: () => {
            throw new Error("must not inspect scan history");
          },
        });
        deps.createSecurity = () => {
          throw new Error("must not initialize Codex");
        };
        deps.publishScan = async () => {
          throw new Error("must not publish to Linear");
        };
        let calls = 0;
        const result = dryRun
          ? { ...receipt, findingIds: [], dryRun: true as const, findings: [] }
          : receipt;
        deps.publishScanToCloud = async (directory, options) => {
          calls++;
          expect(directory).toBe(join(currentDirectory, "completed-scan"));
          expect(options).toEqual({
            environment: deps.environment,
            dryRun,
            signal: expect.any(AbortSignal),
          });
          return result;
        };
        const stdout = capture();
        const stderr = capture();
        expect(
          await main(
            [
              "publish",
              "scan",
              "completed-scan",
              ...destination,
              "--json",
              ...(dryRun ? ["--dry-run"] : []),
            ],
            stdout.stream,
            stderr.stream,
            deps,
          ),
        ).toBe(0);
        expect(calls).toBe(1);
        expect(JSON.parse(stdout.text())).toEqual(result);
        expect(stderr.text()).toBe("");
      }
    }
  });

  test("reuses the completed-scan picker when no directory is supplied", async () => {
    const root = await mkdtemp(join(tmpdir(), "cloud-publish-picker-"));
    const scanDir = join(root, "completed-scan");
    try {
      await mkdir(scanDir);
      const deps = dependencies({
        onWorkbench: (args) => {
          expect(args).toEqual(["list-scans", "--status", "complete"]);
          return {
            scans: [
              {
                scanId: "scan-1",
                scanDir,
                progress: { status: "complete" },
                findingCount: 1,
              },
            ],
          };
        },
      });
      let selections = 0;
      deps.publishPrompt = {
        isInteractive: () => true,
        select: async (_question, choices) => {
          selections++;
          const directories: string[] = choices.map(({ value }) => value);
          expect(directories).toEqual([scanDir]);
          return choices[0]!.value;
        },
      };
      deps.publishScanToCloud = async (directory) => {
        expect(directory).toBe(scanDir);
        return receipt;
      };
      const stdout = capture();
      expect(
        await main(
          ["publish", "scan", "--to", "cloud", "--json"],
          stdout.stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
      expect(selections).toBe(1);
      expect(JSON.parse(stdout.text())).toEqual(receipt);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("requests an explicit scan outside a terminal without suggesting Linear options", async () => {
    const deps = dependencies();
    deps.publishPrompt = {
      isInteractive: () => false,
      select: async () => {
        throw new Error("unexpected picker");
      },
    };
    deps.publishScanToCloud = async () => {
      throw new Error("unexpected publication");
    };
    const stderr = capture();
    expect(
      await main(
        ["publish", "scan", "--to", "cloud"],
        capture().stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("/path/to/sealed-scan --to cloud");
    expect(stderr.text()).not.toContain("--linear-team");
  });

  test("rejects Linear-specific options before uploading to Cloud", async () => {
    for (const flag of [
      "--linear-team",
      "--linear-project",
      "--project",
      "--linear-assignee",
      "--linear-api-key",
    ]) {
      const deps = dependencies();
      let calls = 0;
      deps.publishScanToCloud = async () => {
        calls++;
        return receipt;
      };
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          [
            "publish",
            "scan",
            "completed-scan",
            "--to",
            "cloud",
            flag,
            "synthetic-value",
          ],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(2);
      expect(calls).toBe(0);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain("cannot be combined with Linear options");
    }
  });

  test("keeps the internal Cloud destination out of help and discovery", async () => {
    for (const flag of ["--help", "--schema", "--llms", "--llms-full"]) {
      const stdout = capture();
      const deps = dependencies();
      deps.publishScanToCloud = async () => {
        throw new Error("unexpected publication");
      };
      expect(
        await main(
          ["publish", "scan", flag],
          stdout.stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
      expect(stdout.text().toLowerCase()).not.toContain("cloud");
    }
  });

  test("reports publication failures without leaking credentials or claiming success", async () => {
    const deps = dependencies();
    deps.publishScanToCloud = async () => {
      throw new Error(`Cloud failed: ${SYNTHETIC_CREDENTIALS}`);
    };
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["publish", "scan", "completed-scan", "--to", "cloud"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toBe("codex-security: [redacted]\n");
  });

  test("aborts Cloud publication and removes signal listeners", async () => {
    for (const [signal, code] of [
      ["SIGINT", 130],
      ["SIGTERM", 143],
    ] as const) {
      const signals = new FakeSignals();
      const deps = dependencies({ signals });
      deps.publishScanToCloud = async (_directory, options) => {
        signals.emit(signal);
        expect(options?.signal?.aborted).toBe(true);
        options?.signal?.throwIfAborted();
        return receipt;
      };
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          ["publish", "scan", "completed-scan", "--to", "cloud"],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(code);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(
        signal === "SIGINT" ? "canceled" : "terminated",
      );
      expect(
        [...signals.listeners.values()].every(
          (listeners) => listeners.size === 0,
        ),
      ).toBe(true);
    }
  });
});
