import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type { ScanOptions } from "../src/index.js";
import { dependencies } from "./cli-fixtures.js";
import { runCapturedCli } from "./support/cli-run.js";

test.each(["scan", "resume"])(
  "%s forwards diagnostics only when this invocation requests them",
  async (command) => {
    for (const enabled of [true, false]) {
      let received: ScanOptions | undefined;
      const deps = dependencies({
        onTurn: (_repository, options) => {
          received = options;
        },
        onWorkbench: () => ({
          scanId: "scan-original",
          scanDir: "/synthetic/scan-output",
          recipe: {
            repository: "/synthetic/repository",
            target: { kind: "repository", paths: [] },
            mode: "deep",
            config: {},
            // A saved recipe must not silently enable capture in a later invocation.
            diagnostics: true,
          },
        }),
      });
      expect(
        await runCapturedCli(
          main,
          [
            ...(command === "scan"
              ? ["scan", "."]
              : ["scans", "resume", "scan-original"]),
            ...(enabled ? ["--diagnostics"] : []),
            "--json",
          ],
          deps,
        ),
      ).toBe(0);
      expect(received?.diagnostics).toBe(enabled ? true : undefined);
    }
  },
);
