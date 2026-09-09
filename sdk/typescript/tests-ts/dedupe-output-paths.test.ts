import { spawn } from "node:child_process";
import { mkdir, readdir, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, mock, test } from "bun:test";
import { DeduplicationReviewError } from "../src/errors.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { workflowFixture } from "./support/workflow-fixture.js";

test.each(["dedupe-locks", "dedupe"])(
  "dedupe preserves a completed scan inside its managed %s destination",
  async (destination) => {
    const name = `dedupe preserves a completed scan inside its managed ${destination} destination`;
    if (runTestInSubprocess(import.meta.path, name)) return;
    await using saved = await workflowFixture();
    const { environment, repository, root, document } = saved;
    await mkdir(environment.CODEX_SECURITY_STATE_DIR);
    const scanDir = join(environment.CODEX_SECURITY_STATE_DIR, destination);
    await rename(saved.scanDir, scanDir);
    await mkdir(environment.CODEX_HOME);
    await writeFile(
      join(environment.CODEX_HOME, "config.toml"),
      '[mcp_servers.synthetic]\ncommand="unused"\n',
    );
    const native = {
      ...(await import("../src/deduplication/codex-review.js")),
    };
    const fixture = fileURLToPath(
      new URL("fixtures/codex-review.mjs", import.meta.url),
    );
    let modelCalls = 0;
    mock.module("../src/deduplication/codex-review.js", () => ({
      ...native,
      CodexReviewRunner: class extends native.CodexReviewRunner {
        constructor(
          ...args: ConstructorParameters<typeof native.CodexReviewRunner>
        ) {
          const [
            environment,
            ,
            signal,
            workingDirectory,
            diagnosticsDirectory,
          ] = args;
          super(
            environment,
            (_command, _args, options) => {
              modelCalls++;
              return spawn(
                process.execPath,
                [fixture, "exit", join(root, "messages.jsonl"), repository],
                options,
              );
            },
            signal,
            workingDirectory,
            diagnosticsDirectory,
          );
        }
      },
    }));
    const { deduplicateScanDirectoryInternal } = await import(
      "../src/deduplication/scan.js"
    );
    const before = await readdir(scanDir, { recursive: true });
    let requests = 0;
    const error: unknown = await deduplicateScanDirectoryInternal(
      scanDir,
      { repository, findingsUrl: "http://synthetic.test" },
      {
        environment: { ...environment, OPENAI_API_KEY: "synthetic-review-key" },
        fetch: async () => {
          requests++;
          return Response.json({
            finding: document.findings[0],
            potentialDuplicates: [
              { ...document.findings[0], findingId: `csf_${"f".repeat(24)}` },
            ],
          });
        },
      },
    ).catch((failure: unknown) => failure);
    expect(await readdir(scanDir, { recursive: true })).toEqual(before);
    if (destination === "dedupe-locks") {
      expect(requests).toBe(0);
      expect(modelCalls).toBe(0);
      expect((error as Error).message).toContain(
        "outside the sealed scan artifacts",
      );
    } else {
      expect(modelCalls).toBe(1);
      expect(error).toBeInstanceOf(DeduplicationReviewError);
      expect((error as Error).message).toContain(
        "Codex exited before completing the review",
      );
      expect(
        (error as DeduplicationReviewError).metadata.diagnosticsPath,
      ).toBeUndefined();
    }
  },
);
