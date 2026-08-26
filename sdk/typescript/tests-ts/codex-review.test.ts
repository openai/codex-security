import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";
import { CodexReviewRunner } from "../src/server/codex-review.js";

const fixture = fileURLToPath(
  new URL("fixtures/codex-review.mjs", import.meta.url),
);

for (const scenario of ["correction", "text-only", "failed-turn", "exit"]) {
  test(`Codex review transport: ${scenario}`, async () => {
    const modelHome = await mkdtemp(join(tmpdir(), "codex-review-test-"));
    const transcript = join(modelHome, "messages.jsonl");
    let child: ChildProcessWithoutNullStreams | undefined;
    let directory: string | undefined;
    let args: readonly string[] = [];
    try {
      await writeFile(
        join(modelHome, "config.toml"),
        '[mcp_servers.synthetic]\ncommand = "synthetic-unused-command"\n',
      );
      const runner = new CodexReviewRunner(
        {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          TEMP: process.env["TEMP"],
          TMP: process.env["TMP"],
          CODEX_HOME: modelHome,
          OPENAI_API_KEY: "synthetic-review-key",
        },
        (_command, commandArgs, options) => {
          args = commandArgs;
          directory = String(options.cwd);
          child = spawn(
            process.execPath,
            [fixture, scenario, transcript],
            options,
          );
          return child;
        },
      );
      let validations = 0;
      const result = runner.run({
        model: "gpt-5.6-sol",
        effort: "ultra",
        prompt: "Review the supplied synthetic reports.",
        schema: {
          type: "object",
          properties: { decision: { enum: ["SAME", "DISTINCT"] } },
          required: ["decision"],
          additionalProperties: false,
        },
        validate(value: unknown) {
          validations++;
          if (
            typeof value !== "object" ||
            value === null ||
            !("decision" in value) ||
            value.decision !== "SAME"
          )
            throw new Error("Invalid decision");
          return { decision: value.decision };
        },
      });
      if (scenario === "correction") {
        expect(await result).toEqual({ decision: "SAME" });
        expect(validations).toBe(2);
      } else {
        await expect(result).rejects.toMatchObject({
          code: "deduplication_failed",
          message:
            "Codex did not complete a validated deduplication review. The imported findings remain stored; retry the request.",
        });
        expect(validations).toBe(scenario === "failed-turn" ? 1 : 0);
      }
      expect(args).toContain('cli_auth_credentials_store="ephemeral"');
      expect(args.join(" ")).not.toContain("synthetic-review-key");
      expect(await readFile(transcript, "utf8")).toContain(
        '"method":"account/login/start"',
      );
      expect(existsSync(join(modelHome, "auth.json"))).toBe(false);
      expect(child!.exitCode !== null || child!.signalCode !== null).toBe(true);
      expect(existsSync(directory!)).toBe(false);
    } finally {
      await rm(modelHome, { recursive: true, force: true });
    }
  });
}
