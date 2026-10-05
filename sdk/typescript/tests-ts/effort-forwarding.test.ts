import { Codex } from "@openai/codex-sdk";
import { afterEach, expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DEFAULT_CODEX_CONFIG, scanModelConfiguration } from "../src/config.js";
import {
  runReadOnlyCodex,
  type ReadOnlyCodexOptions,
} from "../src/scan-comparison.js";
import { nodeCommand } from "./support/shell.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const directories = createTemporaryDirectories();
afterEach(directories.cleanup);

test("forwards resolved efforts through the SDK independently for concurrent threads", async () => {
  const root = await directories.create("codex-security-effort-");
  const repository = join(root, "repository");
  const preload = join(root, "capture-codex.mjs");
  await mkdir(repository);
  await writeFile(
    preload,
    [
      "for await (const _chunk of process.stdin) {}",
      "const send = (event) => console.log(JSON.stringify(event));",
      'send({ type: "thread.started", thread_id: "fixture-thread" });',
      'send({ type: "item.completed", item: { id: "reply", type: "agent_message", text: JSON.stringify(process.argv.slice(2)) } });',
      'send({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } });',
      "process.exit(0);",
    ].join("\n"),
  );
  const codex = new Codex({
    codexPathOverride: nodeCommand().command,
    env: {
      NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
      ...(process.env["SystemRoot"] === undefined
        ? {}
        : { SystemRoot: process.env["SystemRoot"] }),
    },
  });
  const configuredProfile = {
    codexOverrides: {
      model: "fixture-global-model",
      model_reasoning_effort: "high",
      profile: "selected",
      profiles: {
        selected: {
          model: "fixture-future-model",
          model_reasoning_effort: "future-effort",
        },
      },
    },
  };
  const defaults = scanModelConfiguration(DEFAULT_CODEX_CONFIG);
  const cases: {
    options: ReadOnlyCodexOptions;
    model?: string;
    effort: string;
  }[] = [
    { options: {}, effort: "medium" },
    {
      options: { config: {} },
      model: defaults.model,
      effort: defaults.reasoningEffort,
    },
    {
      options: {
        config: {
          codexOverrides: {
            model: "fixture-legacy-model",
            model_reasoning_effort: "minimal",
          },
        },
      },
      model: "fixture-legacy-model",
      effort: "minimal",
    },
    {
      options: { config: configuredProfile },
      model: "fixture-future-model",
      effort: "future-effort",
    },
    {
      options: {
        config: configuredProfile,
        model: "fixture-explicit-model",
        reasoningEffort: "none",
      },
      model: "fixture-explicit-model",
      effort: "none",
    },
  ];

  await Promise.all(
    cases.map(async ({ options, model, effort }) => {
      const response = await runReadOnlyCodex(
        "Capture the invocation.",
        {},
        { ...options, codex, workingDirectory: repository },
        { surface: "sdk", threadSource: "security_scan_comparison" },
      );
      const args: string[] = JSON.parse(response);
      expect(
        args.filter((arg) => arg.startsWith("model_reasoning_effort=")),
      ).toEqual([`model_reasoning_effort=${JSON.stringify(effort)}`]);
      if (model === undefined) {
        expect(args).not.toContain("--model");
      } else {
        expect(args[args.indexOf("--model") + 1]).toBe(model);
      }
    }),
  );
});
