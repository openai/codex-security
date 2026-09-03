import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  mergedCodexConfig,
  scanModelConfiguration,
  type ScanModelConfiguration,
} from "../src/config.js";
import type { CatalogModel } from "../src/model-catalog.js";
import { capture, dependencies } from "./cli-fixtures.js";

const models: CatalogModel[] = [
  {
    id: "scan-model-old",
    model: "scan-model-old",
    hidden: false,
    upgrade: "scan-model-new",
    defaultReasoningEffort: "high",
    supportedReasoningEfforts: ["high", "xhigh"].map((reasoningEffort) => ({
      reasoningEffort,
    })),
  },
  {
    id: "scan-model-new",
    model: "scan-model-new",
    hidden: false,
    defaultReasoningEffort: "high",
    supportedReasoningEfforts: ["high", "xhigh"].map((reasoningEffort) => ({
      reasoningEffort,
    })),
  },
];

function runtimeWithGuidance(environment: NodeJS.ProcessEnv = {}) {
  const deps = dependencies({ environment });
  const originalCreate = deps.createSecurity;
  let selection: ScanModelConfiguration | undefined;
  let discoveries = 0;
  let confirmations = 0;
  deps.scanModelPrompt = {
    isInteractive: () => true,
    confirm: async () => {
      confirmations += 1;
      return true;
    },
  };
  deps.createSecurity = (config, selector) => {
    const runtime = originalCreate(config);
    return {
      ...runtime,
      run: async (repository, options = {}) => {
        if (selector !== undefined) {
          selection = await selector(
            scanModelConfiguration(await mergedCodexConfig(config)),
            async () => {
              discoveries += 1;
              return models;
            },
            options.signal ?? new AbortController().signal,
          );
        }
        return await runtime.run(repository, options);
      },
    };
  };
  return {
    deps,
    selection: () => selection,
    discoveries: () => discoveries,
    confirmations: () => confirmations,
  };
}

describe("CLI scan model guidance", () => {
  test("passes accepted per-scan model and effort selections to the runtime", async () => {
    const runtime = runtimeWithGuidance();
    const stderr = capture(true);
    expect(
      await main(
        ["scan", "--model", "scan-model-old", "--effort", "high"],
        capture().stream,
        stderr.stream,
        runtime.deps,
      ),
    ).toBe(0);
    expect(runtime.selection()).toEqual({
      model: "scan-model-new",
      reasoningEffort: "xhigh",
    });
    expect(runtime.confirmations()).toBe(2);
    expect(runtime.discoveries()).toBe(1);
  });

  test.each([
    { name: "headless", argv: ["--headless"], tty: true, environment: {} },
    { name: "JSON", argv: ["--json"], tty: true, environment: {} },
    {
      name: "JSON lines",
      argv: ["--format", "jsonl"],
      tty: true,
      environment: {},
    },
    { name: "CI", argv: [], tty: true, environment: { CI: "true" } },
    { name: "nonterminal", argv: [], tty: false, environment: {} },
  ])(
    "keeps selections and warns during $name scans",
    async ({ argv, tty, environment }) => {
      const runtime = runtimeWithGuidance(environment);
      const stdout = capture();
      const stderr = capture(tty);
      expect(
        await main(
          ["scan", "--model", "scan-model-old", "--effort", "high", ...argv],
          stdout.stream,
          stderr.stream,
          runtime.deps,
        ),
      ).toBe(0);
      expect(runtime.selection()).toEqual({
        model: "scan-model-old",
        reasoningEffort: "high",
      });
      expect(runtime.confirmations()).toBe(0);
      expect(stderr.text()).toContain("scan-model-new");
      expect(stderr.text()).toContain("xhigh");
      expect(stdout.text()).not.toContain("codex-security: warning:");
    },
  );

  test("dry runs do not discover models or prompt", async () => {
    const runtime = runtimeWithGuidance();
    expect(
      await main(
        ["scan", "--dry-run", "--model", "scan-model-old", "--effort", "high"],
        capture().stream,
        capture(true).stream,
        runtime.deps,
      ),
    ).toBe(0);
    expect(runtime.discoveries()).toBe(0);
    expect(runtime.confirmations()).toBe(0);
    expect(runtime.selection()).toBeUndefined();
  });

  test.each([
    { outputArguments: ["--json"] },
    { outputArguments: ["--format", "jsonl"] },
  ])(
    "reruns with %j warn without model prompts",
    async ({ outputArguments }) => {
      const runtime = runtimeWithGuidance();
      runtime.deps.runWorkbench = async () => ({
        recipe: {
          repository: "/synthetic/repository",
          target: { kind: "repository", paths: [] },
          mode: "standard",
          config: { model: "scan-model-old", model_reasoning_effort: "high" },
        },
      });
      expect(
        await main(
          ["scans", "rerun", "scan-original", ...outputArguments],
          capture().stream,
          capture(true).stream,
          runtime.deps,
        ),
      ).toBe(0);
      expect(runtime.confirmations()).toBe(0);
      expect(runtime.selection()).toEqual({
        model: "scan-model-old",
        reasoningEffort: "high",
      });
    },
  );

  test("canceling a model prompt cancels the scan with exit 130", async () => {
    const runtime = runtimeWithGuidance();
    runtime.deps.scanModelPrompt!.confirm = async () => {
      throw Object.assign(new Error("Prompt canceled"), {
        name: "ExitPromptError",
      });
    };
    expect(
      await main(
        ["scan", "--model", "scan-model-old", "--effort", "high"],
        capture().stream,
        capture(true).stream,
        runtime.deps,
      ),
    ).toBe(130);
    expect(runtime.selection()).toBeUndefined();
  });

  test("a terminal failure when resuming the dashboard does not stop the scan", async () => {
    const runtime = runtimeWithGuidance();
    const stderr = capture(true);
    let starts = 0;
    const stream = {
      ...stderr.stream,
      write(value: string | Uint8Array): boolean {
        if (value.toString().includes("\u001B[?1049h") && ++starts > 1) {
          throw new Error("Terminal is closed");
        }
        return stderr.stream.write(value);
      },
    };
    expect(
      await main(
        ["scan", "--model", "scan-model-old", "--effort", "high"],
        capture().stream,
        stream,
        runtime.deps,
      ),
    ).toBe(0);
    expect(starts).toBeGreaterThan(1);
    expect(runtime.selection()).toEqual({
      model: "scan-model-new",
      reasoningEffort: "xhigh",
    });
  });
});
