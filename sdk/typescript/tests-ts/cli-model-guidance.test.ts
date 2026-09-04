import { EventEmitter } from "node:events";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  mergedCodexConfig,
  scanModelConfiguration,
  type ScanModelConfiguration,
} from "../src/config.js";
import { CodexSecurityError } from "../src/errors.js";
import type { ScanOptions } from "../src/index.js";
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

function captureWarnings(isTTY = false) {
  const output = capture(isTTY);
  const warnings: string[] = [];
  return {
    ...output,
    warnings,
    stream: {
      ...output.stream,
      write(value: string | Uint8Array): boolean {
        const message = value.toString();
        if (message.startsWith("codex-security: warning:")) {
          warnings.push(message);
        }
        return output.stream.write(value);
      },
    },
  };
}

function runtimeWithGuidance(
  environment: NodeJS.ProcessEnv = {},
  callbacks: {
    onDiscovery?: () => void;
    onConfirmation?: () => void;
    beforeScanStart?: () => void;
    afterScanStart?: (options: ScanOptions) => void;
  } = {},
) {
  const deps = dependencies({
    environment,
    activities: [
      {
        id: "synthetic-read",
        kind: "command",
        status: "running",
        description: "Reading src/example.ts",
        paths: ["src/example.ts"],
      },
    ],
  });
  const originalCreate = deps.createSecurity;
  let selection: ScanModelConfiguration | undefined;
  let discoveries = 0;
  let confirmations = 0;
  const rawModes: boolean[] = [];
  const input = Object.assign(new EventEmitter(), {
    isTTY: true,
    isRaw: false,
    setRawMode(value: boolean) {
      rawModes.push(value);
      this.isRaw = value;
    },
  });
  deps.scanInput = input;
  deps.scanModelPrompt = {
    isInteractive: () => true,
    confirm: async (_question, defaultValue) => {
      expect(defaultValue).toBe(false);
      confirmations += 1;
      callbacks.onConfirmation?.();
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
              callbacks.onDiscovery?.();
              return models;
            },
            options.signal ?? new AbortController().signal,
          );
        }
        callbacks.beforeScanStart?.();
        return await runtime.run(repository, {
          ...options,
          onScanStarted: () => {
            options.onScanStarted?.();
            callbacks.afterScanStart?.(options);
          },
        });
      },
    };
  };
  return {
    deps,
    input,
    selection: () => selection,
    discoveries: () => discoveries,
    confirmations: () => confirmations,
    rawModes: () => rawModes,
  };
}

describe("CLI scan model guidance", () => {
  test("applies model and effort guidance with one warning and confirmation", async () => {
    const stderr = captureWarnings(true);
    const stages: string[] = [];
    const beforeDashboard = (stage: string) => {
      stages.push(stage);
      expect(stderr.text()).not.toContain("\u001B[?1049h");
      expect(stderr.text()).not.toContain("\u001B[?1049l");
      expect(runtime.rawModes()).toEqual([]);
    };
    const runtime = runtimeWithGuidance(
      {},
      {
        onDiscovery: () => beforeDashboard("catalog"),
        onConfirmation: () => beforeDashboard("confirmation"),
        beforeScanStart: () => beforeDashboard("before scan start"),
        afterScanStart: () => beforeDashboard("scan started"),
      },
    );
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
    expect(runtime.confirmations()).toBe(1);
    expect(runtime.discoveries()).toBe(1);
    expect(stderr.warnings).toHaveLength(1);
    expect(stderr.warnings[0]).toContain("scan-model-new");
    expect(stderr.warnings[0]).toContain("xhigh");
    expect(stages).toEqual([
      "catalog",
      "confirmation",
      "before scan start",
      "scan started",
    ]);
    expect(stderr.text().split("\u001B[?1049h")).toHaveLength(2);
    expect(stderr.text().split("\u001B[?1049l")).toHaveLength(2);
    expect(stderr.text().indexOf(stderr.warnings[0]!)).toBeLessThan(
      stderr.text().indexOf("\u001B[?1049h"),
    );
    expect(runtime.rawModes()).toEqual([true, false]);
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
    {
      name: "dumb terminal",
      argv: [],
      tty: true,
      environment: { TERM: "dumb" },
    },
    { name: "nonterminal", argv: [], tty: false, environment: {} },
  ])(
    "keeps selections and warns during $name scans",
    async ({ argv, tty, environment }) => {
      const runtime = runtimeWithGuidance(environment);
      const stdout = capture();
      const stderr = captureWarnings(tty);
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
      expect(stderr.warnings).toHaveLength(1);
      expect(stderr.warnings[0]).toContain("scan-model-new");
      expect(stderr.warnings[0]).toContain("xhigh");
      expect(stdout.text()).not.toContain("codex-security: warning:");
      expect(stderr.text()).not.toContain("\u001B");
      expect(stderr.text()).not.toContain("\r");
      expect(runtime.rawModes()).toEqual([]);
    },
  );

  test("keeps model guidance noninteractive when stdin is piped", async () => {
    const runtime = runtimeWithGuidance();
    runtime.input.isTTY = false;
    const stderr = captureWarnings(true);
    expect(
      await main(
        ["scan", "--model", "scan-model-old", "--effort", "high"],
        capture().stream,
        stderr.stream,
        runtime.deps,
      ),
    ).toBe(0);
    expect(runtime.selection()).toEqual({
      model: "scan-model-old",
      reasoningEffort: "high",
    });
    expect(runtime.confirmations()).toBe(0);
    expect(stderr.warnings).toHaveLength(1);
    expect(stderr.text()).not.toContain("\u001B");
    expect(stderr.text()).not.toContain("\r");
    expect(runtime.rawModes()).toEqual([]);
  });

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
      const stderr = captureWarnings(true);
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
          stderr.stream,
          runtime.deps,
        ),
      ).toBe(0);
      expect(runtime.confirmations()).toBe(0);
      expect(stderr.warnings).toHaveLength(1);
      expect(stderr.warnings[0]).toContain("scan-model-new");
      expect(stderr.warnings[0]).toContain("xhigh");
      expect(runtime.selection()).toEqual({
        model: "scan-model-old",
        reasoningEffort: "high",
      });
    },
  );

  test("canceling a model prompt cancels the scan with exit 130", async () => {
    const runtime = runtimeWithGuidance();
    const stderr = capture(true);
    runtime.deps.scanModelPrompt!.confirm = async () => {
      throw Object.assign(new Error("Prompt canceled"), {
        name: "ExitPromptError",
      });
    };
    expect(
      await main(
        ["scan", "--model", "scan-model-old", "--effort", "high"],
        capture().stream,
        stderr.stream,
        runtime.deps,
      ),
    ).toBe(130);
    expect(runtime.selection()).toBeUndefined();
    expect(stderr.text()).not.toContain("\u001B[?1049h");
    expect(stderr.text()).not.toContain("\u001B[?1049l");
    expect(runtime.rawModes()).toEqual([]);
  });

  test.each(["before", "after"] as const)(
    "a failure %s the scan starts but before activity reports its error without entering the dashboard",
    async (stage) => {
      const stderr = capture(true);
      const stdout = capture();
      const fail = () => {
        throw new CodexSecurityError("Synthetic scan preparation failed.");
      };
      const runtime = runtimeWithGuidance(
        {},
        stage === "before"
          ? { beforeScanStart: fail }
          : { afterScanStart: fail },
      );
      expect(
        await main(
          ["scan", "--model", "scan-model-old", "--effort", "high"],
          stdout.stream,
          stderr.stream,
          runtime.deps,
        ),
      ).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain("Synthetic scan preparation failed.");
      expect(stderr.text()).not.toContain("\u001B[?1049h");
      expect(stderr.text()).not.toContain("\u001B[?1049l");
      expect(runtime.confirmations()).toBe(1);
      expect(runtime.rawModes()).toEqual([]);
    },
  );

  test("prints preparation retries, observer warnings, and archived output before a failure", async () => {
    const stdout = capture();
    const stderr = capture(true);
    let preparationOutput = "";
    const runtime = runtimeWithGuidance(
      {},
      {
        afterScanStart: (options) => {
          options.onReconnect?.(1, 3, { reason: "network" });
          options.onObserverError?.(
            "onWorkerStatus",
            new Error("Synthetic observer failure."),
          );
          options.onOutputArchived?.("/synthetic/previous-scan");
          preparationOutput = stderr.text();
          throw new CodexSecurityError("Synthetic scan preparation failed.");
        },
      },
    );
    expect(
      await main(
        ["scan", "--model", "scan-model-old", "--effort", "high"],
        stdout.stream,
        stderr.stream,
        runtime.deps,
      ),
    ).toBe(2);
    expect(preparationOutput).toContain(
      "Network connection interrupted; retrying (1/3).",
    );
    expect(preparationOutput).toContain("Synthetic observer failure.");
    expect(preparationOutput).toContain(
      "Moved existing results to: /synthetic/previous-scan",
    );
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Synthetic scan preparation failed.");
    expect(stderr.text()).not.toContain("\u001B");
    expect(runtime.rawModes()).toEqual([]);
  });

  test("a terminal failure when starting the dashboard does not stop the scan", async () => {
    const runtime = runtimeWithGuidance();
    const stderr = capture(true);
    let starts = 0;
    const stream = {
      ...stderr.stream,
      write(value: string | Uint8Array): boolean {
        if (value.toString().includes("\u001B[?1049h")) {
          starts += 1;
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
    expect(starts).toBe(1);
    expect(stderr.text()).toContain("Running scan");
    expect(runtime.selection()).toEqual({
      model: "scan-model-new",
      reasoningEffort: "xhigh",
    });
  });
});
