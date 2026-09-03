import { describe, expect, test } from "bun:test";
import type { BulkScanPrompt } from "../src/bulk-scan-discovery.js";
import { createScanModelSelector } from "../src/cli-model-selection.js";
import { DEFAULT_CODEX_CONFIG, scanModelConfiguration } from "../src/config.js";
import type { CatalogModel } from "../src/model-catalog.js";

function catalogModel(
  model: string,
  overrides: Partial<CatalogModel> = {},
): CatalogModel {
  return {
    id: model,
    model,
    hidden: false,
    supportedReasoningEfforts: ["high", "xhigh"].map((reasoningEffort) => ({
      reasoningEffort,
    })),
    defaultReasoningEffort: "high",
    ...overrides,
  };
}

function upgradeModels() {
  return [
    catalogModel("model-old", { upgrade: "model-new" }),
    catalogModel("model-new"),
  ];
}

function fixture(
  options: {
    interactive?: boolean;
    terminalInteractive?: boolean;
    maxCostUsd?: number;
    answers?: boolean[];
    confirm?: BulkScanPrompt["confirm"];
    write?: (message: string) => void;
  } = {},
) {
  const warnings: string[] = [];
  const confirmations: {
    question: string;
    defaultValue: boolean | undefined;
    signal: AbortSignal | undefined;
  }[] = [];
  const controller = new AbortController();
  const select = createScanModelSelector({
    interactive: options.interactive ?? true,
    maxCostUsd: options.maxCostUsd,
    prompt: {
      isInteractive: () => options.terminalInteractive ?? true,
      async confirm(question, defaultValue, signal) {
        const index = confirmations.length;
        confirmations.push({ question, defaultValue, signal });
        return options.confirm === undefined
          ? options.answers?.[index] ?? false
          : await options.confirm(question, defaultValue, signal);
      },
    },
    write: options.write ?? ((message) => warnings.push(message)),
  });
  return { select, warnings, confirmations, controller };
}

describe("CLI scan model selection", () => {
  test("requires independent affirmative choices for model and effort changes", async () => {
    for (const answers of [
      [false, false],
      [true, false],
      [false, true],
      [true, true],
    ]) {
      const { select, confirmations, controller } = fixture({ answers });
      const configuration = { model: "model-old", reasoningEffort: "high" };
      expect(
        await select(
          configuration,
          async () => upgradeModels(),
          controller.signal,
        ),
      ).toEqual({
        model: answers[0] ? "model-new" : "model-old",
        reasoningEffort: answers[1] ? "xhigh" : "high",
      });
      expect(configuration).toEqual({
        model: "model-old",
        reasoningEffort: "high",
      });
      expect(confirmations).toHaveLength(2);
      expect(confirmations[0]?.question).toContain("model-new");
      expect(confirmations[1]?.question).toContain("xhigh");
      expect(
        confirmations.every(({ defaultValue }) => defaultValue === false),
      ).toBe(true);
      expect(
        confirmations.every(({ signal }) => signal === controller.signal),
      ).toBe(true);
    }
  });

  test("writes warnings without prompting in headless or noninteractive terminals", async () => {
    for (const options of [
      { interactive: false, terminalInteractive: true },
      { interactive: true, terminalInteractive: false },
    ]) {
      const { select, warnings, confirmations, controller } = fixture(options);
      const configuration = { model: "model-old", reasoningEffort: "high" };
      expect(
        await select(
          configuration,
          async () => upgradeModels(),
          controller.signal,
        ),
      ).toEqual(configuration);
      expect(confirmations).toHaveLength(0);
      expect(warnings.join(" ")).toContain("model-new");
      expect(warnings.join(" ")).toContain("xhigh");
    }
  });

  test("still warns about cyber scans when account model discovery is unavailable", async () => {
    const { select, warnings, confirmations, controller } = fixture({
      interactive: false,
    });
    const configuration = { model: "model-cyber", reasoningEffort: "xhigh" };
    expect(
      await select(configuration, async () => undefined, controller.signal),
    ).toEqual(configuration);
    expect(warnings.join(" ")).toContain("dynamic exploitation");
    expect(confirmations).toHaveLength(0);
  });

  test("discovery failures preserve settings and warn without interrupting the scan", async () => {
    for (const reasoningEffort of ["high", "custom-effort"]) {
      const { select, warnings, confirmations, controller } = fixture({
        answers: [true],
      });
      const configuration = { model: "model-unknown", reasoningEffort };
      expect(
        await select(
          configuration,
          async () => {
            throw new Error("Catalog unavailable");
          },
          controller.signal,
        ),
      ).toEqual(configuration);
      expect(warnings.join(" ")).toContain(
        "Could not check available scan models",
      );
      expect(confirmations).toHaveLength(0);
    }
  });

  test("preserves higher effort settings when accepting a model upgrade", async () => {
    for (const reasoningEffort of ["max", "ultra", "persistent"]) {
      const { select, confirmations, controller } = fixture({
        answers: [true],
      });
      const models = upgradeModels().map((model) => ({
        ...model,
        supportedReasoningEfforts: [
          ...model.supportedReasoningEfforts,
          { reasoningEffort },
        ],
      }));
      expect(
        await select(
          { model: "model-old", reasoningEffort },
          async () => models,
          controller.signal,
        ),
      ).toEqual({ model: "model-new", reasoningEffort });
      expect(confirmations).toHaveLength(1);
    }
  });

  test("does not offer model upgrades that cannot preserve the chosen effort", async () => {
    const { select, warnings, confirmations, controller } = fixture({
      answers: [true],
    });
    const configuration = { model: "model-old", reasoningEffort: "max" };
    const models = [
      catalogModel("model-old", {
        upgrade: "model-new",
        supportedReasoningEfforts: [
          { reasoningEffort: "xhigh" },
          { reasoningEffort: "max" },
        ],
      }),
      catalogModel("model-new"),
    ];
    expect(
      await select(configuration, async () => models, controller.signal),
    ).toEqual(configuration);
    expect(warnings.join(" ")).toContain("does not support the configured max");
    expect(confirmations).toHaveLength(0);
  });

  test("keeps the current model when an upgrade cannot support the scan cost limit", async () => {
    const { select, warnings, confirmations, controller } = fixture({
      answers: [true],
      maxCostUsd: 10,
    });
    const configuration = scanModelConfiguration(DEFAULT_CODEX_CONFIG);
    const models = [
      catalogModel(configuration.model, { upgrade: "model-new" }),
      catalogModel("model-new"),
    ];
    expect(
      await select(configuration, async () => models, controller.signal),
    ).toEqual(configuration);
    expect(confirmations).toHaveLength(0);
    expect(warnings.join(" ")).toContain("Cost tracking is unavailable");
    expect(warnings.join(" ")).toContain("preserve the scan cost limit");
  });

  test("shares discovery and choices across concurrent scans with matching settings", async () => {
    const { select, confirmations, controller } = fixture({ answers: [true] });
    const pendingModels = Promise.withResolvers<CatalogModel[]>();
    let discoveryCalls = 0;
    const loadModels = async () => {
      discoveryCalls += 1;
      return await pendingModels.promise;
    };
    const first = select(
      { model: "model-old", reasoningEffort: "xhigh" },
      loadModels,
      controller.signal,
    );
    const second = select(
      { model: "model-old", reasoningEffort: "xhigh" },
      loadModels,
      controller.signal,
    );
    expect(first).toBe(second);
    expect(discoveryCalls).toBe(1);
    pendingModels.resolve(upgradeModels());
    const results = await Promise.all([first, second]);
    expect(results).toEqual([
      { model: "model-new", reasoningEffort: "xhigh" },
      { model: "model-new", reasoningEffort: "xhigh" },
    ]);
    expect(confirmations).toHaveLength(1);
  });

  test("cancels while a confirmation is pending even if the prompt stays open", async () => {
    const entered = Promise.withResolvers<void>();
    const pendingAnswer = Promise.withResolvers<boolean>();
    const { select, controller } = fixture({
      confirm: async () => {
        entered.resolve();
        return await pendingAnswer.promise;
      },
    });
    const selection = select(
      { model: "model-old", reasoningEffort: "xhigh" },
      async () => upgradeModels(),
      controller.signal,
    );
    await entered.promise;
    const cancellation = new Error("Scan cancelled");
    controller.abort(cancellation);
    await expect(selection).rejects.toBe(cancellation);
    pendingAnswer.resolve(false);
  });

  test("propagates prompt cancellation instead of treating it as consent", async () => {
    const cancellation = new Error("Prompt cancelled");
    const { select, controller } = fixture({
      confirm: async () => {
        throw cancellation;
      },
    });
    await expect(
      select(
        { model: "model-old", reasoningEffort: "high" },
        async () => upgradeModels(),
        controller.signal,
      ),
    ).rejects.toBe(cancellation);
  });

  test("keeps cancellation during discovery from becoming a recoverable warning", async () => {
    const { select, warnings, confirmations, controller } = fixture();
    const cancellation = new Error("Scan cancelled");
    await expect(
      select(
        { model: "model-old", reasoningEffort: "high" },
        async () => {
          controller.abort(cancellation);
          throw cancellation;
        },
        controller.signal,
      ),
    ).rejects.toBe(cancellation);
    expect(warnings).toHaveLength(0);
    expect(confirmations).toHaveLength(0);
  });

  test("continues with explicit selections when warning output fails", async () => {
    const { select, confirmations, controller } = fixture({
      answers: [true, true],
      write: () => {
        throw new Error("Output stream closed");
      },
    });
    expect(
      await select(
        { model: "model-old", reasoningEffort: "high" },
        async () => upgradeModels(),
        controller.signal,
      ),
    ).toEqual({ model: "model-new", reasoningEffort: "xhigh" });
    expect(confirmations).toHaveLength(2);
  });
});
