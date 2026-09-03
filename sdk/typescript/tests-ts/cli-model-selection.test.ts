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
  test("accepts or declines model and effort changes together with one default-no confirmation", async () => {
    for (const accepted of [false, true]) {
      const { select, warnings, confirmations, controller } = fixture({
        answers: [accepted],
      });
      const configuration = { model: "model-old", reasoningEffort: "high" };
      expect(
        await select(
          configuration,
          async () => upgradeModels(),
          controller.signal,
        ),
      ).toEqual({
        model: accepted ? "model-new" : "model-old",
        reasoningEffort: accepted ? "xhigh" : "high",
      });
      expect(configuration).toEqual({
        model: "model-old",
        reasoningEffort: "high",
      });
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("model-new");
      expect(warnings[0]).toContain("xhigh");
      expect(confirmations).toHaveLength(1);
      expect(confirmations[0]?.question).toContain("model-new");
      expect(confirmations[0]?.question).toContain("xhigh");
      expect(
        confirmations.every(({ defaultValue }) => defaultValue === false),
      ).toBe(true);
      expect(
        confirmations.every(({ signal }) => signal === controller.signal),
      ).toBe(true);
    }
  });

  test("combines cyber, model, and effort guidance into one warning", async () => {
    const { select, warnings, confirmations, controller } = fixture({
      answers: [true],
    });
    expect(
      await select(
        { model: "model-cyber", reasoningEffort: "high" },
        async () => [
          catalogModel("model-cyber", { upgrade: "model-new" }),
          catalogModel("model-new", { isDefault: true }),
        ],
        controller.signal,
      ),
    ).toEqual({ model: "model-new", reasoningEffort: "xhigh" });
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("dynamic exploitation");
    expect(warnings[0]).toContain("available as an upgrade");
    expect(warnings[0]).toContain("xhigh");
    expect(confirmations).toHaveLength(1);
  });

  test("checks xhigh eligibility on the proposed model before asking", async () => {
    for (const upgradeSupportsXhigh of [false, true]) {
      const { select, confirmations, controller } = fixture({
        answers: [true],
      });
      const models = [
        catalogModel("model-old", {
          upgrade: "model-new",
          supportedReasoningEfforts: upgradeSupportsXhigh
            ? [{ reasoningEffort: "high" }]
            : catalogModel("model-old").supportedReasoningEfforts,
        }),
        catalogModel("model-new", {
          supportedReasoningEfforts: upgradeSupportsXhigh
            ? catalogModel("model-new").supportedReasoningEfforts
            : [{ reasoningEffort: "high" }],
        }),
      ];
      expect(
        await select(
          { model: "model-old", reasoningEffort: "high" },
          async () => models,
          controller.signal,
        ),
      ).toEqual({
        model: "model-new",
        reasoningEffort: upgradeSupportsXhigh ? "xhigh" : "high",
      });
      expect(confirmations).toHaveLength(1);
      expect(confirmations[0]?.question).toContain("model-new");
      expect(confirmations[0]?.question.includes("xhigh")).toBe(
        upgradeSupportsXhigh,
      );
    }
  });

  test("offers an effort-only change when there is no model upgrade", async () => {
    const { select, warnings, confirmations, controller } = fixture({
      answers: [true],
    });
    expect(
      await select(
        { model: "model-current", reasoningEffort: "high" },
        async () => [catalogModel("model-current")],
        controller.signal,
      ),
    ).toEqual({ model: "model-current", reasoningEffort: "xhigh" });
    expect(warnings).toHaveLength(1);
    expect(confirmations).toHaveLength(1);
    expect(confirmations[0]?.question).toContain("xhigh");
    expect(confirmations[0]?.question).not.toContain("model-current");
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
      expect(warnings).toHaveLength(1);
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
      const configuration = { model: "model-cyber", reasoningEffort };
      expect(
        await select(
          configuration,
          async () => {
            throw new Error("Catalog unavailable");
          },
          controller.signal,
        ),
      ).toEqual(configuration);
      expect(warnings).toHaveLength(1);
      expect(warnings.join(" ")).toContain(
        "Could not check available scan models",
      );
      expect(warnings[0]).toContain("dynamic exploitation");
      expect(warnings[0]?.includes("xhigh")).toBe(reasoningEffort === "high");
      expect(confirmations).toHaveLength(0);
    }
  });

  test("preserves higher and unknown effort settings when accepting a model upgrade", async () => {
    for (const reasoningEffort of [
      "max",
      "ultra",
      "persistent",
      "custom-effort",
    ]) {
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
      expect(confirmations[0]?.question).not.toContain("xhigh");
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

  test("does not combine an incompatible model upgrade with a supported effort change", async () => {
    const { select, warnings, confirmations, controller } = fixture({
      answers: [true],
    });
    expect(
      await select(
        { model: "model-old", reasoningEffort: "high" },
        async () => [
          catalogModel("model-old", { upgrade: "model-new" }),
          catalogModel("model-new", {
            supportedReasoningEfforts: [{ reasoningEffort: "xhigh" }],
          }),
        ],
        controller.signal,
      ),
    ).toEqual({ model: "model-old", reasoningEffort: "xhigh" });
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("does not support the configured high");
    expect(warnings[0]).toContain("Use xhigh");
    expect(confirmations).toHaveLength(1);
    expect(confirmations[0]?.question).toContain("xhigh");
    expect(confirmations[0]?.question).not.toContain("model-new");
  });

  test("keeps the current model when an upgrade cannot support the scan cost limit", async () => {
    for (const reasoningEffort of ["high", "xhigh"]) {
      const { select, warnings, confirmations, controller } = fixture({
        answers: [true],
        maxCostUsd: 10,
      });
      const configuration = {
        ...scanModelConfiguration(DEFAULT_CODEX_CONFIG),
        reasoningEffort,
      };
      const models = [
        catalogModel(configuration.model, { upgrade: "model-new" }),
        catalogModel("model-new"),
      ];
      expect(
        await select(configuration, async () => models, controller.signal),
      ).toEqual({ ...configuration, reasoningEffort: "xhigh" });
      expect(confirmations).toHaveLength(reasoningEffort === "high" ? 1 : 0);
      if (reasoningEffort === "high") {
        expect(confirmations[0]?.question).toContain("xhigh");
        expect(confirmations[0]?.question).not.toContain("model-new");
      }
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("Cost tracking is unavailable");
      expect(warnings[0]).toContain("preserve the scan cost limit");
    }
  });

  test("shares discovery and choices across concurrent scans with matching settings", async () => {
    const { select, warnings, confirmations, controller } = fixture({
      answers: [true],
    });
    const pendingModels = Promise.withResolvers<CatalogModel[]>();
    let discoveryCalls = 0;
    const loadModels = async () => {
      discoveryCalls += 1;
      return await pendingModels.promise;
    };
    const first = select(
      { model: "model-old", reasoningEffort: "high" },
      loadModels,
      controller.signal,
    );
    const second = select(
      { model: "model-old", reasoningEffort: "high" },
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
    expect(warnings).toHaveLength(1);
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
      answers: [true],
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
    expect(confirmations).toHaveLength(1);
  });
});
