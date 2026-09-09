import { describe, expect, test } from "bun:test";
import {
  getScanModelAdvice,
  isNonAstraCyberModel,
} from "../src/model-advice.js";
import type { CatalogModel } from "../src/model-catalog.js";

function catalogModel(
  model: string,
  overrides: Partial<CatalogModel> = {},
): CatalogModel {
  return {
    id: model,
    model,
    hidden: false,
    supportedReasoningEfforts: ["low", "medium", "high", "xhigh"].map(
      (reasoningEffort) => ({ reasoningEffort }),
    ),
    defaultReasoningEffort: "medium",
    ...overrides,
  };
}

function advice(
  model: string,
  availableModels?: CatalogModel[],
  reasoningEffort = "xhigh",
) {
  return getScanModelAdvice({ model, reasoningEffort, availableModels });
}

describe("scan model advice", () => {
  test("recognizes cyber model tokens and the Astra exception", () => {
    for (const model of [
      "model-cyber-preview",
      "provider/model-cyber",
      "model-CYBER",
      "astral-cyber-preview",
    ]) {
      expect(isNonAstraCyberModel(model)).toBe(true);
      expect(advice(model).cyberWarning).toContain("dynamic exploitation");
    }
    for (const model of [
      "astra-cyber-preview",
      "model-astra-cyber",
      "model-noncyber",
      "model-standard",
    ]) {
      expect(isNonAstraCyberModel(model)).toBe(false);
      expect(advice(model).cyberWarning).toBeUndefined();
    }
  });

  test("uses generic cyber guidance when account model discovery is unknown", () => {
    const result = advice("model-cyber");
    expect(result.cyberWarning).toContain(
      "the latest non-cyber model available to you",
    );
    expect(result.modelUpgrade).toBeUndefined();
  });

  test("does not infer releases from catalog order, defaults, or model names", () => {
    const models = [
      catalogModel("model-99", { isDefault: true }),
      catalogModel("model-1"),
      catalogModel("model-100"),
    ];
    expect(advice("model-1", models).modelUpgrade).toBeUndefined();
    expect(advice("unknown", models).modelUpgrade).toBeUndefined();
    expect(advice("model-1", []).modelUpgrade).toBeUndefined();
  });

  test("follows explicit upgrade metadata to the latest accessible target", () => {
    const newest = catalogModel("model-newest");
    const models = [
      newest,
      catalogModel("model-old", {
        upgrade: "model-legacy-target",
        upgradeInfo: { model: "model-new" },
      }),
      catalogModel("model-new", { upgrade: newest.model }),
      catalogModel("model-legacy-target"),
    ];
    expect(advice("model-old", models).modelUpgrade).toBe(newest);
  });

  test("skips hidden and unsuitable cyber targets while following upgrades", () => {
    const astra = catalogModel("astra-cyber");
    const models = [
      catalogModel("model-old", { upgrade: "model-hidden" }),
      catalogModel("model-hidden", {
        hidden: true,
        upgrade: "model-cyber",
      }),
      catalogModel("model-cyber", { upgrade: astra.model }),
      astra,
    ];
    expect(advice("model-old", models).modelUpgrade).toBe(astra);
    expect(
      advice("model-old", models.slice(0, 3)).modelUpgrade,
    ).toBeUndefined();
  });

  test("retains known upgrades before missing targets but rejects cyclic chains", () => {
    const next = catalogModel("model-next", { upgrade: "unavailable" });
    const models = [catalogModel("model-old", { upgrade: next.model }), next];
    expect(advice("model-old", models).modelUpgrade).toBe(next);
    next.upgrade = "model-old";
    expect(advice("model-old", models).modelUpgrade).toBeUndefined();
    expect(
      advice("model-self", [
        catalogModel("model-self", { upgrade: "model-self" }),
      ]).modelUpgrade,
    ).toBeUndefined();
  });

  test("uses model IDs as aliases for explicit upgrades", () => {
    const next = catalogModel("model-next", { id: "next-id" });
    const models = [
      catalogModel("model-old", { id: "old-id", upgrade: next.id }),
      next,
    ];
    expect(advice("old-id", models).modelUpgrade).toBe(next);
    expect(
      advice("cyber-alias", [
        catalogModel("model-cyber", { id: "cyber-alias" }),
      ]).cyberWarning,
    ).toBeDefined();
  });

  test("uses explicit non-cyber upgrades for the scanning recommendation", () => {
    const models = [
      catalogModel("model-default", { isDefault: true, upgrade: "model-new" }),
      catalogModel("model-new", { upgrade: "astra-cyber" }),
      catalogModel("astra-cyber"),
    ];
    expect(advice("model-cyber", models).cyberWarning).toContain("model-new");
    expect(advice("model-cyber", models).cyberWarning).not.toContain(
      "astra-cyber",
    );
  });

  test("recommends visible non-cyber defaults without calling them a newer release", () => {
    const models = [
      catalogModel("hidden-default", { isDefault: true, hidden: true }),
      catalogModel("model-cyber", { isDefault: true }),
      catalogModel("model-default", { isDefault: true }),
    ];
    const result = advice("model-cyber", models);
    expect(result.cyberWarning).toContain("model-default");
    expect(result.cyberWarning).not.toMatch(/latest|newer/i);
    expect(result.modelUpgrade).toBeUndefined();
    expect(advice("model-cyber", models.slice(0, 2)).cyberWarning).toContain(
      "the latest non-cyber model available to you",
    );
  });

  test("prefers the selected model's non-cyber upgrade over catalog defaults", () => {
    const models = [
      catalogModel("model-default", { isDefault: true }),
      catalogModel("model-cyber", { upgrade: "model-upgrade" }),
      catalogModel("model-upgrade"),
    ];
    expect(advice("model-cyber", models).cyberWarning).toContain(
      "model-upgrade",
    );
    expect(advice("model-cyber", models).cyberWarning).not.toContain(
      "model-default",
    );
  });

  test("uses only known lower reasoning efforts when the model is unknown", () => {
    for (const effort of ["none", "minimal", "low", "medium", "high"]) {
      expect(advice("model-unknown", undefined, effort).recommendXhigh).toBe(
        true,
      );
    }
    for (const effort of ["xhigh", "max", "ultra", "persistent", "custom"]) {
      expect(advice("model-unknown", undefined, effort).recommendXhigh).toBe(
        false,
      );
    }
  });

  test("does not infer unknown effort semantics from catalog ordering", () => {
    const models = [
      catalogModel("model-custom", {
        supportedReasoningEfforts: [
          "custom-lower",
          "xhigh",
          "high",
          "custom-higher",
        ].map((reasoningEffort) => ({ reasoningEffort })),
      }),
    ];
    expect(advice("model-custom", models, "high").recommendXhigh).toBe(true);
    for (const effort of [
      "custom-lower",
      "xhigh",
      "custom-higher",
      "max",
      "ultra",
      "persistent",
    ]) {
      expect(advice("model-custom", models, effort).recommendXhigh).toBe(false);
    }
  });

  test("does not suggest xhigh when the selected model does not support it", () => {
    const models = [
      catalogModel("model-limited", {
        supportedReasoningEfforts: ["low", "medium", "high"].map(
          (reasoningEffort) => ({ reasoningEffort }),
        ),
      }),
    ];
    expect(advice("model-limited", models, "low").recommendXhigh).toBe(false);
  });
});
