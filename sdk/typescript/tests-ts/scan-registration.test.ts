import { expect, test } from "bun:test";
import { registerScan } from "../src/scan-registration.js";
import type { JsonObject } from "../src/config.js";

for (const continuation of ["resume", "registered"] as const) {
  test(`${continuation} accepts a sealed legacy recipe without a document digest`, async () => {
    const recipe: JsonObject = {
      repository: "/synthetic/repository",
      target: { kind: "repository", paths: [] },
      knowledgeBasePaths: ["/synthetic/knowledge"],
      knowledgeBaseSha256: "current-documents",
    };
    const expectation = {
      repository: "/synthetic/repository",
      repositoryRevision: "revision",
      target: { kind: "repository" as const, paths: [] },
      pluginVersion: "current",
      mode: "deep" as const,
    };
    const result = await registerScan({
      scan:
        continuation === "resume"
          ? { resumeScanId: "saved" }
          : {
              registeredScan: {
                scanId: "saved",
                scanDir: "/synthetic/scan",
                threadId: "owner",
              },
            },
      recipe,
      expectation,
      scanDir: "/synthetic/scan",
      workbench: async () => ({
        scanId: "saved",
        scanDir: "/synthetic/scan",
        threadId: null,
        targetId: "target",
        targetRevision: "revision",
        contract: { target: { allowedKinds: ["git_revision"] } },
        sealedProducerVersion: "legacy",
        recipe: {
          repository: recipe["repository"]!,
          target: recipe["target"]!,
          knowledgeBasePaths: recipe["knowledgeBasePaths"]!,
        },
      }),
    });
    expect(result.sealed).toBe(true);
    expect(expectation.pluginVersion).toBe("legacy");
  });

  test.each([
    [undefined, "new-documents"],
    ["saved-documents", undefined],
    ["saved-documents", "changed-documents"],
  ])(
    `${continuation} rejects changes to the saved document selection (%p -> %p)`,
    async (saved, current) => {
      const recipe: JsonObject = {
        repository: "/synthetic/repository",
        target: { kind: "repository" },
        ...(current === undefined ? {} : { knowledgeBaseSha256: current }),
      };
      await expect(
        registerScan({
          scan:
            continuation === "resume"
              ? { resumeScanId: "saved" }
              : {
                  registeredScan: {
                    scanId: "saved",
                    scanDir: "/synthetic/scan",
                    threadId: "owner",
                    handoffClaimToken: "synthetic",
                  },
                },
          recipe,
          expectation: {
            repository: "/synthetic/repository",
            repositoryRevision: null,
            target: { kind: "repository", paths: [] },
            pluginVersion: "0.0.0",
            mode: "deep",
          },
          scanDir: "/synthetic/scan",
          workbench: async () => ({
            scanId: "saved",
            recipe: {
              repository: recipe["repository"]!,
              target: recipe["target"]!,
              ...(saved === undefined ? {} : { knowledgeBaseSha256: saved }),
            },
          }),
        }),
      ).rejects.toThrow("knowledge base changed");
    },
  );
}
