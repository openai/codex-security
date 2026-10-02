import { expect, test } from "bun:test";
import { registerScan } from "../src/scan-registration.js";
import type { JsonObject } from "../src/config.js";

for (const continuation of ["resume", "registered"] as const) {
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
          archivedScanDir: null,
          codexHome: "/synthetic/codex-home",
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
