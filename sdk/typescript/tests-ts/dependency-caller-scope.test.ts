import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dependencyPathExcluded } from "../src/dependency-caller-scope.js";
import { ProjectConfigInputSchema } from "../src/project-config-schema.js";
import { runReviewedDependencyCheck } from "../src/dependency-reviewed-check.js";

test("endpoint boundaries distinguish omitted and explicitly empty and retain producer selector metadata", () => {
  for (const boundary of [
    { sources: [] },
    { sinks: [] },
    {
      scope: { exclude_paths: ["examples"] },
      sources: [
        {
          function: "receive",
          runtime_selectors: [{ name: "start", extra: "raw" }],
        },
      ],
    },
  ]) {
    expect(
      ProjectConfigInputSchema.parse({ exploitability: boundary })
        .exploitability,
    ).toEqual(boundary);
  }
});

test("broad production and explicit exclusions reopen paths with their own SECURITY.md", () => {
  const policyPaths = new Set(["SECURITY.md", "examples/service/SECURITY.md"]);
  for (const boundary of [
    { productionOnly: true, excludePaths: [] },
    { productionOnly: false, excludePaths: ["examples"] },
  ]) {
    expect(
      dependencyPathExcluded(
        "examples/demo/package.json",
        policyPaths,
        boundary,
      ),
    ).toBe(true);
    expect(
      dependencyPathExcluded(
        "examples/service/src/main.js",
        policyPaths,
        boundary,
      ),
    ).toBe(false);
    expect(dependencyPathExcluded("src/main.js", policyPaths, boundary)).toBe(
      false,
    );
  }
});

test("a production-only investigation can close a checkout with a test-only manifest", async () => {
  const directory = await mkdtemp(join(tmpdir(), "scope-check-"));
  try {
    await mkdir(join(directory, "tests"));
    await writeFile(
      join(directory, "tests/package.json"),
      JSON.stringify({ dependencies: { "fixture-parser": "1.0.0" } }),
    );
    const git = (...args: string[]) =>
      execFileSync("git", ["-C", directory, ...args]);
    git("init", "-q");
    git("add", ".");
    git(
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "commit",
      "-qm",
      "Fixture",
    );
    for (const scope of [
      undefined,
      "Only production services. Independent tests are outside scope.",
    ]) {
      let reviewed = false;
      const result = await runReviewedDependencyCheck(
        {
          subject: "npm:fixture-parser",
          vulnDescription: "A caller must pass untrusted data to parse.",
          scope,
          directory,
          signal: new AbortController().signal,
        },
        {
          runAgent: async ({ prompt }) => {
            const input = JSON.parse(prompt.split("\n\n").at(-1)!);
            if (!input.claims) {
              expect(input.callerScope.toLowerCase()).toContain("production");
              expect(input.discoveries[0].manifests.length).toBe(
                scope === undefined ? 0 : 1,
              );
              return JSON.stringify({
                uses: [],
                limitations: [
                  "The dependency is declared only for independent tests.",
                ],
              });
            }
            reviewed = true;
            return JSON.stringify({
              decisions: input.claims.map(
                (claim: { id: string; revision: number; hash: string }) => ({
                  id: claim.id,
                  revision: claim.revision,
                  hash: claim.hash,
                  approved: true,
                  evidenceKeys: [],
                  reason:
                    "Checked the only manifest against the caller boundary.",
                }),
              ),
            });
          },
        },
      );
      expect(reviewed).toBe(true);
      if (!("checks" in result)) throw new Error("Expected package report");
      expect(result.checks[0]!.uses).toHaveLength(0);
      if (scope)
        expect(result.checks[0]!.coverage).toMatchObject([
          { kind: "dismissed", location: "tests" },
        ]);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
