import { readReviewState } from "./support/review-state.js";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { loadContract } from "../src/contract.js";
import { ScanResult } from "../src/result.js";
import { capture, dependencies } from "./cli-fixtures.js";

const fixtureUrl = new URL(
  "../../../plugins/codex-security/mcp-app/tests/deep_scan_coverage_fixture.mjs",
  import.meta.url,
);

test.each([
  ["partial", false, false],
  ["unknown", false, false],
  ["complete", false, false],
  ["partial", true, false],
  ["partial", true, true],
] as const)(
  "publishes %s source coverage through CLI results (resume: %p, continued: %p)",
  async (completeness, resume, continueAfterResume) => {
    const root = await mkdtemp(join(tmpdir(), "deep-coverage-publication-"));
    try {
      await mkdir(join(root, "fixture"), { mode: 0o700 });
      // Keep the real workbench outside other suites' persistent module mocks.
      const child = Bun.spawn(
        [
          Bun.which("node")!,
          "--experimental-strip-types",
          fileURLToPath(fixtureUrl),
          join(root, "fixture"),
          completeness,
          String(resume),
          String(continueAfterResume),
        ],
        { stdout: "pipe", stderr: "pipe" },
      );
      const [output, errors, exitCode] = await Promise.all([
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
        child.exited,
      ]);
      expect(exitCode, errors).toBe(0);
      const { scanDir, threadId, terminal } = JSON.parse(output);
      const contract = await loadContract(scanDir, {
        pluginRoot: fileURLToPath(
          new URL("../../../plugins/codex-security/", import.meta.url),
        ),
      });
      const result = new ScanResult({
        ...contract,
        scanDir,
        threadId,
        turnResult: { status: "completed" },
      });
      expect(result.review).not.toHaveProperty("completeness");
      const coverage = (await readReviewState(scanDir)) as {
        reviews: { workerId: string; attempt: number; completeness?: string }[];
        explicitExclusions: { pattern: string }[];
        surfaces: { id: string; receiptRefs: string[] }[];
        deferred: {
          id: string;
          reason: string;
          provenance: { workerId: string; candidateId: string };
          surfaceIds: string[];
        }[];
      } & Awaited<ReturnType<typeof readReviewState>>;
      expect(result.review.excludedPaths).toEqual(
        coverage.explicitExclusions.map((exclusion) => exclusion.pattern),
      );
      expect(coverage.reviews[0]!.attempt).toBe(2);
      const report = await readFile(join(scanDir, "report.md"), "utf8");
      for (const path of result.review.excludedPaths)
        expect(report).toContain(path);
      expect(coverage.explicitExclusions).toHaveLength(coverage.reviews.length);
      for (const review of coverage.reviews)
        expect(terminal.persistedWorkers).toContainEqual(
          expect.objectContaining({
            id: review.workerId,
            attempt: review.attempt,
          }),
        );
      if (completeness === "partial") {
        expect(coverage.deferred.map((item) => item.reason)).toEqual([
          "Verify entry boundaries.",
          "Verify symbolic links.",
        ]);
        expect(
          new Set(
            coverage.deferred.map((item) =>
              JSON.stringify([item.provenance.workerId, item.id]),
            ),
          ).size,
        ).toBe(2);
        expect(
          coverage.reviews.every((review) => review.completeness === undefined),
        ).toBe(true);
        for (const item of coverage.deferred) {
          expect(item.provenance.candidateId).toBe("candidate-1");
          expect(
            coverage.surfaces.some((surface) =>
              item.surfaceIds.includes(surface.id),
            ),
          ).toBe(true);
        }
      }
      for (const surface of coverage.surfaces) {
        expect(
          await readFile(join(scanDir, surface.receiptRefs[0]!), "utf8"),
        ).toContain("Synthetic review evidence.");
      }
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          ["scan", "--mode", "deep", "--json"],
          stdout.stream,
          stderr.stream,
          dependencies({ result, onWorkbench: () => ({ deepScan: terminal }) }),
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text()).review).toEqual(result.review);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
  120_000,
);
