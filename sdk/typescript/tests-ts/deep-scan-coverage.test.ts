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
  ["partial", false],
  ["unknown", false],
  ["complete", false],
  ["partial", true],
] as const)(
  "publishes %s source coverage through CLI results (resume: %p)",
  async (completeness, resume) => {
    const root = await mkdtemp(join(tmpdir(), "deep-coverage-publication-"));
    try {
      await mkdir(join(root, "fixture"), { mode: 0o700 });
      // Keep the real workbench outside other suites' persistent module mocks.
      const child = Bun.spawn(
        [
          Bun.which("node")!,
          fileURLToPath(fixtureUrl),
          join(root, "fixture"),
          completeness,
          String(resume),
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
      expect(result.coverage.completeness).toBe(completeness);
      const coverage = JSON.parse(
        await readFile(join(scanDir, "coverage.json"), "utf8"),
      );
      expect(coverage.reviews[0].attempt).toBe(2);
      const report = await readFile(join(scanDir, "report.md"), "utf8");
      expect(report).toContain(`| Coverage | ${completeness} |`);
      expect(coverage.explicitExclusions).toHaveLength(coverage.reviews.length);
      for (const review of coverage.reviews)
        expect(report).toContain(review.workerId);
      if (completeness === "partial") {
        expect(
          coverage.deferred.map((item: { reason: string }) => item.reason),
        ).toEqual(["Verify entry boundaries.", "Verify symbolic links."]);
        expect(
          new Set(coverage.deferred.map((item: { id: string }) => item.id))
            .size,
        ).toBe(2);
        expect(
          coverage.reviews.map(
            (review: { completeness: string }) => review.completeness,
          ),
        ).toEqual(["partial", "complete", "unknown"]);
        for (const item of coverage.deferred) {
          expect(item.provenance.candidateId).toBe("candidate-1");
          expect(report).toContain(item.reason);
          expect(
            coverage.surfaces.some((surface: { id: string }) =>
              item.surfaceIds.includes(surface.id),
            ),
          ).toBe(true);
        }
      }
      for (const surface of coverage.surfaces) {
        expect(
          await readFile(join(scanDir, surface.receiptRefs[0]), "utf8"),
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
      ).toBe(completeness === "complete" ? 0 : 2);
      expect(JSON.parse(stdout.text()).coverage).toEqual(coverage);
      if (completeness !== "complete")
        expect(stderr.text()).toContain("STOPPED");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
  60_000,
);
