import {
  readFile,
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import {
  compositionCheckpointFromWorkbench,
  decodeDeepScanCheckpoint,
  loadDeepScanCheckpoint,
  type DeepScanCheckpointSummary,
} from "../src/deep-scan-checkpoint.js";

test.each(["current", "legacy", "pending-stop"])(
  "round-trips the shared %s checkpoint without rewriting fields",
  async (name) => {
    const document: unknown = JSON.parse(
      await readFile(
        new URL(
          `../../../plugins/codex-security/tests/fixtures/composition-checkpoints/${name}.json`,
          import.meta.url,
        ),
        "utf8",
      ),
    );
    const before = JSON.stringify(document);
    const checkpoint = decodeDeepScanCheckpoint(document);
    expect(JSON.stringify(checkpoint)).toBe(before);
    expect(JSON.stringify(document)).toBe(before);
    if (name === "current") {
      expect(checkpoint.passes[0]!["extension"]).toEqual({ retain: 1 });
      expect(checkpoint["extension"]).toEqual({
        future: ["preserve", null, 7],
      });
      expect(Object.hasOwn(checkpoint, "mergeFailures")).toBe(false);
      expect(checkpoint.aggregate!.findings[0]!.identity).toBeUndefined();
      expect(
        checkpoint.aggregate!.findings[0]!.provenance.sourceFindings,
      ).toEqual([
        {
          id: "child:0",
          finding: {
            findingId: "original-id",
            extensions: { proof: ["Exact source payload"] },
          },
        },
      ]);
    } else if (name === "pending-stop") {
      expect(checkpoint.pendingStop?.reason).toBe("canceled");
      expect(
        checkpoint.pendingStop?.costs[checkpoint.passes[0]!.directory]
          ?.estimatedUsd,
      ).toBe(0.01);
    } else {
      expect(
        (checkpoint["legacy"] as Record<string, unknown>)["originThreadId"],
      ).toBeNull();
      expect(Object.hasOwn(checkpoint["legacy"]!, "cost")).toBe(false);
      expect(checkpoint.terminalReason).toBe("capped");
    }
  },
);

test.each(["current", "legacy", "pending-stop"])(
  "reads the %s get-scan summary without claiming its omitted payloads",
  async (name) => {
    const checkpoint = decodeDeepScanCheckpoint(
      JSON.parse(
        await readFile(
          new URL(
            `../../../plugins/codex-security/tests/fixtures/composition-checkpoints/${name}.json`,
            import.meta.url,
          ),
          "utf8",
        ),
      ),
    );
    const { aggregate: _aggregate, legacy, ...metadata } = checkpoint;
    const document: DeepScanCheckpointSummary = metadata;
    if (legacy) {
      const { coverage: _coverage, ...legacyMetadata } = legacy as Record<
        string,
        unknown
      >;
      document["legacy"] = legacyMetadata;
    }
    const summary = compositionCheckpointFromWorkbench({
      compositionCheckpoint: document,
    })!;
    expect(summary).toBe(document);
    expect(summary.version).toBe(2);
    expect(Object.hasOwn(summary, "aggregate")).toBe(false);
    if (legacy) {
      expect(
        (summary["legacy"] as Record<string, unknown>)["originThreadId"],
      ).toBeNull();
      expect(Object.hasOwn(summary["legacy"]!, "coverage")).toBe(false);
    }
  },
);

test("workbench responses distinguish an absent checkpoint from an unsupported version", () => {
  expect(compositionCheckpointFromWorkbench({})).toBeNull();
  expect(
    compositionCheckpointFromWorkbench({ compositionCheckpoint: null }),
  ).toBeNull();
  expect(() =>
    compositionCheckpointFromWorkbench({
      compositionCheckpoint: { version: 1 },
    }),
  ).toThrow("Unsupported saved Deep Scan checkpoint.");
});

test.each([
  "empty",
  "no-leaf",
  "missing-root",
  "linked-parent",
  "dangling-parent",
  "linked-root",
  "parent-file",
  "malformed",
])("optional checkpoint preserves path errors for %s", async (layout) => {
  const temporary = await mkdtemp(join(tmpdir(), "checkpoint-path-"));
  const scanDir = join(temporary, "scan");
  try {
    if (layout !== "missing-root") await mkdir(scanDir, { mode: 0o700 });
    if (layout === "linked-root") {
      const target = join(temporary, "target");
      await mkdir(target, { mode: 0o700 });
      await rm(scanDir, { recursive: true });
      await symlink(target, scanDir, "junction");
    } else if (layout !== "empty" && layout !== "missing-root") {
      await mkdir(join(scanDir, "artifacts"), { mode: 0o700 });
      const parent = join(scanDir, "artifacts/deep-scan");
      if (layout === "linked-parent" || layout === "dangling-parent") {
        const target = join(temporary, "target");
        if (layout === "linked-parent") await mkdir(target, { mode: 0o700 });
        await symlink(target, parent, "junction");
      } else if (layout === "parent-file") {
        await writeFile(parent, "synthetic file");
      } else {
        await mkdir(parent, { mode: 0o700 });
        if (layout === "malformed")
          await writeFile(join(parent, "checkpoint.json"), "{");
      }
    }
    if (layout === "empty" || layout === "no-leaf") {
      expect(await loadDeepScanCheckpoint(scanDir)).toBeNull();
    } else {
      await expect(loadDeepScanCheckpoint(scanDir)).rejects.toThrow();
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
