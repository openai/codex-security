import { createHash } from "node:crypto";
import { chmod, cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { loadContract } from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const EXAMPLE = join(PLUGIN_ROOT, "examples", "completed-scan");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function scanWithDeferredPath(path: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-deferred-path-"));
  temporaryDirectories.push(root);
  const scanDir = join(root, "scan");
  await cp(EXAMPLE, scanDir, { recursive: true });
  if (process.platform !== "win32") await chmod(scanDir, 0o700);

  const coveragePath = join(scanDir, "coverage.json");
  const coverage = JSON.parse(await readFile(coveragePath, "utf8")) as Record<
    string,
    unknown
  >;
  coverage["completeness"] = "partial";
  coverage["deferred"] = [
    {
      id: "deferred-source-review",
      reason: "Source review remains incomplete.",
      paths: [path],
    },
  ];
  await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);

  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    scan: { artifacts: Array<{ path: string; sha256: string }> };
  };
  const artifact = manifest.scan.artifacts.find(
    (candidate) => candidate.path === "coverage.json",
  );
  expect(artifact).toBeDefined();
  artifact!.sha256 = createHash("sha256")
    .update(await readFile(coveragePath))
    .digest("hex");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return scanDir;
}

describe("canonical deferred coverage paths", () => {
  test("rejects paths outside the repository-relative POSIX boundary", async () => {
    for (const path of [
      "../../outside.ts",
      "/etc/passwd",
      "C:/outside.ts",
      "src\\outside.ts",
      ".",
      "src:stream.ts",
      "src/\0outside.ts",
    ]) {
      const scanDir = await scanWithDeferredPath(path);
      await expect(
        loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
      ).rejects.toThrow("coverage.json");
    }
  });

  test("accepts a repository-relative deferred path", async () => {
    const scanDir = await scanWithDeferredPath("src/extract.py");
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).resolves.toMatchObject({
      coverage: {
        completeness: "partial",
        deferred: [
          expect.objectContaining({ paths: ["src/extract.py"] }),
        ],
      },
    });
  });
});
