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

async function scanWithLocationRange(
  startLine: number,
  endLine: number,
): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-location-range-"));
  temporaryDirectories.push(root);
  const scanDir = join(root, "scan");
  await cp(EXAMPLE, scanDir, { recursive: true });
  if (process.platform !== "win32") await chmod(scanDir, 0o700);

  const findingsPath = join(scanDir, "findings.json");
  const findings = JSON.parse(await readFile(findingsPath, "utf8")) as {
    findings: Array<{
      locations: Array<{ startLine: number; endLine?: number }>;
    }>;
  };
  const location = findings.findings[0]!.locations[0]!;
  location.startLine = startLine;
  location.endLine = endLine;
  await writeFile(findingsPath, `${JSON.stringify(findings, null, 2)}\n`);

  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    scan: { artifacts: Array<{ path: string; sha256: string }> };
  };
  const artifact = manifest.scan.artifacts.find(
    (candidate) => candidate.path === "findings.json",
  );
  expect(artifact).toBeDefined();
  artifact!.sha256 = createHash("sha256")
    .update(await readFile(findingsPath))
    .digest("hex");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return scanDir;
}

describe("canonical finding location line ranges", () => {
  test("rejects an end line before the start line", async () => {
    const scanDir = await scanWithLocationRange(41, 40);
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("endLine");
  });

  test("accepts a forward multi-line range", async () => {
    const scanDir = await scanWithLocationRange(41, 44);
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).resolves.toMatchObject({
      findings: {
        findings: [
          {
            locations: [
              expect.objectContaining({ startLine: 41, endLine: 44 }),
            ],
          },
        ],
      },
    });
  });
});
