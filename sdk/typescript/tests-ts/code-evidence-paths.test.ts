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

async function scanWithEvidencePath(path: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-evidence-path-"));
  temporaryDirectories.push(root);
  const scanDir = join(root, "scan");
  await cp(EXAMPLE, scanDir, { recursive: true });
  if (process.platform !== "win32") await chmod(scanDir, 0o700);

  const findingsPath = join(scanDir, "findings.json");
  const findings = JSON.parse(await readFile(findingsPath, "utf8")) as {
    findings: Array<Record<string, unknown>>;
  };
  findings.findings[0]!["codeEvidence"] = [
    {
      id: "evidence-1",
      label: "Source evidence",
      path,
      startLine: 41,
      endLine: 44,
      language: "python",
      role: "sink",
      code: "target.write(data)",
      explanation: "The selected path reaches the filesystem write.",
    },
  ];
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

describe("canonical code-evidence paths", () => {
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
      const scanDir = await scanWithEvidencePath(path);
      await expect(
        loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
      ).rejects.toThrow("findings.json");
    }
  });

  test("accepts a repository-relative code-evidence path", async () => {
    const scanDir = await scanWithEvidencePath("src/extract.py");
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).resolves.toMatchObject({
      findings: {
        findings: [
          {
            codeEvidence: [
              expect.objectContaining({ path: "src/extract.py" }),
            ],
          },
        ],
      },
    });
  });
});
