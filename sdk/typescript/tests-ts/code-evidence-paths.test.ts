import { createHash } from "node:crypto";
import { chmod, cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { loadContract } from "../src/contract.js";
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

async function scanWithEvidencePath(
  path: string,
  field = "codeEvidence",
): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-evidence-path-"));
  temporaryDirectories.push(root);
  const scanDir = join(root, "scan");
  await cp(EXAMPLE, scanDir, { recursive: true });
  if (process.platform !== "win32") await chmod(scanDir, 0o700);

  const findingsPath = join(scanDir, "findings.json");
  const findings = JSON.parse(await readFile(findingsPath, "utf8")) as {
    findings: Array<Record<string, unknown>>;
  };
  findings.findings[0]![field] = [
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

const unsafePaths = [
  "../../outside.ts",
  "/outside.ts",
  "C:/outside.ts",
  "src\\outside.ts",
  ".",
  "./",
  "src/\0outside.ts",
  "src/\toutside.ts",
  "src/\u0001outside.ts",
  "src/example.ts\n",
];
const validPaths = [
  "src/extract.py",
  "src/module:helper.ts",
  "src:stream.ts",
  "./src/extract.py",
  "src//extract.py",
  "src/naïve file.ts",
];

describe("canonical code-evidence paths", () => {
  test("rejects unsafe canonical paths in sealed findings", async () => {
    for (const path of [...unsafePaths, " "]) {
      const scanDir = await scanWithEvidencePath(path);
      await expect(
        loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
      ).rejects.toThrow("codeEvidence[0].path");
    }
  });

  test("preserves valid historical path spellings and sealed bytes", async () => {
    for (const path of validPaths) {
      const scanDir = await scanWithEvidencePath(path);
      const before = await readFile(join(scanDir, "findings.json"));
      const contract = await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
      expect(contract.findings.findings[0]?.codeEvidence?.[0]?.path).toBe(path);
      expect(await readFile(join(scanDir, "findings.json"))).toEqual(before);
    }
  });

  test("keeps legacy evidence path compatibility", async () => {
    const scanDir = await scanWithEvidencePath("../legacy.ts", "code_evidence");
    const contract = await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
    expect(contract.findings.findings[0]?.code_evidence?.[0]?.["path"]).toBe(
      "../legacy.ts",
    );
  });

  test("the typed draft producer rejects unsafe canonical paths", async () => {
    const producer = new URL(
      "../../../plugins/codex-security/mcp-app/src/artifact-scan-draft.ts",
      import.meta.url,
    );
    const { parseScanDraft } = await import(producer.href);
    const scanDir = await scanWithEvidencePath("src/extract.py");
    const document = JSON.parse(
      await readFile(join(scanDir, "findings.json"), "utf8"),
    );
    const finding = document.findings[0];
    for (const field of ["findingId", "occurrenceId", "fingerprints"]) {
      delete finding[field];
    }
    const coverage = JSON.parse(
      await readFile(join(scanDir, "coverage.json"), "utf8"),
    );
    const draft = {
      scanId: "00000000-0000-4000-8000-000000000001",
      findings: [finding],
      coverage: {
        completeness: coverage.completeness,
        surfaces: coverage.surfaces,
        explicitExclusions: coverage.explicitExclusions,
        deferred: coverage.deferred,
      },
    };
    for (const path of unsafePaths) {
      finding.codeEvidence[0].path = path;
      expect(() => parseScanDraft(draft)).toThrow();
    }
    for (const path of validPaths.filter((value) => !value.includes("//"))) {
      finding.codeEvidence[0].path = path;
      expect(parseScanDraft(draft).findings[0]?.["codeEvidence"]).toEqual(
        finding.codeEvidence,
      );
    }
  });
});
