import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import fc from "fast-check";
import { ContractValidationError, loadContract } from "../src/index.js";
import type { ScanManifest } from "../src/models.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createContractTestFixtures } from "./support/contract-fixture.js";
import { sha256 } from "./support/finding-identity.js";
import { readJson, writeJson } from "./support/json.js";
import { propertyOptions } from "./support/property.js";

const { copyExample, cleanup } = createContractTestFixtures();
afterEach(cleanup);

describe("canonical scan contract", () => {
  test("rejects byte changes to any sealed binary artifact", async () => {
    const scanDir = await copyExample();
    const artifactPath = join(scanDir, "artifacts", "synthetic.bin");
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson<ScanManifest>(manifestPath);
    await mkdir(dirname(artifactPath), { recursive: true });

    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 256 }),
        fc.nat(),
        fc.integer({ min: 1, max: 255 }),
        async (bytes, offset, difference) => {
          await writeFile(artifactPath, bytes);
          await writeJson(manifestPath, {
            ...manifest,
            scan: {
              ...manifest.scan,
              artifacts: [
                ...manifest.scan.artifacts,
                {
                  path: "artifacts/synthetic.bin",
                  sha256: sha256(bytes),
                  mediaType: "application/octet-stream",
                },
              ],
            },
          });
          await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
          const changed = Uint8Array.from(bytes);
          changed[offset % bytes.length]! ^= difference;
          await writeFile(artifactPath, changed);
          await expect(
            loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
          ).rejects.toBeInstanceOf(ContractValidationError);
        },
      ),
      {
        ...propertyOptions,
        numRuns: Number(process.env["CODEX_SECURITY_PROPERTY_RUNS"] ?? "20"),
      },
    );
  });

  test("rejects non-relative artifact paths before accepting a seal", async () => {
    const scanDir = await copyExample();
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson<ScanManifest>(manifestPath);
    const prefixes = ["../", "/", "C:/", "artifacts/../", "artifacts\\"];
    await mkdir(join(scanDir, "artifacts"), { recursive: true });
    await fc.assert(
      fc.asyncProperty(
        fc.stringMatching(/^[a-z]{1,16}$/u),
        fc.constantFrom(...prefixes),
        async (name, prefix) => {
          const filename = `artifact-${name}`;
          const bytes = Buffer.from(name);
          const artifact = {
            path: `artifacts/${filename}`,
            sha256: sha256(bytes),
            mediaType: "application/octet-stream",
          };
          const scan = {
            ...manifest.scan,
            artifacts: [...manifest.scan.artifacts, artifact],
          };
          await writeFile(join(scanDir, "artifacts", filename), bytes);
          await writeJson(manifestPath, { ...manifest, scan });
          await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });

          artifact.path = `${prefix}${filename}`;
          await writeJson(manifestPath, { ...manifest, scan });
          const rejected = loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
          await expect(rejected).rejects.toBeInstanceOf(
            ContractValidationError,
          );
          await expect(rejected).rejects.toThrow(
            /safe scan-relative POSIX path|schema validation failed \(pattern/u,
          );
        },
      ),
      {
        ...propertyOptions,
        numRuns: Number(process.env["CODEX_SECURITY_PROPERTY_RUNS"] ?? "20"),
        examples: [
          ...prefixes.map((prefix): [string, string] => ["synthetic", prefix]),
          ["con", "C:/"],
        ],
      },
    );
  });
});
