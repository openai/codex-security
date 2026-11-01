import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type {
  CoverageDocument,
  FindingsDocument,
  ScanManifest,
} from "../../src/models.js";
import { readJson, writeJson } from "./json.js";
import { setFindingIdentity, sha256 } from "./finding-identity.js";

export async function reseal(scanDirectory: string, updated?: ScanManifest) {
  const manifestPath = join(scanDirectory, "scan-manifest.json");
  const manifest = updated ?? (await readJson<ScanManifest>(manifestPath));
  for (const artifact of manifest.scan.artifacts) {
    artifact.sha256 = sha256(
      await readFile(join(scanDirectory, artifact.path)),
    );
  }
  await writeJson(manifestPath, manifest);
}

export async function writePublicationFindings(
  scanDirectory: string,
  scanId: string,
  count: number,
) {
  const manifest = await readJson<ScanManifest>(
    join(scanDirectory, "scan-manifest.json"),
  );
  const findingsPath = join(scanDirectory, "findings.json");
  const coveragePath = join(scanDirectory, "coverage.json");
  const findings = await readJson<FindingsDocument>(findingsPath);
  const coverage = await readJson<CoverageDocument>(coveragePath);
  manifest.scan.id = scanId;
  findings.scanId = scanId;
  coverage.scanId = scanId;
  const example = findings.findings[0]!;
  findings.findings = Array.from({ length: count }, (_, index) => {
    const finding = structuredClone(example);
    finding.identity.anchor = `${example.identity.anchor}-${index + 1}`;
    finding.title = `Synthetic finding ${index + 1}`;
    setFindingIdentity(manifest.scan, finding);
    return finding;
  });
  await writeJson(findingsPath, findings);
  await writeJson(coveragePath, coverage);
  await reseal(scanDirectory, manifest);
  return findings.findings;
}
